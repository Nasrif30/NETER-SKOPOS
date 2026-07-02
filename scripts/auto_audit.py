import subprocess
import re
import platform
import time
import sys

def get_default_gateway():
    """Extracts the default gateway IP for the active network interface."""
    system = platform.system()
    gateway = None
    
    try:
        if system == "Windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
            output = result.stdout
            
            # Find Default Gateway line that has an IP
            for line in output.split("\n"):
                if "Default Gateway" in line:
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        gateway = match.group(1)
                        break
        elif system == "Linux":
            result = subprocess.run(["ip", "r"], capture_output=True, text=True, check=True)
            output = result.stdout
            
            # Find the default route line
            for line in output.split("\n"):
                if line.startswith("default via"):
                    match = re.search(r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        gateway = match.group(1)
                        break
    except Exception as e:
        print(f"[!] Error detecting gateway: {e}")
        
    return gateway

def discover_and_audit():
    print("==========================================")
    print("  NETER-SKOPOS :: One-Click Auto-Auditor")
    print("==========================================")
    
    system = platform.system()
    
    print("\n[+] Step 1: Scanning Network Interface...")
    
    # Allow manual override via command line argument
    if len(sys.argv) > 1:
        gateway = sys.argv[1]
        print("[-] Manual Override Detected.")
    else:
        gateway = get_default_gateway()
    
    if not gateway:
        print("[-] FAILED: Could not detect default gateway.")
        print("    Are you connected to a network?")
        sys.exit(1)
        
    target_url = f"http://{gateway}"
    print(f"[*] Found Gateway / Router IP: {gateway}")
    print(f"[*] Setting Target to: {target_url}")
    time.sleep(1)
    
    print("\n[+] Step 2: Preparing Traffic Generators...")
    proxy = "http://127.0.0.1:8080"
    
    print("\n[+] Step 3: Probing Auto-Discovered Target...")
    # Base admin check
    try:
        subprocess.run(
            ["curl", "-s", "-x", proxy, f"{target_url}/", "-o", "/dev/null" if system == "Linux" else "NUL"],
            timeout=5
        )
        print("  [*] HTTP index probed")
    except Exception as e:
         print(f"  [-] Probe error: {e}")
         
    # Probe common paths
    paths = ["/", "/admin", "/login", "/login.html", "/login.cgi", "/cgi-bin/login.cgi", "/index.html"]
    for path in paths:
        try:
            subprocess.run(["curl", "-s", "-x", proxy, f"{target_url}{path}", "-o", "/dev/null" if system == "Linux" else "NUL"], timeout=2)
            print(f"  [*] Path {path} probed")
        except:
            pass
            
    # Inject standard credential attacks
    print("\n[+] Step 4: Injecting standard credentials against router...")
    default_creds = [
        {"user": "admin", "pass": "admin"},
        {"user": "admin", "pass": "password"},
        {"user": "admin", "pass": "1234"},
        {"user": "root", "pass": "root"}
    ]
    
    for cred in default_creds:
        u = cred['user']
        p = cred['pass']
        form_data = f"username={u}&password={p}"
        try:
            # Login POST
            subprocess.run(["curl", "-s", "-x", proxy, f"{target_url}/login", "-d", form_data, "-o", "/dev/null" if system == "Linux" else "NUL"], timeout=2)
            # Basic Auth
            subprocess.run(["curl", "-s", "-x", proxy, f"{target_url}/", "-u", f"{u}:{p}", "-o", "/dev/null" if system == "Linux" else "NUL"], timeout=2)
        except:
            pass
            
    print("\n[+] Step 5: Finalizing Session...")
    for _ in range(3):
         try:
            subprocess.run(["curl", "-s", "-x", proxy, f"{target_url}/", "-o", "/dev/null" if system == "Linux" else "NUL"], timeout=2)
         except:
             pass
             
    print("\n==========================================")
    print(f"[SUCCESS] Audit completed for Auto-Discovered Router ({gateway}).")
    print("Look at your UI dashboard in the browser to see the results!")
    print("==========================================\n")

if __name__ == "__main__":
    discover_and_audit()
