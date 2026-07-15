import socket
import sys
import re

print("""
            [+] m0n3ef : github.com/m0n3ef/regreSSHion-Checker
""")
def parse_ssh_banner(banner):
    """
    Parses a standard SSH banner to extract OpenSSH version and OS build.
    Example: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16'
    """
    # Regex to capture the OpenSSH version and the Ubuntu package version
    match = re.search(r"OpenSSH_([0-9.]+p[0-9]+)\s*(Ubuntu-([0-9a-zA-Z.]+))?", banner)
    if not match:
        return None, None
    
    openssh_ver = match.group(1)
    ubuntu_ver = match.group(3) if match.group(3) else None
    return openssh_ver, ubuntu_ver

def get_ubuntu_build_numeric(ubuntu_str):
    """
    Converts '3ubuntu13.16' to a tuple of integers (3, 13, 16) for reliable comparison.
    """
    if not ubuntu_str:
        return (0, 0, 0)
    # Extracts all numbers from strings like '3ubuntu13.16' -> [3, 13, 16]
    numbers = re.findall(r'\d+', ubuntu_str)
    return tuple(map(int, numbers))

def check_vulnerabilities(openssh_ver, ubuntu_ver):
    """
    Evaluates the versions against known critical vulnerability thresholds.
    """
    status = {"safe": True, "details": []}
    
    # --- 1. Evaluate CVE-2024-6387 (regreSSHion) ---
    # Upstream vulnerable range: 8.5p1 <= version < 9.8p1 (excluding 9.6p1 on some OS, but let's be strict)
    # Ubuntu noble (24.04) fixed this in 3ubuntu13.3 (or later)
    is_upstream_vuln_regression = False
    try:
        ver_num = float(re.search(r"^[0-9.]+", openssh_ver).group(0))
        if 8.5 <= ver_num < 9.8:
            is_upstream_vuln_regression = True
    except:
        pass

    if is_upstream_vuln_regression:
        # Check if we have an Ubuntu build to determine if it is patched
        if ubuntu_ver:
            # For Noble (which runs 9.6p1), 3ubuntu13.3 is the patched release for regreSSHion
            build_nums = get_ubuntu_build_numeric(ubuntu_ver)
            # If the base version is 9.6p1 and build is >= 3ubuntu13.3
            if openssh_ver == "9.6p1" and build_nums >= (3, 13, 3):
                status["details"].append("[+] CVE-2024-6387 (regreSSHion): PATCHED by Ubuntu package " + ubuntu_ver)
            else:
                status["safe"] = False
                status["details"].append("[!] CVE-2024-6387 (regreSSHion): VULNERABLE (Requires Ubuntu build 3ubuntu13.3 or newer)")
        else:
            status["safe"] = False
            status["details"].append("[!] CVE-2024-6387 (regreSSHion): POTENTIALLY VULNERABLE (Upstream version falls in risk range)")

    # --- 2. Evaluate CVE-2026-35386 & CVE-2026-35385 ---
    # Upstream vulnerable range: < 10.3p1
    # Ubuntu noble (24.04) fixed this in 3ubuntu13.16 (USN-8222-1)
    is_upstream_vuln_2026 = False
    try:
        ver_num = float(re.search(r"^[0-9.]+", openssh_ver).group(0))
        if ver_num < 10.3:
            is_upstream_vuln_2026 = True
    except:
        pass

    if is_upstream_vuln_2026:
        if ubuntu_ver:
            build_nums = get_ubuntu_build_numeric(ubuntu_ver)
            if openssh_ver == "9.6p1" and build_nums >= (3, 13, 16):
                status["details"].append("[+] CVE-2026-35385/6 (Command Exec): PATCHED by Ubuntu package " + ubuntu_ver)
            else:
                status["safe"] = False
                status["details"].append("[!] CVE-2026-35385/6 (Command Exec): VULNERABLE (Requires Ubuntu build 3ubuntu13.16 or newer)")
        else:
            status["safe"] = False
            status["details"].append("[!] CVE-2026-35385/6: POTENTIALLY VULNERABLE (Upstream version is below 10.3p1)")

    return status

def audit_target(ip, port=22, timeout=5):
    print(f"[*] Connecting to {ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        banner_bytes = s.recv(1024)
        s.close()
        
        banner = banner_bytes.decode('utf-8', errors='ignore').strip()
        print(f"[+] Raw Banner: {banner}")
        
        openssh_ver, ubuntu_ver = parse_ssh_banner(banner)
        
        if not openssh_ver:
            print("[-] Unable to identify a standard OpenSSH version structure in the banner.")
            return

        print(f"[+] Detected Upstream OpenSSH: {openssh_ver}")
        if ubuntu_ver:
            print(f"[+] Detected Ubuntu Package:   {ubuntu_ver}")
        else:
            print("[*] No OS-specific patch signature detected in banner (generic Unix/Source build).")
        
        print("\n--- Vulnerability Assessment ---")
        results = check_vulnerabilities(openssh_ver, ubuntu_ver)
        
        for detail in results["details"]:
            print(detail)
            
        if results["safe"] and len(results["details"]) > 0:
            print(f"\n[PASS] {ip} appears to have applied necessary security backports.")
        elif not results["safe"]:
            print(f"\n[FAIL] {ip} is running a vulnerable deployment.")
        else:
            print(f"\n[PASS] No critical vulnerabilities detected for {openssh_ver}.")

    except socket.timeout:
        print(f"[-] Error: Connection to {ip}:{port} timed out.")
    except ConnectionRefusedError:
        print(f"[-] Error: Connection refused on port {port}.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[*] Usage: python ssh_audit.py <IP_ADDRESS> [PORT]")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    audit_target(target_ip, target_port)