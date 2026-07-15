# OpenSSH Security Auditor (regreSSHion & 2026 Flaws)

A lightweight, non-intrusive Python tool designed to check if remote SSH servers are vulnerable to critical OpenSSH exploits. It extracts and parses SSH banners to detect vulnerable versions and factors in OS-specific security backports (specifically for Ubuntu Noble 24.04).

## 🛡️ Supported Vulnerability Checks

1. **CVE-2024-6387 (regreSSHion)**: The critical remote code execution (RCE) signal handler race condition in OpenSSH.
   * **Upstream Risk Range:** `8.5p1` <= version < `9.8p1`
   * **Ubuntu Noble Patch:** Fixed in package version `3ubuntu13.3` or newer.
2. **CVE-2026-35385 & CVE-2026-35386**: 
   * **Upstream Risk Range:** Versions < `10.3p1`
   * **Ubuntu Noble Patch:** Fixed in package version `3ubuntu13.16` (via USN-8222-1) or newer.

---

## 🚀 Features

* **Zero Intrusion:** It strictly reads and parses the public SSH service banner (`banner-grabbing`). It does not trigger exploits, cause crashes, or trigger denial-of-service state.
* **Intelligent Backport Parsing:** Unlike generic scanners that flag patched systems as "false positives," this tool parses complex OS version strings (e.g., `3ubuntu13.16`) to recognize backported patches reliably.
* **Fast and Lightweight:** Implemented entirely in standard Python libraries (`socket`, `sys`, `re`)—no installation dependencies required.

---

## 📦 Usage

Simply run the script with the target IP address. You can optionally supply a custom port if the target is not running on default port `22`.

### Syntax:
```bash
python3 regreSSHion.py <IP_ADDRESS> [PORT]
