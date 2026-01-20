# JAWS V3.0 - Just Another Web Scanner

A powerful, modular web reconnaissance and vulnerability scanner written in pure bash.

## 🎯 Features

- **Comprehensive Reconnaissance Pipeline**
  - Subdomain enumeration (amass, subfinder, sublist3r)
  - Port scanning (rustscan, naabu, nmap)
  - URL discovery (gau, katana)
  - Web vulnerability scanning (nuclei, nikto)
  - Targeted directory bruteforcing (gobuster)

- **Bug Bounty Compliant**
  - Custom User-Agent support
  - Custom headers
  - Rate limiting
  - Configurable timeouts and threading

- **Modular Architecture**
  - Run all modules or select specific ones
  - Skip unwanted modules
  - Passive-only mode available

## 📦 Installation

### Quick Install (Automated)

```bash
cd /home/nofx/.gemini/antigravity/scratch/jaws-v3.0
chmod +x install_tools.sh jaws.sh
./install_tools.sh
```

The installation script will:
- ✅ Detect your OS (Ubuntu/Debian/Kali/Fedora/Arch)
- ✅ Install system dependencies
- ✅ Install Go (if not present)
- ✅ Install all required security tools
- ✅ Update Nuclei templates
- ✅ Verify all installations

**Supported OS:** Ubuntu, Debian, Kali, Fedora, RHEL, CentOS, Arch, Manjaro

> [!NOTE]
> After installation, restart your shell or run `source ~/.bashrc` to update your PATH.

### Manual Installation

If you prefer to install tools manually, JAWS requires:

**Subdomain Enumeration:**
- [amass](https://github.com/OWASP/Amass)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [sublist3r](https://github.com/aboul3la/Sublist3r)

**Port Scanning:**
- [rustscan](https://github.com/RustScan/RustScan)
- [naabu](https://github.com/projectdiscovery/naabu)
- [nmap](https://nmap.org/)

**URL Discovery:**
- [gau](https://github.com/lc/gau)
- [katana](https://github.com/projectdiscovery/katana)

**Vulnerability Scanning:**
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [nikto](https://github.com/sullo/nikto)

**Directory Bruteforcing:**
- [gobuster](https://github.com/OJ/gobuster)

**Utilities:**
- [httpx](https://github.com/projectdiscovery/httpx)

## 🚀 Usage

### Basic Scan
```bash
./jaws.sh -t example.com
```

### Bug Bounty Compliant Scan
```bash
./jaws.sh -t example.com \
  --user-agent "MyBugBounty/1.0 (Contact: security@example.com)" \
  --rate-limit 10
```

### Run Specific Modules
```bash
# Only subdomain enumeration and URL discovery
./jaws.sh -t example.com -m subdomain,urls

# Skip port scanning
./jaws.sh -t example.com --skip portscan
```

### Custom Headers
```bash
./jaws.sh -t example.com \
  --header "X-Bug-Bounty: true" \
  --header "X-Researcher: YourName"
```

## 📋 Command-Line Options

### Required
| Option | Description |
|--------|-------------|
| `-t, --target <DOMAIN>` | Target domain (e.g., example.com) |

### General Options
| Option | Description |
|--------|-------------|
| `-o, --output <DIR>` | Output directory (default: output/<target>) |
| `-m, --modules <LIST>` | Comma-separated modules to run (default: all) |
| `--skip <LIST>` | Comma-separated modules to skip |
| `-v, --verbose` | Verbose output |
| `-h, --help` | Show help message |

### Bug Bounty Compliance
| Option | Description |
|--------|-------------|
| `--user-agent <STRING>` | Custom User-Agent for HTTP requests |
| `--header <HEADER>` | Custom header (repeatable) |
| `--rate-limit <NUM>` | Max requests per second |
| `--threads <NUM>` | Max concurrent threads (default: 50) |

### Other
| Option | Description |
|--------|-------------|
| `-v, --verbose` | Verbose output |
| `-h, --help` | Show help message |

## 🔧 Modules

| Module | Tools Used | Description |
|--------|-----------|-------------|
| `subdomain` | amass, subfinder, sublist3r, httpx | Enumerate and verify live subdomains |
| `portscan` | rustscan, naabu, nuclei | Discover open ports and scan for network vulnerabilities |
| `urls` | gau, katana, httpx | Discover and verify live URLs |
| `webvuln` | nuclei, nikto | Scan for web vulnerabilities and misconfigurations |
| `dirbust` | gobuster | Prepare targeted directory bruteforcing |

## 📊 Output Files

After a scan, you'll find these key files in your output directory:

| File | Description |
|------|-------------|
| `live.txt` | Live subdomains |
| `all_live_urls.txt` | All discovered live URLs |
| `naabu-vulns.txt` | Network/service vulnerabilities |
| `http-vulns.txt` | Web application vulnerabilities |
| `nikto.json` | Nikto scan results |
| `rustscan.gnmap` | Port scan results (for deeper nmap analysis) |
| `gobuster_paths.txt` | Interesting paths for manual bruteforcing |

## 💡 Examples

### Full Scan with Custom Settings
```bash
./jaws.sh -t bugcrowd-target.com \
  --user-agent "BugHunter/1.0" \
  --rate-limit 5 \
  --threads 20 \
  -v
```

### Subdomain Enumeration Only
```bash
./jaws.sh -t example.com -m subdomain -o results/subdomains/
```

### Web Vulnerability Scan (Skip Recon)
```bash
# Assumes you already have subdomains/URLs
./jaws.sh -t example.com -m webvuln --skip subdomain,portscan,urls
```

## 🔍 Manual Follow-up

### Deep Nmap Scan
After the initial scan, you can run a deeper nmap scan:
```bash
nmap -iL output/example.com/rustscan.gnmap -sV -sC -oN output/example.com/nmap-deep.txt
```

### Directory Bruteforcing
JAWS prepares targeted paths for gobuster. Run manually:
```bash
while read sub; do 
  while read path; do 
    gobuster dir -u "$sub$path" -w /path/to/wordlist.txt -a "JAWS/3.0"
  done < output/example.com/gobuster_paths.txt
done < output/example.com/live.txt
```

## 🛡️ Bug Bounty Best Practices

1. **Always set a custom User-Agent** to identify yourself
2. **Use rate limiting** to avoid overwhelming targets
3. **Read the program rules** before scanning
4. **Respect scope** - only scan authorized targets

## 🤝 Contributing

This is JAWS V3.0 - built for speed, flexibility, and bug bounty compliance!

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any target. Unauthorized scanning may be illegal.

## 📄 License

MIT License - Use responsibly and ethically!
