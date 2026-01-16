# 🦈 JAWS - Just Another Web Scanner

A comprehensive bug bounty reconnaissance tool that automates the entire recon workflow from subdomain enumeration to vulnerability scanning.

## Features

✨ **Complete Recon Workflow**
- Passive & Active Subdomain Enumeration
- DNS Resolution & Validation
- HTTP Service Probing
- URL Discovery & Crawling
- Visual Screenshot Capture
- Port Scanning
- Vulnerability Detection

📊 **Multiple Scan Modes**
- **Full**: Complete reconnaissance (all phases)
- **Passive**: Only passive enumeration (no active scanning)
- **Active**: Port & vulnerability scanning only
- **Quick**: Fast scan with essential tools
- **Custom**: Choose specific tools interactively

📝 **Professional Reporting**
- HTML reports with statistics
- Text-based reports for CLI
- Organized output directories

## Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/404Future/jaws.git
cd jaws

# Make scripts executable
chmod +x JAWS.sh scan.lib install_tools.sh

# Run installer (requires sudo for some tools)
sudo ./install_tools.sh

# Update PATH
source ~/.bashrc  # or source ~/.zshrc for zsh users
```

### Fresh Install / Reinstall

If you need to start clean:

```bash
# Uninstall everything
chmod +x uninstall_tools.sh
./uninstall_tools.sh

# For complete cleanup (removes wordlists too)
./uninstall_tools.sh --full

# Then reinstall
sudo ./install_tools.sh
source ~/.zshrc  # or ~/.bashrc
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

#### 1. Install Go
```bash
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 2. Install Go Tools
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest
```

#### 3. Install System Tools
```bash
# Ubuntu/Debian
sudo apt install nmap masscan jq python3 python3-pip amass

# Fedora/RHEL
sudo dnf install nmap masscan jq python3 python3-pip amass
```

#### 4. Install Python Tools
```bash
git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch
```

#### 5. Download Wordlists
```bash
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists
```

</details>

## Configuration

You can customize JAWS behavior by editing `scan.lib`:

```bash
# Edit configuration section at top of scan.lib
nano scan.lib
```

**Available settings:**

```bash
# Status codes considered "interesting" for filtering
INTERESTING_STATUS_CODES="200|201|301|302|307|308|401|403"

# Amass timeout in seconds (default: 300 = 5 minutes)
AMASS_TIMEOUT=300
```

**Status Code Filtering:**
- By default, JAWS filters HTTP responses to show only interesting status codes
- 200/201: Successful responses
- 301/302/307/308: Redirects (often lead to interesting resources)
- 401/403: Authentication/Authorization required (potential targets)
- All results saved in `httpx_results_all.txt`, filtered in `httpx_results.txt`

## Usage

### Basic Scan
```bash
./JAWS.sh example.com
```

### Scan Multiple Domains
```bash
./JAWS.sh example.com target.com domain.com
```

### Scan Modes

#### Full Reconnaissance (Default)
```bash
./JAWS.sh example.com
```
Runs all phases: subdomain enum → bruteforce → DNS resolution → HTTP probing → URL discovery → screenshots → port scan → vulnerability scan

#### Passive Mode Only
```bash
./JAWS.sh -m passive example.com
```
Only passive reconnaissance, no active scanning against target

#### Active Scanning
```bash
./JAWS.sh -m active example.com
```
Port scanning and vulnerability detection only

#### Quick Scan
```bash
./JAWS.sh -m quick example.com
```
Fast scan with essential tools (subfinder, httpx, nmap top ports)

#### Custom Mode
```bash
./JAWS.sh -m custom example.com
```
Choose which specific tools to run interactively

### Interactive Mode
```bash
./JAWS.sh -i
```
Enter domains one by one, type 'quit' to exit

### Help
```bash
./JAWS.sh -h
```

## Output Structure

Each scan creates a directory named `{domain}_recon/` containing:

```
example.com_recon/
├── scan.log                   # Scan activity log
├── report.html                # HTML report with stats
├── report.txt                 # Text-based report
├── subdomains_all.txt         # All discovered subdomains
├── subfinder.txt              # Subfinder results
├── assetfinder.txt            # Assetfinder results
├── amass.txt                  # Amass results
├── crtsh.txt                  # crt.sh certificate results
├── puredns.txt                # Bruteforced subdomains
├── resolved.txt               # DNS resolution results
├── httpx_results_all.txt      # All HTTP probe results (any status)
├── httpx_results.txt          # Filtered HTTP results (interesting status codes)
├── live_hosts_all.txt         # All live HTTP/HTTPS hosts
├── live_hosts.txt             # Filtered live hosts (200/30x/40x only)
├── katana_urls.txt            # Crawled URLs
├── gau_urls.txt               # Archive URLs
├── wayback_urls.txt           # Wayback machine URLs
├── urls_all.txt               # All discovered URLs
├── screenshots/               # Website screenshots
├── naabu_ports.txt            # Fast port scan
├── nmap_scan.txt              # Detailed nmap scan
└── nuclei_results.txt         # Vulnerability scan results
```

## Workflow Phases

### Phase 1: Subdomain Enumeration (Passive)
- **subfinder**: Fast passive subdomain discovery
- **assetfinder**: Find related domains
- **amass**: Comprehensive OSINT gathering
- **crt.sh**: Certificate transparency logs

### Phase 2: Subdomain Bruteforce (Active)
- **puredns**: DNS bruteforcing with wildcard filtering
- Uses wordlists for common subdomains

### Phase 3: DNS Resolution
- **dnsx**: Validates and resolves discovered subdomains
- Filters out dead/non-resolving domains

### Phase 4: HTTP Probing
- **httpx**: Probes for web servers
- Detects technologies, status codes, titles
- Identifies live HTTP/HTTPS services

### Phase 5: URL Discovery
- **katana**: Modern web crawler
- **gau**: Fetches URLs from AlienVault, Wayback
- **waybackurls**: Wayback machine historical URLs

### Phase 6: Visual Reconnaissance
- **gowitness**: Captures screenshots of all live hosts
- Helps identify interesting targets quickly

### Phase 7: Port Scanning
- **naabu**: Fast port scanner (top 1000 ports)
- **nmap**: Comprehensive scan with service detection
- **masscan**: Ultra-fast full port scan (optional)

### Phase 8: Vulnerability Scanning
- **nuclei**: Template-based vulnerability scanner
- Scans for CVEs, misconfigurations, exposures
- **nikto**: Web server vulnerability scanner (optional)

## Tools Used

| Tool | Purpose | Speed |
|------|---------|-------|
| subfinder | Subdomain enumeration | ⚡⚡⚡ |
| assetfinder | Asset discovery | ⚡⚡⚡ |
| amass | Deep OSINT | ⚡⚡ |
| puredns | DNS bruteforce | ⚡⚡ |
| dnsx | DNS resolution | ⚡⚡⚡ |
| httpx | HTTP probing | ⚡⚡⚡ |
| katana | Web crawling | ⚡⚡ |
| gau | Archive URLs | ⚡⚡⚡ |
| waybackurls | Wayback URLs | ⚡⚡ |
| gowitness | Screenshots | ⚡⚡ |
| naabu | Port scanning | ⚡⚡⚡ |
| nmap | Service detection | ⚡ |
| nuclei | Vuln scanning | ⚡⚡ |

## Tips & Best Practices

### 🎯 Target Selection
- Start with passive mode on new targets
- Use full mode on authorized targets only
- Respect scope and rules of engagement

### ⚡ Performance
- Quick mode for initial assessment
- Full mode for deep reconnaissance
- Consider network bandwidth for large scans

### 📊 Results Analysis
- Check HTML report for quick overview
- Review nuclei results for vulnerabilities
- Examine screenshots for interesting targets
- Grep through URLs for specific patterns

### 🔍 Finding Bugs
```bash
# Find potential XSS parameters
cat domain_recon/urls_all.txt | grep "=" | grep -E "search|query|q=|s=|keyword"

# Find API endpoints
cat domain_recon/urls_all.txt | grep -E "api|v[0-9]|json|xml"

# Find admin panels
cat domain_recon/live_hosts.txt | grep -E "admin|dashboard|panel|login"

# Check for exposed files
cat domain_recon/urls_all.txt | grep -E "\.env|\.git|\.sql|backup|config"
```

## Troubleshooting

### Tools Not Found After Installation

If tools show as "not installed" after running install_tools.sh:

**Quick Fix:**
```bash
# Option 1: Fix the Source script
source ./fix_path.sh

# Option 2: Manually export PATH
export PATH=$PATH:~/go/bin

# Option 3: Reload your shell config
# For zsh:
source ~/.zshrc
# For bash:
source ~/.bashrc

# Option 4: Restart your terminal
```

**Verify Installation:**
```bash
# Check what's installed
./check_tools.sh

# Verify tools are in PATH
which subfinder httpx nuclei
```

### Zsh Users

The installer now auto-detects zsh and configures `.zshrc` instead of `.bashrc`. If you're using zsh:

```bash
# Make sure PATH is set in current session
source ~/.zshrc

# Or manually:
export PATH=$PATH:~/go/bin
```

### Tools Not Found
```bash
# Verify tools are in PATH
source ~/.bashrc

# Check Go bin directory
ls ~/go/bin/

# Reinstall specific tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Permission Denied
```bash
# Make scripts executable
chmod +x JAWS.sh scan.lib

# Some tools need root (masscan, nmap SYN scan)
sudo ./JAWS.sh -m active example.com
```

### No Results Found
- Check domain is valid and accessible
- Verify internet connection
- Some targets may have no subdomains
- Try passive mode first to verify tools work

## Contributing

Contributions welcome! Areas for improvement:
- Additional tool integrations
- Better reporting formats
- Performance optimizations
- Error handling improvements

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for authorized security testing only.

- Only scan domains you own or have explicit permission to test
- Respect bug bounty program scopes and rules
- Unauthorized scanning may be illegal in your jurisdiction
- Users are responsible for complying with applicable laws
- The authors assume no liability for misuse

## License

MIT License - See LICENSE file for details

## Credits

Created for bug bounty hunters and security researchers.

Special thanks to:
- ProjectDiscovery for amazing tools
- Tom Hudson (tomnomnom) for essential utilities
- OWASP Amass team
- The entire bug bounty community

## Support

- 🦈 Report bugs via GitHub Issues
- 💡 Feature requests welcome
- ⭐ Star if you find it useful!
