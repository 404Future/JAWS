#!/bin/bash

# JAWS.sh - Complete Bug Bounty Reconnaissance Tool
# Usage: ./JAWS.sh [options] domain1.com domain2.com ...

source ./scan.lib

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
MODE="full"
INTERACTIVE=false

# Banner
echo -e "${BLUE}"
cat << "EOF"
     ██╗ █████╗ ██╗    ██╗███████╗
     ██║██╔══██╗██║    ██║██╔════╝
     ██║███████║██║ █╗ ██║███████╗
██   ██║██╔══██║██║███╗██║╚════██║
╚█████╔╝██║  ██║╚███╔███╔╝███████║
 ╚════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
    Bug Bounty Recon Tool v2.0
EOF
echo -e "${NC}"

# Parse command line options
while getopts "m:ih" OPTION; do
  case $OPTION in
    m)
      MODE=$OPTARG
      ;;
    i)
      INTERACTIVE=true
      ;;
    h)
      show_help
      exit 0
      ;;
    *)
      show_help
      exit 1
      ;;
  esac
done

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS] domain1.com domain2.com ..."
    echo ""
    echo "Options:"
    echo "  -m MODE    Scan mode (default: full)"
    echo "             Modes: full, passive, active, quick, custom"
    echo "  -i         Interactive mode"
    echo "  -h         Show this help message"
    echo ""
    echo "Modes:"
    echo "  full       Complete reconnaissance workflow"
    echo "  passive    Only passive enumeration (subfinder, crt.sh, etc.)"
    echo "  active     Active scanning (port scan, vuln scan)"
    echo "  quick      Fast scan (subfinder, httpx, nmap top ports)"
    echo "  custom     Choose specific tools interactively"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 -m passive example.com target.com"
    echo "  $0 -i"
}

# Main scan function
scan_domain() {
    DOMAIN=$1
    DIRECTORY="${DOMAIN}_recon"
    
    echo -e "${GREEN}[+] Starting reconnaissance on: $DOMAIN${NC}"
    echo -e "${YELLOW}[*] Creating directory: $DIRECTORY${NC}"
    mkdir -p "$DIRECTORY"
    
    # Log file
    LOGFILE="$DIRECTORY/scan.log"
    echo "Scan started at $(date)" | tee "$LOGFILE"
    
    case $MODE in
        passive)
            echo -e "${BLUE}[*] Running PASSIVE mode${NC}" | tee -a "$LOGFILE"
            subdomain_enum
            dns_resolution
            http_probe
            url_discovery_passive
            ;;
        active)
            echo -e "${BLUE}[*] Running ACTIVE mode${NC}" | tee -a "$LOGFILE"
            port_scan_fast
            port_scan_full
            vulnerability_scan
            ;;
        quick)
            echo -e "${BLUE}[*] Running QUICK mode${NC}" | tee -a "$LOGFILE"
            subdomain_enum_quick
            http_probe
            port_scan_fast
            ;;
        custom)
            custom_scan
            ;;
        full|*)
            echo -e "${BLUE}[*] Running FULL reconnaissance${NC}" | tee -a "$LOGFILE"
            subdomain_enum
            subdomain_bruteforce
            dns_resolution
            http_probe
            url_discovery
            screenshots
            port_scan_fast
            port_scan_full
            vulnerability_scan
            ;;
    esac
    
    echo -e "${GREEN}[+] Scan completed at $(date)${NC}" | tee -a "$LOGFILE"
}

# Report generation function
report_domain() {
    DOMAIN=$1
    DIRECTORY="${DOMAIN}_recon"
    REPORT="$DIRECTORY/report.html"
    
    echo -e "${YELLOW}[*] Generating HTML report for $DOMAIN...${NC}"
    
    cat > "$REPORT" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; }
        h2 { color: #34495e; margin-top: 30px; }
        .section { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .stats { display: flex; gap: 20px; }
        .stat-box { background: #3498db; color: white; padding: 15px; border-radius: 5px; flex: 1; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 10px; overflow-x: auto; }
        .timestamp { color: #7f8c8d; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Reconnaissance Report</h1>
        <p><strong>Target:</strong> $DOMAIN</p>
        <p class="timestamp">Generated: $(date)</p>
        
        <div class="stats">
            <div class="stat-box">
                <h3>Subdomains</h3>
                <p style="font-size: 2em; margin: 0;">$(cat "$DIRECTORY/subdomains_all.txt" 2>/dev/null | wc -l)</p>
            </div>
            <div class="stat-box">
                <h3>Live Hosts</h3>
                <p style="font-size: 2em; margin: 0;">$(cat "$DIRECTORY/live_hosts.txt" 2>/dev/null | wc -l)</p>
            </div>
            <div class="stat-box">
                <h3>URLs Found</h3>
                <p style="font-size: 2em; margin: 0;">$(cat "$DIRECTORY/urls_all.txt" 2>/dev/null | wc -l)</p>
            </div>
        </div>
EOF

    # Add sections for each scan result
    add_report_section "Subdomain Enumeration" "$DIRECTORY/subdomains_all.txt"
    add_report_section "Live HTTP Hosts" "$DIRECTORY/httpx_results.txt"
    add_report_section "Open Ports" "$DIRECTORY/nmap_scan.txt"
    add_report_section "Vulnerabilities" "$DIRECTORY/nuclei_results.txt"
    
    echo "</div></body></html>" >> "$REPORT"
    
    echo -e "${GREEN}[+] Report saved to: $REPORT${NC}"
    
    # Also create text report
    generate_text_report
}

# Add section to HTML report
add_report_section() {
    local title=$1
    local file=$2
    
    if [ -f "$file" ]; then
        cat >> "$REPORT" << EOF
        <div class="section">
            <h2>$title</h2>
            <pre>$(head -50 "$file")</pre>
        </div>
EOF
    fi
}

# Generate text report
generate_text_report() {
    local TEXT_REPORT="$DIRECTORY/report.txt"
    
    cat > "$TEXT_REPORT" << EOF
================================================================================
                    RECONNAISSANCE REPORT - $DOMAIN
================================================================================
Generated: $(date)

SUMMARY:
--------
Subdomains Found: $(cat "$DIRECTORY/subdomains_all.txt" 2>/dev/null | wc -l)
Live Hosts: $(cat "$DIRECTORY/live_hosts.txt" 2>/dev/null | wc -l)
URLs Discovered: $(cat "$DIRECTORY/urls_all.txt" 2>/dev/null | wc -l)

EOF

    [ -f "$DIRECTORY/subdomains_all.txt" ] && {
        echo "SUBDOMAINS:" >> "$TEXT_REPORT"
        echo "----------" >> "$TEXT_REPORT"
        cat "$DIRECTORY/subdomains_all.txt" >> "$TEXT_REPORT"
        echo "" >> "$TEXT_REPORT"
    }

    [ -f "$DIRECTORY/httpx_results.txt" ] && {
        echo "LIVE HTTP HOSTS:" >> "$TEXT_REPORT"
        echo "---------------" >> "$TEXT_REPORT"
        cat "$DIRECTORY/httpx_results.txt" >> "$TEXT_REPORT"
        echo "" >> "$TEXT_REPORT"
    }

    [ -f "$DIRECTORY/nuclei_results.txt" ] && {
        echo "VULNERABILITIES:" >> "$TEXT_REPORT"
        echo "---------------" >> "$TEXT_REPORT"
        cat "$DIRECTORY/nuclei_results.txt" >> "$TEXT_REPORT"
    }
    
    echo -e "${GREEN}[+] Text report saved to: $TEXT_REPORT${NC}"
}

# Custom scan mode
custom_scan() {
    echo -e "${YELLOW}Select tools to run (space-separated numbers):${NC}"
    echo "1) Subdomain Enumeration"
    echo "2) Subdomain Bruteforce"
    echo "3) DNS Resolution"
    echo "4) HTTP Probing"
    echo "5) URL Discovery"
    echo "6) Screenshots"
    echo "7) Port Scan (Fast)"
    echo "8) Port Scan (Full)"
    echo "9) Vulnerability Scan"
    read -p "Enter choices: " choices
    
    for choice in $choices; do
        case $choice in
            1) subdomain_enum ;;
            2) subdomain_bruteforce ;;
            3) dns_resolution ;;
            4) http_probe ;;
            5) url_discovery ;;
            6) screenshots ;;
            7) port_scan_fast ;;
            8) port_scan_full ;;
            9) vulnerability_scan ;;
        esac
    done
}

# Main execution
if [ "$INTERACTIVE" = true ]; then
    INPUT="BLANK"
    while [ "$INPUT" != "quit" ]; do
        echo -e "${YELLOW}Please enter a domain (or 'quit' to exit):${NC}"
        read INPUT
        if [ "$INPUT" != "quit" ]; then
            scan_domain "$INPUT"
            report_domain "$INPUT"
        fi
    done
else
    # Check if domains were provided
    if [ $OPTIND -gt $# ]; then
        echo -e "${RED}[!] Error: No domains specified${NC}"
        show_help
        exit 1
    fi
    
    # Scan all provided domains
    for domain in "${@:$OPTIND}"; do
        scan_domain "$domain"
        report_domain "$domain"
        echo ""
    done
fi

echo -e "${GREEN}[+] JAWS reconnaissance complete!${NC}"
