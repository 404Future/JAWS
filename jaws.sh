#!/bin/bash

################################################################################
# JAWS (Just Another Web Scanner) V3.0
# A comprehensive web reconnaissance and vulnerability scanner
################################################################################

VERSION="3.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

################################################################################
# Banner
################################################################################
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
     ___  ________  ___       __   ________      
    |\  \|\   __  \|\  \     |\  \|\   ____\     
    \ \  \ \  \|\  \ \  \    \ \  \ \  \___|_    
  __ \ \  \ \   __  \ \  \  __\ \  \ \_____  \   
 |\  \\_\  \ \  \ \  \ \  \|\__\_\  \|____|\  \  
 \ \________\ \__\ \__\ \____________\____\_\  \ 
  \|________|\|__|\|__|\|____________|\_________\
                                     \|_________|
EOF
    echo -e "${NC}"
    echo -e "${MAGENTA}JAWS - Just Another Web Scanner v${VERSION}${NC}"
    echo -e "${BLUE}Comprehensive Reconnaissance & Vulnerability Scanner${NC}"
    echo ""
}

################################################################################
# Help
################################################################################
show_help() {
    cat << EOF
Usage: ./jaws.sh -t <target> [OPTIONS]

Required:
    -t, --target <DOMAIN>        Target domain (e.g., example.com)

Options:
    -o, --output <DIR>           Output directory (default: output/<target>)
    -m, --modules <LIST>         Comma-separated modules to run (default: all)
                                 Available: subdomain,portscan,urls,webvuln,dirbust
    --skip <LIST>                Comma-separated modules to skip
    
Bug Bounty Compliance:
    --user-agent <STRING>        Custom User-Agent for HTTP requests
    --header <HEADER>            Custom header (format: "Name: Value", repeatable)
    --rate-limit <NUM>           Max requests per second (for supported tools)
    --threads <NUM>              Max concurrent threads (default: 50)
    
Other:
    -v, --verbose                Verbose output
    -h, --help                   Show this help

Modules:
    subdomain    - Subdomain enumeration (amass, subfinder, sublist3r)
    portscan     - Port scanning (naabu, nuclei)
    urls         - URL discovery (katana, waybackurls)
    webvuln      - Web vulnerability scanning (nuclei, nikto)
    dirbust      - Directory bruteforcing (gobuster)

Examples:
    # Full scan
    ./jaws.sh -t example.com
    
    # Bug bounty compliant scan
    ./jaws.sh -t example.com --user-agent "MyBugBounty/1.0" --rate-limit 10
    
    # Only subdomain enumeration and URL discovery
    ./jaws.sh -t example.com -m subdomain,urls

EOF
}

################################################################################
# Configuration
################################################################################
TARGET=""
OUTPUT_DIR=""
MODULES="all"
SKIP_MODULES=""
USER_AGENT="JAWS/3.0 (Security Scanner)"
CUSTOM_HEADERS=()
RATE_LIMIT=0
THREADS=50
VERBOSE=false

################################################################################
# Parse Arguments
################################################################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -m|--modules)
                MODULES="$2"
                shift 2
                ;;
            --skip)
                SKIP_MODULES="$2"
                shift 2
                ;;
            --user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            --header)
                CUSTOM_HEADERS+=("$2")
                shift 2
                ;;
            --rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --threads)
                THREADS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

################################################################################
# Logging
################################################################################
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${CYAN}[V]${NC} $1"
    fi
}

################################################################################
# Dependency Check
################################################################################
check_dependencies() {
    local required_tools=()
    local missing_tools=()
    
    # Check which modules are enabled
    if should_run_module "subdomain"; then
        required_tools+=(amass subfinder sublist3r)
    fi
    
    if should_run_module "portscan"; then
        required_tools+=(naabu nuclei nmap)
    fi
    
    if should_run_module "urls"; then
        required_tools+=(katana httpx)
        if ! command -v waybackurls >/dev/null 2>&1; then
            log_warning "waybackurls not found (optional, continuing...)"
        fi
    fi
    
    if should_run_module "webvuln"; then
        required_tools+=(nuclei nikto)
    fi
    
    if should_run_module "dirbust"; then
        required_tools+=(gobuster)
    fi
    
    # Always needed
    required_tools+=(httpx grep awk sed sort)
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install missing tools:"
        log_info "  go install github.com/projectdiscovery/katana/cmd/katana@latest"
        log_info "  go install github.com/tomnomnom/waybackurls@latest"
        exit 1
    fi
    
    log_success "All required dependencies found"
}

################################################################################
# Module Control
################################################################################
should_run_module() {
    local module="$1"
    
    # Check if in skip list
    if [[ "$SKIP_MODULES" == *"$module"* ]]; then
        return 1
    fi
    
    # Check if in modules list
    if [[ "$MODULES" == "all" ]]; then
        return 0
    elif [[ "$MODULES" == *"$module"* ]]; then
        return 0
    else
        return 1
    fi
}

################################################################################
# Module: Subdomain Enumeration
################################################################################
run_subdomain_enum() {
    log_info "Starting subdomain enumeration..."
    
    # Amass
    log_verbose "Running amass..."
    amass enum -d "$TARGET" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null
    touch "$OUTPUT_DIR/amass.txt" 2>/dev/null
    
    # Subfinder
    log_verbose "Running subfinder..."
    subfinder -d "$TARGET" -o "$OUTPUT_DIR/subfinder.txt" -silent
    touch "$OUTPUT_DIR/subfinder.txt" 2>/dev/null
    
    # Sublist3r
    log_verbose "Running sublist3r..."
    sublist3r -d "$TARGET" -o "$OUTPUT_DIR/sublist3r.txt" 2>/dev/null
    touch "$OUTPUT_DIR/sublist3r.txt" 2>/dev/null
    
    # Merge and filter live subdomains
    log_info "Filtering live subdomains..."
    cat "$OUTPUT_DIR"/{amass,subfinder,sublist3r}.txt 2>/dev/null | \
        sort -u | \
        httpx -silent -H "User-Agent: $USER_AGENT" -o "$OUTPUT_DIR/live.txt"
    
    # Ensure file exists for counting
    touch "$OUTPUT_DIR/live.txt" 2>/dev/null
    local count=$(wc -l <"$OUTPUT_DIR/live.txt" 2>/dev/null || echo 0)
    log_success "Found $count live subdomains → $OUTPUT_DIR/live.txt"
}

################################################################################
# Module: Port Scanning
################################################################################
run_port_scan() {
    log_info "Starting port scanning..."
    
    if [[ ! -f "$OUTPUT_DIR/live.txt" ]]; then
        log_warning "No live subdomains found, scanning target domain only"
        echo "$TARGET" > "$OUTPUT_DIR/live.txt"
    fi
    
    # Naabu for port discovery
    log_verbose "Running naabu..."
    naabu -list "$OUTPUT_DIR/live.txt" -top-ports 1000 -silent -o "$OUTPUT_DIR/naabu.txt" 2>/dev/null
    
    # Ensure file exists
    touch "$OUTPUT_DIR/naabu.txt" 2>/dev/null
    
    # Run nuclei on discovered services only if we have targets
    if [[ -s "$OUTPUT_DIR/naabu.txt" ]]; then
        log_info "Scanning for network vulnerabilities..."
        nuclei -l "$OUTPUT_DIR/naabu.txt" -t network/ -t cves/ -silent -o "$OUTPUT_DIR/naabu-vulns.txt" 2>/dev/null
        touch "$OUTPUT_DIR/naabu-vulns.txt" 2>/dev/null
    else
        log_warning "No ports found for vulnerability scanning"
        touch "$OUTPUT_DIR/naabu-vulns.txt" 2>/dev/null
    fi
    
    local vuln_count=$(wc -l <"$OUTPUT_DIR/naabu-vulns.txt" 2>/dev/null || echo 0)
    log_success "Port scan complete, found $vuln_count potential vulnerabilities → $OUTPUT_DIR/naabu-vulns.txt"
}

################################################################################
# Module: URL Discovery
################################################################################
run_url_discovery() {
    log_info "Starting URL discovery (katana + waybackurls)..."
    
    [[ ! -s "$OUTPUT_DIR/live.txt" ]] && { 
        log_warning "No live subdomains found"; return 
    }
    
    # Katana - active crawling (conservative)
    log_verbose "Running katana (top 50 domains, 60s max)..."
    cat "$OUTPUT_DIR/live.txt" | head -50 | \
        timeout 60 katana -silent -jc -ef js,css -c 3 -rl 2 -depth 2 \
        -H "User-Agent: $USER_AGENT" -o "$OUTPUT_DIR/katana.txt" || 
        touch "$OUTPUT_DIR/katana.txt"
    
    # Waybackurls - passive archive
    if command -v waybackurls >/dev/null 2>&1; then
        log_verbose "Running waybackurls (top 100 domains)..."
        cat "$OUTPUT_DIR/live.txt" | head -100 | \
            timeout 45 waybackurls > "$OUTPUT_DIR/wayback.txt" || 
            touch "$OUTPUT_DIR/wayback.txt"
    fi
    
    # Merge ALL URLs
    log_info "Merging URLs..."
    {
        cat "$OUTPUT_DIR"/{katana,wayback}.txt 2>/dev/null;
        cat "$OUTPUT_DIR/live.txt" | sed 's#^#https://#';
    } | sort -u | grep -E "^https?://" > "$OUTPUT_DIR/all_live_urls.txt"
    
    # INTELLIGENT PRIORITIZATION - FIXED REGEX
    log_info "Prioritizing critical endpoints..."
    
    # CRITICAL: High-value paths (no parentheses)
    grep -E -i "admin|api|login|auth|dashboard|panel|portal|dev|stage|qa|beta|test|staging|uat|debug|config|backup|private|internal|console|mgmt|management|control|gateway|proxy|redirect" \
         "$OUTPUT_DIR/all_live_urls.txt" > "$OUTPUT_DIR/critical_urls.txt" 2>/dev/null || 
         touch "$OUTPUT_DIR/critical_urls.txt"
    
    # Remove noise files - FIXED REGEX
    grep -v -E "manifest\.json|site\.webmanifest|i18n.*\.json|olkerror\.html|favicon\.ico|robots\.txt|sitemap\.xml|\.DS_Store" \
         "$OUTPUT_DIR/critical_urls.txt" > "$OUTPUT_DIR/vuln_targets.txt" 2>/dev/null || 
         touch "$OUTPUT_DIR/vuln_targets.txt"
    
    local total=$(wc -l < "$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null || echo 0)
    local critical=$(wc -l < "$OUTPUT_DIR/vuln_targets.txt" 2>/dev/null || echo 0)
    log_success "URLs: $total total -> $critical CRITICAL prioritized -> vuln_targets.txt"
}

################################################################################
# Module: Web Vulnerability Scanning
################################################################################
run_web_vuln_scan() {
    log_info "Intelligent web vulnerability scanning..."
    
    # PRIORITY 1: CRITICAL URLS (limit to 50)
    if [[ -s "$OUTPUT_DIR/vuln_targets.txt" ]]; then
        critical_count=$(wc -l < "$OUTPUT_DIR/vuln_targets.txt" 2>/dev/null || echo 0)
        log_info "Nuclei: $critical_count CRITICAL URLs..."
        head -50 "$OUTPUT_DIR/vuln_targets.txt" > "$OUTPUT_DIR/scan_critical.txt"
        timeout 120 nuclei -l "$OUTPUT_DIR/scan_critical.txt" \
            -tags http,cve,misconfig,default-login,auth-bypass,xss,lfi,rfi,ssrf,api \
            -severity critical,high,medium -c 20 \
            -H "User-Agent: $USER_AGENT" \
            -o "$OUTPUT_DIR/http-vulns.txt" 2>/dev/null || {
                log_warning "Nuclei partial results saved"
            }
        rm -f "$OUTPUT_DIR/scan_critical.txt"
    fi
    
    # PRIORITY 2: Top live subdomains (25 max) - FIXED SYNTAX
    log_info "Nikto: Top 25 live subdomains..."
    if [[ -f "$OUTPUT_DIR/live.txt" ]]; then
        {
            echo "=== $(date) JAWS Nikto Scan ===" 
            head -25 "$OUTPUT_DIR/live.txt" | \
            xargs -I {} -P 5 timeout 25 sh -c '
                echo "--- $(date) https://{} ---" &&
                nikto -h "https://{}" -Format txt -user-agent "'"$USER_AGENT"'" \
                    -Tuning x 2>/dev/null || echo "Nikto: {} - failed/timeout"
            '
        } > "$OUTPUT_DIR/nikto.txt" 2>/dev/null || touch "$OUTPUT_DIR/nikto.txt"
    fi
    
    # PRIORITY 3: Fallback to top ALL URLs if no critical results - FIXED PIPE
    if [[ ! -s "$OUTPUT_DIR/http-vulns.txt" && -s "$OUTPUT_DIR/all_live_urls.txt" ]]; then
        log_info "Fallback: Top 100 ALL URLs..."
        head -100 "$OUTPUT_DIR/all_live_urls.txt" > "$OUTPUT_DIR/top100_urls.txt"
        timeout 90 nuclei -l "$OUTPUT_DIR/top100_urls.txt" \
            -tags misconfig,http -c 10 \
            -H "User-Agent: $USER_AGENT" \
            -o "$OUTPUT_DIR/http-vulns.txt" 2>/dev/null || touch "$OUTPUT_DIR/http-vulns.txt"
        rm -f "$OUTPUT_DIR/top100_urls.txt"
    fi
    
    # Results summary
    local nuclei=$(wc -l < "$OUTPUT_DIR/http-vulns.txt" 2>/dev/null || echo 0)
    local nikto_size=$(stat -c%s "$OUTPUT_DIR/nikto.txt" 2>/dev/null || echo 0)
    log_success "Web scan COMPLETE | Nuclei: $nuclei | Nikto: $(($nikto_size/1024))KB"
}

################################################################################
# Module: Directory Bruteforcing
################################################################################
run_directory_brute() {
    log_info "Preparing targeted directory bruteforcing..."
    
    # Ensure we have URLs, fallback to live subdomains if needed
    if [[ ! -f "$OUTPUT_DIR/all_live_urls.txt" || ! -s "$OUTPUT_DIR/all_live_urls.txt" ]]; then
        log_warning "No URLs found, converting live subdomains for directory bruteforcing"
        if [[ -f "$OUTPUT_DIR/live.txt" && -s "$OUTPUT_DIR/live.txt" ]]; then
            # Convert domains to HTTPS URLs
            cat "$OUTPUT_DIR/live.txt" | \
                sed 's#^#https://#' > "$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null
            log_verbose "Created $OUTPUT_DIR/all_live_urls.txt from live subdomains"
        else
            log_warning "No targets available for directory bruteforcing"
            return
        fi
    fi
    
    # Extract interesting paths (API, admin, dev, test, debug, etc.)
    grep -Ei "(api|admin|dev|test|debug|config|backup|private|wp-admin|phpmyadmin)" "$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null | \
        sed 's#https\?://[^/]*##g' | \
        cut -d'?' -f1 | \
        cut -d'#' -f1 | \
        sort -u | \
        grep -v '^/$' > "$OUTPUT_DIR/gobuster_paths.txt"
    
    local path_count=$(wc -l < "$OUTPUT_DIR/gobuster_paths.txt" 2>/dev/null || echo 0)
    
    if [[ $path_count -gt 0 ]]; then
        log_success "Found $path_count interesting paths for targeted bruteforcing"
        log_info "Ready for gobuster - use this optimized command:"
        echo -e "${CYAN}cat $OUTPUT_DIR/live.txt | sed 's#^#https://#' | \\
xargs -I {} -P $THREADS gobuster dir -u {} -w /path/to/wordlist.txt \\
    -a \"$USER_AGENT\" ${RATE_LIMIT:+ -r -t $THREADS} --no-tls-validation${NC}"
        echo -e "${YELLOW}Paths saved: $OUTPUT_DIR/gobuster_paths.txt${NC}"
    else
        log_warning "No interesting paths found for bruteforcing"
        log_info "This is normal for highly-secured targets like coca-cola.com"
    fi
}

################################################################################
# Initialize
################################################################################
init_scanner() {
    # Set default output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$SCRIPT_DIR/output/$TARGET"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    log_success "Output directory: $OUTPUT_DIR"
    
    # Check dependencies
    check_dependencies
    
    # Log configuration
    log_verbose "Target: $TARGET"
    log_verbose "User-Agent: $USER_AGENT"
    log_verbose "Threads: $THREADS"
    if [[ $RATE_LIMIT -gt 0 ]]; then
        log_verbose "Rate Limit: $RATE_LIMIT req/s"
    fi
}

################################################################################
# Main Scan
################################################################################
run_scan() {
    local start_time=$(date +%s)
    
    log_info "Starting JAWS scan on $TARGET"
    echo ""
    
    # Run enabled modules
    if should_run_module "subdomain"; then
        run_subdomain_enum
        echo ""
    fi
    
    if should_run_module "portscan"; then
        run_port_scan
        echo ""
    fi
    
    if should_run_module "urls"; then
        run_url_discovery
        echo ""
    fi
    
    if should_run_module "webvuln"; then
        run_web_vuln_scan
        echo ""
    fi
    
    if should_run_module "dirbust"; then
        run_directory_brute
        echo ""
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "SCAN COMPLETE! (${duration}s)"
    echo ""
    echo -e "${GREEN}Priority Outputs:${NC}"
    [[ -f "$OUTPUT_DIR/live.txt" ]] && echo "  → $OUTPUT_DIR/live.txt (live subdomains)"
    [[ -f "$OUTPUT_DIR/naabu-vulns.txt" ]] && echo "  → $OUTPUT_DIR/naabu-vulns.txt (network vulnerabilities)"
    [[ -f "$OUTPUT_DIR/http-vulns.txt" ]] && echo "  → $OUTPUT_DIR/http-vulns.txt (web vulnerabilities)"
    [[ -f "$OUTPUT_DIR/all_live_urls.txt" ]] && echo "  → $OUTPUT_DIR/all_live_urls.txt (endpoints for manual testing)"
    [[ -f "$OUTPUT_DIR/naabu.txt" ]] && echo "  → $OUTPUT_DIR/naabu.txt (ports for deeper nmap scan)"
}

################################################################################
# Main
################################################################################
main() {
    show_banner
    parse_args "$@"
    
    # Validate target
    if [[ -z "$TARGET" ]]; then
        log_error "No target specified!"
        echo ""
        show_help
        exit 1
    fi
    
    init_scanner
    run_scan
}

main "$@"
