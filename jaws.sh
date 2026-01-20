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
    urls         - URL discovery (gau, katana)
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
        required_tools+=(gau katana)
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
        log_info "Install missing tools before running JAWS"
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
    log_info "Starting URL discovery..."
    
    if [[ ! -f "$OUTPUT_DIR/live.txt" ]]; then
        log_warning "No live subdomains found, skipping URL discovery"
        return
    fi
    
    local total_subdomains=$(wc -l < "$OUTPUT_DIR/live.txt")
    local current=0
    
    # Passive collection with gau
    log_verbose "Running gau (passive)..."
    {
        while IFS= read -r subdomain; do
            current=$((current + 1))
            printf "\r${CYAN}[*]${NC} Collecting URLs with gau... [%d/%d subdomains]" "$current" "$total_subdomains"
            echo "$subdomain"
        done < "$OUTPUT_DIR/live.txt" | gau --subs > "$OUTPUT_DIR/gau.txt" 2>/dev/null
        printf "\r\033[K"  # Clear the line
    }
    
    # Active crawling with katana
    current=0
    log_verbose "Running katana (active)..."
    {
        while IFS= read -r subdomain; do
            current=$((current + 1))
            printf "\r${CYAN}[*]${NC} Crawling with katana... [%d/%d subdomains]" "$current" "$total_subdomains"
            echo "$subdomain"
        done < "$OUTPUT_DIR/live.txt" | \
            katana -silent -jc -ef js,css -H "User-Agent: $USER_AGENT" -o "$OUTPUT_DIR/katana.txt" 2>/dev/null
        printf "\r\033[K"  # Clear the line
    }
    
    # Merge and filter live URLs
    log_info "Filtering live URLs..."
    local total_urls=$(cat "$OUTPUT_DIR/gau.txt" "$OUTPUT_DIR/katana.txt" 2>/dev/null | sort -u | grep -E "^https?://" | wc -l)
    current=0
    
    {
        cat "$OUTPUT_DIR/gau.txt" "$OUTPUT_DIR/katana.txt" 2>/dev/null | \
            sort -u | \
            grep -E "^https?://" | \
            while IFS= read -r url; do
                current=$((current + 1))
                if (( current % 10 == 0 )); then
                    printf "\r${CYAN}[*]${NC} Verifying URLs with httpx... [%d/%d URLs]" "$current" "$total_urls"
                fi
                echo "$url"
            done | \
            httpx -mc 200-399 -silent -H "User-Agent: $USER_AGENT" -o "$OUTPUT_DIR/all_live_urls.txt"
        printf "\r\033[K"  # Clear the line
    }
    
    # Ensure file exists for counting
    touch "$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null
    local url_count=$(wc -l <"$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null || echo 0)
    log_success "Discovered $url_count live URLs → $OUTPUT_DIR/all_live_urls.txt"
}

################################################################################
# Module: Web Vulnerability Scanning
################################################################################
run_web_vuln_scan() {
    log_info "Starting web vulnerability scanning..."
    
    if [[ ! -f "$OUTPUT_DIR/all_live_urls.txt" ]]; then
        log_warning "No URLs found, using live subdomains instead"
        if [[ ! -f "$OUTPUT_DIR/live.txt" ]]; then
            log_error "No targets for web scanning"
            return
        fi
        cp "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR/all_live_urls.txt"
    fi
    
    # Nuclei scan
    log_verbose "Running nuclei..."
    nuclei -l "$OUTPUT_DIR/all_live_urls.txt" \
        -t cves/ -t misconfig/ \
        -silent \
        -H "User-Agent: $USER_AGENT" \
        -o "$OUTPUT_DIR/http-vulns.txt" 2>/dev/null
    
    # Nikto scan
    log_verbose "Running nikto..."
    cat "$OUTPUT_DIR/live.txt" 2>/dev/null | \
        nikto -h - -Format json -useragent "$USER_AGENT" -o "$OUTPUT_DIR/nikto.json" 2>/dev/null
    
    local vuln_count=$(wc -l < "$OUTPUT_DIR/http-vulns.txt" 2>/dev/null || echo 0)
    log_success "Web scan complete, found $vuln_count potential vulnerabilities → $OUTPUT_DIR/http-vulns.txt"
}

################################################################################
# Module: Directory Bruteforcing
################################################################################
run_directory_brute() {
    log_info "Preparing targeted directory bruteforcing..."
    
    if [[ ! -f "$OUTPUT_DIR/all_live_urls.txt" ]]; then
        log_warning "No URLs found for directory bruteforcing"
        return
    fi
    
    # Extract interesting paths (API, admin, dev, test, debug)
    grep -E "(api|admin|dev|test|debug)" "$OUTPUT_DIR/all_live_urls.txt" 2>/dev/null | \
        sed 's#https\?://[^/]*##g' | \
        cut -d'?' -f1 | \
        sort -u > "$OUTPUT_DIR/gobuster_paths.txt"
    
    local path_count=$(wc -l < "$OUTPUT_DIR/gobuster_paths.txt" 2>/dev/null || echo 0)
    
    if [[ $path_count -gt 0 ]]; then
        log_success "Found $path_count interesting paths for targeted bruteforcing"
        log_info "Manual gobuster command:"
        echo -e "${CYAN}while read sub; do while read path; do gobuster dir -u \$sub\$path -w /path/to/wordlist.txt -a \"$USER_AGENT\"; done < $OUTPUT_DIR/gobuster_paths.txt; done < $OUTPUT_DIR/live.txt${NC}"
    else
        log_warning "No interesting paths found for bruteforcing"
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
