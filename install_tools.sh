#!/bin/bash

################################################################################
# JAWS V3.0 - Tool Installation Script  
# Installs all required dependencies for JAWS scanner
################################################################################

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================${NC}"
echo -e "${CYAN}JAWS V3.0 - Tool Installation${NC}"
echo -e "${CYAN}================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Do not run this script as root${NC}"
   echo -e "${YELLOW}[*] Run as normal user, sudo will be requested when needed${NC}"
   exit 1
fi

# Detect shell and set RC file
SHELL_NAME=$(basename "$SHELL")
if [[ "$SHELL_NAME" == "zsh" ]]; then
    RC_FILE="$HOME/.zshrc"
elif [[ "$SHELL_NAME" == "bash" ]]; then
    RC_FILE="$HOME/.bashrc"
else
    RC_FILE="$HOME/.bashrc"  # Default to bashrc
fi

echo -e "${BLUE}[*] Detected shell: $SHELL_NAME${NC}"
echo -e "${BLUE}[*] Using RC file: $RC_FILE${NC}"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}[!] Cannot detect OS${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Detected OS: $OS${NC}"
echo ""

################################################################################
# Install Go (required for many tools)
################################################################################
install_go() {
    if command -v go &> /dev/null; then
        echo -e "${GREEN}[+] Go already installed: $(go version)${NC}"
        return
    fi
    
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    
    GO_VERSION="1.23.6"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to PATH if not already there
    if ! grep -q "/usr/local/go/bin" "$RC_FILE"; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$RC_FILE"
        echo -e "${BLUE}  → Added Go to PATH in $RC_FILE${NC}"
    fi
    
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    echo -e "${GREEN}[+] Go $(go version) installed successfully${NC}"
}

################################################################################
# Install system dependencies
################################################################################
install_system_deps() {
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
    
    case $OS in
        ubuntu|debian|kali)
            sudo apt update
            sudo apt install -y git wget curl python3 python3-pip build-essential libpcap-dev golang-go
            ;;
        fedora|rhel|centos)
            sudo dnf install -y git wget curl python3 python3-pip gcc make libpcap-devel golang
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm git wget curl python python-pip base-devel libpcap go
            ;;
        *)
            echo -e "${RED}[!] Unsupported OS: $OS${NC}"
            echo -e "${YELLOW}[*] Please install manually: git, wget, curl, python3, pip3, build tools, go${NC}"
            return
            ;;
    esac
    
    echo -e "${GREEN}[+] System dependencies installed${NC}"
}

################################################################################
# Install Go-based tools 
################################################################################
install_go_tools() {
    echo -e "${YELLOW}[*] Installing Go-based tools...${NC}"
    
    # Subfinder v2.6.6
    echo -e "${BLUE}  → Installing subfinder v2.6.6...${NC}"
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6
    
    # Httpx v1.6.0
    echo -e "${BLUE}  → Installing httpx v1.6.0...${NC}"
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0
    
    # Nuclei v3.3.9
    echo -e "${BLUE}  → Installing nuclei v3.3.9...${NC}"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9
    
    # Katana v1.1.2
    echo -e "${BLUE}  → Installing katana v1.1.2...${NC}"
    go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2
    
    # Naabu v2.3.1
    echo -e "${BLUE}  → Installing naabu v2.3.1...${NC}"
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1
    
    # WAYBACKURLS
    echo -e "${BLUE}  → Installing waybackurls...${NC}"
    go install github.com/tomnomnom/waybackurls@latest
    
    # Gobuster v3.6.0
    echo -e "${BLUE}  → Installing gobuster...${NC}"
    go install github.com/OJ/gobuster/v3@latest
    
    echo -e "${GREEN}[+] Go-based tools installed${NC}"
}

################################################################################
# Install Amass
################################################################################
install_amass() {
    echo -e "${YELLOW}[*] Installing Amass...${NC}"
    
    if command -v amass &> /dev/null; then
        echo -e "${GREEN}[+] Amass already installed: $(amass version 2>&1 | head -1)${NC}"
        return
    fi
    
    go install github.com/owasp-amass/amass/v4@latest
    
    echo -e "${GREEN}[+] Amass installed successfully${NC}"
}

################################################################################
# Install Sublist3r
################################################################################
install_sublist3r() {
    echo -e "${YELLOW}[*] Installing Sublist3r...${NC}"
    
    if command -v sublist3r &> /dev/null; then
        echo -e "${GREEN}[+] Sublist3r already installed${NC}"
        return
    fi
    
    pip3 install --user sublist3r || {
        echo -e "${YELLOW}[*] Installing sublist3r requirements first...${NC}"
        pip3 install --user requests dnspython argparse
        pip3 install --user sublist3r
    }
    
    # Add to PATH if not already there
    if ! grep -q "$HOME/.local/bin" "$RC_FILE"; then
        echo 'export PATH=$PATH:$HOME/.local/bin' >> "$RC_FILE"
        echo -e "${BLUE}  → Added Python local bin to PATH in $RC_FILE${NC}"
    fi
    
    export PATH=$PATH:$HOME/.local/bin
    
    echo -e "${GREEN}[+] Sublist3r installed${NC}"
}

################################################################################
# Install Nmap
################################################################################
install_nmap() {
    echo -e "${YELLOW}[*] Installing Nmap...${NC}"
    
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}[+] Nmap already installed: $(nmap --version | head -1)${NC}"
        return
    fi
    
    case $OS in
        ubuntu|debian|kali)
            sudo apt install -y nmap
            ;;
        fedora|rhel|centos)
            sudo dnf install -y nmap
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm nmap
            ;;
    esac
    
    echo -e "${GREEN}[+] Nmap installed${NC}"
}

################################################################################
# Install Nikto
################################################################################
install_nikto() {
    echo -e "${YELLOW}[*] Installing Nikto...${NC}"
    
    if command -v nikto &> /dev/null; then
        echo -e "${GREEN}[+] Nikto already installed${NC}"
        return
    fi
    
    case $OS in
        ubuntu|debian|kali)
            sudo apt install -y nikto
            ;;
        fedora|rhel|centos)
            sudo dnf install -y nikto || sudo yum install -y nikto
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm nikto
            ;;
    esac
    
    echo -e "${GREEN}[+] Nikto installed${NC}"
}

################################################################################
# Update Nuclei templates
################################################################################
update_nuclei_templates() {
    if command -v nuclei &> /dev/null; then
        echo -e "${YELLOW}[*] Updating Nuclei templates...${NC}"
        nuclei -update-templates
        echo -e "${GREEN}[+] Nuclei templates updated${NC}"
    fi
}

################################################################################
# Verify installations
################################################################################
verify_tools() {
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}Verifying Tool Installation${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
    
    declare -A tools=(
        ["amass"]="amass version"
        ["subfinder"]="subfinder -version"
        ["sublist3r"]="sublist3r -h"
        ["naabu"]="naabu -version"
        ["katana"]="katana -version"
        ["httpx"]="httpx -version"
        ["nuclei"]="nuclei -version"
        ["nikto"]="nikto -Version"
        ["gobuster"]="gobuster version"
        ["nmap"]="nmap --version"
        ["waybackurls"]="waybackurls -h"  # NEW: Added waybackurls
    )
    
    local missing=()
    
    for tool in "${!tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            version=$($tool ${tools[$tool]} 2>&1 | head -1 | grep -oP '\d+\.\d+(\.\d+)*' | head -1 || echo "installed")
            echo -e "${GREEN}[✓]${NC} $tool $version"
        else
            echo -e "${RED}[✗]${NC} $tool"
            missing+=("$tool")
        fi
    done
    
    echo ""
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        echo -e "${GREEN}[+] 🎉 All JAWS V3.0 tools installed successfully!${NC}"
    else
        echo -e "${YELLOW}[!] ⚠️  Missing tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Run script again or install manually${NC}"
    fi
    
    echo -e "${BLUE}[*] Reload shell: source $RC_FILE${NC}"
}

################################################################################
# Main installation
################################################################################
main() {
    echo -e "${BLUE}[*] Starting JAWS V3.0 installation...${NC}"
    echo ""
    
    install_system_deps
    echo ""
    
    install_go
    echo ""
    
    install_go_tools
    echo ""
    
    install_amass
    echo ""
    
    install_sublist3r
    echo ""
    
    install_nmap
    echo ""
    
    install_nikto
    echo ""
    
    update_nuclei_templates
    echo ""
    
    verify_tools
    
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
    echo -e "${YELLOW}[*] ⚡ Quick start:${NC}"
    echo -e "${CYAN}    source $RC_FILE${NC}"
    echo -e "${CYAN}    ./jaws.sh -h${NC}"
    echo ""
}

# Run main installation
main "$@"
