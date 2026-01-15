#!/bin/bash

# install_tools.sh - Install all tools needed for JAWS.sh
# Run with: sudo ./install_tools.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
 ╦╔╗╔╔═╗╔╦╗╔═╗╦  ╦  ╔═╗╦═╗
 ║║║║╚═╗ ║ ╠═╣║  ║  ║╣ ╠╦╝
 ╩╝╚╝╚═╝ ╩ ╩ ╩╩═╝╩═╝╚═╝╩╚═
   JAWS Tool Installer
EOF
echo -e "${NC}"

# Check if running as root for some installations
if [ "$EUID" -ne 0 ] && [ "$1" != "--user" ]; then 
    echo -e "${YELLOW}[!] Some tools require sudo. Run with sudo or use --user flag for user installation only${NC}"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}[!] Cannot detect OS${NC}"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
install_go() {
    if command_exists go; then
        echo -e "${GREEN}[✓] Go is already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        sudo apt update
        sudo apt install -y golang-go
    elif [ "$OS" = "fedora" ] || [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
        sudo dnf install -y golang
    elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
        sudo pacman -S --noconfirm go
    else
        # Manual installation
        wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
        source ~/.bashrc
    fi
    
    # Set Go environment variables
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:~/go/bin
    
    echo -e "${GREEN}[✓] Go installed${NC}"
}

# Install system dependencies
install_dependencies() {
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        sudo apt update
        sudo apt install -y curl wget git build-essential jq python3 python3-pip nmap masscan
    elif [ "$OS" = "fedora" ] || [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
        sudo dnf install -y curl wget git gcc make jq python3 python3-pip nmap masscan
    elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
        sudo pacman -S --noconfirm curl wget git base-devel jq python python-pip nmap masscan
    fi
    
    echo -e "${GREEN}[✓] System dependencies installed${NC}"
}

# Install Go-based tools
install_go_tools() {
    echo -e "${YELLOW}[*] Installing Go-based reconnaissance tools...${NC}"
    
    # ProjectDiscovery tools (most important)
    echo -e "${BLUE}  [→] Installing subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    echo -e "${BLUE}  [→] Installing httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    echo -e "${BLUE}  [→] Installing nuclei...${NC}"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    echo -e "${BLUE}  [→] Installing katana...${NC}"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    
    echo -e "${BLUE}  [→] Installing naabu...${NC}"
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    
    echo -e "${BLUE}  [→] Installing dnsx...${NC}"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    
    # Other essential tools
    echo -e "${BLUE}  [→] Installing assetfinder...${NC}"
    go install -v github.com/tomnomnom/assetfinder@latest
    
    echo -e "${BLUE}  [→] Installing waybackurls...${NC}"
    go install -v github.com/tomnomnom/waybackurls@latest
    
    echo -e "${BLUE}  [→] Installing gau...${NC}"
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    
    echo -e "${BLUE}  [→] Installing gowitness...${NC}"
    go install -v github.com/sensepost/gowitness@latest
    
    echo -e "${BLUE}  [→] Installing puredns...${NC}"
    go install -v github.com/d3mondev/puredns/v2@latest
    
    echo -e "${GREEN}[✓] Go tools installed${NC}"
}

# Install Amass
install_amass() {
    echo -e "${YELLOW}[*] Installing Amass...${NC}"
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        sudo apt install -y amass
    else
        go install -v github.com/owasp-amass/amass/v4/...@master
    fi
    
    echo -e "${GREEN}[✓] Amass installed${NC}"
}

# Install Python tools
install_python_tools() {
    echo -e "${YELLOW}[*] Installing Python-based tools...${NC}"
    
    # Dirsearch
    if [ ! -d "$HOME/tools/dirsearch" ]; then
        echo -e "${BLUE}  [→] Installing dirsearch...${NC}"
        mkdir -p ~/tools
        git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch
    fi
    
    # Install requirements for various tools
    pip3 install requests beautifulsoup4 colorama --break-system-packages 2>/dev/null || pip3 install requests beautifulsoup4 colorama
    
    echo -e "${GREEN}[✓] Python tools installed${NC}"
}

# Install wordlists
install_wordlists() {
    echo -e "${YELLOW}[*] Installing wordlists...${NC}"
    
    mkdir -p ~/wordlists
    
    # SecLists
    if [ ! -d "$HOME/wordlists/SecLists" ]; then
        echo -e "${BLUE}  [→] Cloning SecLists...${NC}"
        git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists
    fi
    
    # Create symlink for common wordlist
    if [ -f "$HOME/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
        ln -sf "$HOME/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" ~/wordlists/subdomains.txt
    fi
    
    echo -e "${GREEN}[✓] Wordlists installed${NC}"
}

# Download DNS resolvers
install_resolvers() {
    echo -e "${YELLOW}[*] Downloading DNS resolvers...${NC}"
    
    mkdir -p ~/.config/resolvers
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o ~/.config/resolvers/resolvers.txt
    
    # Create system-wide location
    if [ "$EUID" -eq 0 ]; then
        mkdir -p /usr/share/dns
        cp ~/.config/resolvers/resolvers.txt /usr/share/dns/resolvers.txt
    fi
    
    echo -e "${GREEN}[✓] DNS resolvers downloaded${NC}"
}

# Post-installation configuration
post_install() {
    echo -e "${YELLOW}[*] Performing post-installation configuration...${NC}"
    
    # Add Go bin to PATH if not already there
    if ! grep -q "export PATH=\$PATH:~/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    fi
    
    # Update nuclei templates
    if command_exists nuclei; then
        echo -e "${BLUE}  [→] Updating nuclei templates...${NC}"
        nuclei -update-templates -silent
    fi
    
    # Make JAWS.sh executable
    if [ -f "JAWS.sh" ]; then
        chmod +x JAWS.sh
        echo -e "${GREEN}[✓] Made JAWS.sh executable${NC}"
    fi
    
    if [ -f "scan.lib" ]; then
        chmod +x scan.lib
    fi
    
    echo -e "${GREEN}[✓] Post-installation complete${NC}"
}

# Verification
verify_installation() {
    echo -e "\n${YELLOW}[*] Verifying installation...${NC}\n"
    
    tools=(
        "subfinder"
        "httpx"
        "nuclei"
        "katana"
        "naabu"
        "dnsx"
        "assetfinder"
        "waybackurls"
        "gau"
        "gowitness"
        "amass"
        "nmap"
    )
    
    installed=0
    total=${#tools[@]}
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            echo -e "${GREEN}[✓] $tool${NC}"
            ((installed++))
        else
            echo -e "${RED}[✗] $tool${NC}"
        fi
    done
    
    echo -e "\n${BLUE}Installed: $installed/$total tools${NC}"
    
    if [ $installed -eq $total ]; then
        echo -e "${GREEN}\n[✓] All tools successfully installed!${NC}"
        echo -e "${YELLOW}[*] Run 'source ~/.bashrc' to update your PATH${NC}"
        echo -e "${YELLOW}[*] Then run: ./JAWS.sh -h${NC}"
    else
        echo -e "${YELLOW}\n[!] Some tools failed to install. Check errors above.${NC}"
    fi
}

# Main installation
main() {
    echo -e "${BLUE}Starting JAWS tool installation...${NC}\n"
    
    install_dependencies
    install_go
    install_go_tools
    install_amass
    install_python_tools
    install_wordlists
    install_resolvers
    post_install
    verify_installation
    
    echo -e "\n${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Installation Complete!             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo -e "\n${YELLOW}Next steps:${NC}"
    echo -e "1. Run: ${BLUE}source ~/.bashrc${NC}"
    echo -e "2. Test: ${BLUE}./JAWS.sh -h${NC}"
    echo -e "3. Scan: ${BLUE}./JAWS.sh example.com${NC}\n"
}

# Run main installation
main
