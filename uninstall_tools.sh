#!/bin/bash

# uninstall_tools.sh - Uninstall all JAWS tools and cleanup
# Usage: ./uninstall_tools.sh [--full]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}"
cat << "EOF"
 ██╗   ██╗███╗   ██╗██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
 ██║   ██║████╗  ██║██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
 ██║   ██║██╔██╗ ██║██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
 ██║   ██║██║╚██╗██║██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
 ╚██████╔╝██║ ╚████║██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
                    JAWS Uninstaller
EOF
echo -e "${NC}"

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

FULL_UNINSTALL=false
if [ "$1" = "--full" ]; then
    FULL_UNINSTALL=true
fi

echo -e "${YELLOW}This will uninstall JAWS reconnaissance tools.${NC}"
echo -e "${YELLOW}Shell config: $SHELL_RC${NC}"

if [ "$FULL_UNINSTALL" = true ]; then
    echo -e "${RED}FULL uninstall mode - will also remove wordlists and configs${NC}"
fi

echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${BLUE}[*] Uninstall cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}[*] Starting uninstallation...${NC}"

# Remove Go-based tools
echo -e "\n${YELLOW}[*] Removing Go-based reconnaissance tools...${NC}"

GO_TOOLS=(
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
    "puredns"
)

for tool in "${GO_TOOLS[@]}"; do
    if [ -f "$HOME/go/bin/$tool" ]; then
        rm -f "$HOME/go/bin/$tool"
        echo -e "${GREEN}  [✓] Removed $tool${NC}"
    else
        echo -e "${BLUE}  [·] $tool not found${NC}"
    fi
done

# Remove nuclei templates
if [ -d "$HOME/nuclei-templates" ]; then
    echo -e "${YELLOW}[*] Removing nuclei templates...${NC}"
    rm -rf "$HOME/nuclei-templates"
    echo -e "${GREEN}[✓] Nuclei templates removed${NC}"
fi

# Remove Python tools
echo -e "\n${YELLOW}[*] Removing Python tools...${NC}"

if [ -d "$HOME/tools/dirsearch" ]; then
    rm -rf "$HOME/tools/dirsearch"
    echo -e "${GREEN}  [✓] Removed dirsearch${NC}"
fi

if [ -d "$HOME/tools" ] && [ -z "$(ls -A $HOME/tools)" ]; then
    rmdir "$HOME/tools"
    echo -e "${GREEN}  [✓] Removed empty tools directory${NC}"
fi

# Remove wordlists (only in full mode)
if [ "$FULL_UNINSTALL" = true ]; then
    echo -e "\n${YELLOW}[*] Removing wordlists...${NC}"
    
    if [ -d "$HOME/wordlists/SecLists" ]; then
        rm -rf "$HOME/wordlists/SecLists"
        echo -e "${GREEN}  [✓] Removed SecLists${NC}"
    fi
    
    if [ -f "$HOME/wordlists/subdomains.txt" ]; then
        rm -f "$HOME/wordlists/subdomains.txt"
        echo -e "${GREEN}  [✓] Removed subdomain wordlist symlink${NC}"
    fi
    
    if [ -d "$HOME/wordlists" ] && [ -z "$(ls -A $HOME/wordlists)" ]; then
        rmdir "$HOME/wordlists"
        echo -e "${GREEN}  [✓] Removed empty wordlists directory${NC}"
    fi
    
    # Remove system-wide wordlist if it exists
    if [ -f "/usr/share/wordlists/subdomains-top1million-5000.txt" ] && [ "$EUID" -eq 0 ]; then
        sudo rm -f /usr/share/wordlists/subdomains-top1million-5000.txt
        echo -e "${GREEN}  [✓] Removed system wordlist${NC}"
    fi
fi

# Remove resolvers (only in full mode)
if [ "$FULL_UNINSTALL" = true ]; then
    echo -e "\n${YELLOW}[*] Removing DNS resolvers...${NC}"
    
    if [ -d "$HOME/.config/resolvers" ]; then
        rm -rf "$HOME/.config/resolvers"
        echo -e "${GREEN}  [✓] Removed resolvers${NC}"
    fi
    
    if [ -d "/usr/share/dns" ] && [ "$EUID" -eq 0 ]; then
        sudo rm -rf /usr/share/dns
        echo -e "${GREEN}  [✓] Removed system DNS resolvers${NC}"
    fi
fi

# Clean PATH from shell config
echo -e "\n${YELLOW}[*] Cleaning shell configuration...${NC}"

if [ -f "$SHELL_RC" ]; then
    # Create backup
    cp "$SHELL_RC" "${SHELL_RC}.bak.$(date +%Y%m%d_%H%M%S)"
    echo -e "${BLUE}  [·] Created backup: ${SHELL_RC}.bak${NC}"
    
    # Remove JAWS PATH entries
    sed -i.tmp '/# Added by JAWS/d' "$SHELL_RC" 2>/dev/null || sed -i '' '/# Added by JAWS/d' "$SHELL_RC" 2>/dev/null
    sed -i.tmp '/export PATH=\$PATH:~\/go\/bin/d' "$SHELL_RC" 2>/dev/null || sed -i '' '/export PATH=\$PATH:~\/go\/bin/d' "$SHELL_RC" 2>/dev/null
    rm -f "${SHELL_RC}.tmp"
    
    echo -e "${GREEN}  [✓] Cleaned $SHELL_RC${NC}"
fi

# Ask about scan results
echo -e "\n${YELLOW}[*] Checking for scan results...${NC}"
RECON_DIRS=$(find . -maxdepth 1 -type d -name "*_recon" 2>/dev/null)

if [ -n "$RECON_DIRS" ]; then
    echo -e "${BLUE}Found reconnaissance directories:${NC}"
    echo "$RECON_DIRS"
    echo ""
    read -p "Do you want to remove all *_recon directories? (yes/no): " remove_scans
    
    if [ "$remove_scans" = "yes" ]; then
        find . -maxdepth 1 -type d -name "*_recon" -exec rm -rf {} +
        echo -e "${GREEN}  [✓] Removed scan results${NC}"
    else
        echo -e "${BLUE}  [·] Keeping scan results${NC}"
    fi
fi

# Optional: Remove system packages (only if full and root)
if [ "$FULL_UNINSTALL" = true ] && [ "$EUID" -eq 0 ]; then
    echo -e "\n${YELLOW}[*] System packages...${NC}"
    read -p "Remove system packages (amass, nmap, masscan, jq)? (yes/no): " remove_sys
    
    if [ "$remove_sys" = "yes" ]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            
            if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
                sudo apt remove -y amass nmap masscan jq libpcap-dev pkg-config
                sudo apt autoremove -y
            elif [ "$OS" = "fedora" ] || [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
                sudo dnf remove -y amass nmap masscan jq libpcap-devel pkgconfig
            elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
                sudo pacman -Rs --noconfirm amass nmap masscan jq libpcap pkgconf
            fi
            
            echo -e "${GREEN}  [✓] Removed system packages${NC}"
        fi
    else
        echo -e "${BLUE}  [·] Keeping system packages${NC}"
    fi
fi

# Summary
echo -e "\n${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Uninstallation Complete!            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}What was removed:${NC}"
echo -e "  • Go-based reconnaissance tools from ~/go/bin"
echo -e "  • Nuclei templates"
echo -e "  • Python tools (dirsearch)"
echo -e "  • PATH modifications from $SHELL_RC"

if [ "$FULL_UNINSTALL" = true ]; then
    echo -e "  • Wordlists (SecLists)"
    echo -e "  • DNS resolvers"
fi

echo -e "\n${BLUE}What was preserved:${NC}"
echo -e "  • Go installation"
echo -e "  • Shell configuration backup: ${SHELL_RC}.bak"

if [ "$FULL_UNINSTALL" != true ]; then
    echo -e "  • Wordlists (use --full to remove)"
    echo -e "  • DNS resolvers (use --full to remove)"
fi

echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "  1. Restart your terminal or run: ${BLUE}source $SHELL_RC${NC}"
echo -e "  2. To reinstall fresh: ${BLUE}./install_tools.sh${NC}"
echo -e "  3. Your backup config: ${BLUE}${SHELL_RC}.bak.*${NC}"

echo -e "\n${BLUE}Note: Run with --full flag for complete cleanup:${NC}"
echo -e "  ${YELLOW}./uninstall_tools.sh --full${NC}\n"
