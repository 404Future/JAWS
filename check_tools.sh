#!/bin/bash

# check_tools.sh - Diagnostic script for JAWS
# Usage: ./check_tools.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== JAWS Diagnostic Tool ===${NC}\n"

# Check shell
echo -e "${YELLOW}[*] Checking shell configuration...${NC}"
if [ -n "$ZSH_VERSION" ]; then
    SHELL_TYPE="zsh"
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_TYPE="bash"
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_TYPE="unknown"
    SHELL_RC="unknown"
fi

echo -e "  Shell: $SHELL_TYPE"
echo -e "  RC File: $SHELL_RC"
echo -e "  Current PATH: $PATH"

# Check if Go bin is in PATH
if echo "$PATH" | grep -q "$HOME/go/bin"; then
    echo -e "${GREEN}  [✓] ~/go/bin is in PATH${NC}"
else
    echo -e "${RED}  [✗] ~/go/bin is NOT in PATH${NC}"
    echo -e "${YELLOW}  [!] Run: export PATH=\$PATH:~/go/bin${NC}"
    echo -e "${YELLOW}  [!] Or add to $SHELL_RC: echo 'export PATH=\$PATH:~/go/bin' >> $SHELL_RC${NC}"
fi

# Check Go installation
echo -e "\n${YELLOW}[*] Checking Go installation...${NC}"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version)
    echo -e "${GREEN}  [✓] Go installed: $GO_VERSION${NC}"
    echo -e "  GOPATH: $(go env GOPATH)"
else
    echo -e "${RED}  [✗] Go not installed${NC}"
fi

# List all required tools
echo -e "\n${YELLOW}[*] Checking tool installation...${NC}"

TOOLS=(
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
    "amass"
    "nmap"
    "masscan"
    "jq"
)

installed=0
total=${#TOOLS[@]}

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        TOOL_PATH=$(which "$tool")
        echo -e "${GREEN}  [✓] $tool${NC} -> $TOOL_PATH"
        ((installed++))
    else
        echo -e "${RED}  [✗] $tool${NC}"
        
        # Check if it exists in ~/go/bin but not in PATH
        if [ -f "$HOME/go/bin/$tool" ]; then
            echo -e "${YELLOW}      Found in ~/go/bin but not in PATH!${NC}"
        fi
    fi
done

echo -e "\n${BLUE}Summary: $installed/$total tools installed${NC}"

# Check wordlists
echo -e "\n${YELLOW}[*] Checking wordlists...${NC}"
WORDLIST_PATHS=(
    "/usr/share/wordlists/subdomains-top1million-5000.txt"
    "$HOME/wordlists/subdomains.txt"
    "$HOME/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
)

WORDLIST_FOUND=false
for path in "${WORDLIST_PATHS[@]}"; do
    if [ -f "$path" ]; then
        echo -e "${GREEN}  [✓] Found: $path${NC}"
        WORDLIST_FOUND=true
    fi
done

if [ "$WORDLIST_FOUND" = false ]; then
    echo -e "${RED}  [✗] No wordlists found${NC}"
    echo -e "${YELLOW}  [!] Install: git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists${NC}"
fi

# Check resolvers
echo -e "\n${YELLOW}[*] Checking DNS resolvers...${NC}"
RESOLVER_PATHS=(
    "/usr/share/dns/resolvers.txt"
    "$HOME/.config/resolvers/resolvers.txt"
)

RESOLVER_FOUND=false
for path in "${RESOLVER_PATHS[@]}"; do
    if [ -f "$path" ]; then
        echo -e "${GREEN}  [✓] Found: $path${NC}"
        RESOLVER_FOUND=true
    fi
done

if [ "$RESOLVER_FOUND" = false ]; then
    echo -e "${YELLOW}  [!] No resolvers found (optional, will use defaults)${NC}"
fi

# Check JAWS files
echo -e "\n${YELLOW}[*] Checking JAWS files...${NC}"
if [ -f "JAWS.sh" ]; then
    echo -e "${GREEN}  [✓] JAWS.sh found${NC}"
    if [ -x "JAWS.sh" ]; then
        echo -e "${GREEN}  [✓] JAWS.sh is executable${NC}"
    else
        echo -e "${RED}  [✗] JAWS.sh is NOT executable${NC}"
        echo -e "${YELLOW}  [!] Run: chmod +x JAWS.sh${NC}"
    fi
else
    echo -e "${RED}  [✗] JAWS.sh not found${NC}"
fi

if [ -f "scan.lib" ]; then
    echo -e "${GREEN}  [✓] scan.lib found${NC}"
else
    echo -e "${RED}  [✗] scan.lib not found${NC}"
fi

# Recommendations
echo -e "\n${BLUE}=== Recommendations ===${NC}"

if [ $installed -lt $total ]; then
    echo -e "${YELLOW}[!] Missing tools detected${NC}"
    echo -e "    Run: ${BLUE}./install_tools.sh${NC} to install missing tools"
fi

if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
    echo -e "${YELLOW}[!] PATH not configured${NC}"
    echo -e "    Run: ${BLUE}export PATH=\$PATH:~/go/bin${NC}"
    echo -e "    Or: ${BLUE}source $SHELL_RC${NC}"
    echo -e "    Or restart your terminal"
fi

if [ $installed -eq $total ] && echo "$PATH" | grep -q "$HOME/go/bin"; then
    echo -e "${GREEN}[✓] All checks passed! You're ready to use JAWS${NC}"
    echo -e "    Run: ${BLUE}./JAWS.sh -h${NC}"
fi

echo ""
