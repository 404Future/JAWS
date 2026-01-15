#!/bin/bash

# fix_path.sh - Quick fix for PATH issues
# Usage: source ./fix_path.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== JAWS PATH Fixer ===${NC}\n"

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_TYPE="zsh"
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_TYPE="bash"
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_TYPE="unknown"
    SHELL_RC="$HOME/.bashrc"
fi

echo -e "${YELLOW}[*] Detected shell: $SHELL_TYPE${NC}"

# Add to PATH for current session
export PATH=$PATH:~/go/bin

echo -e "${GREEN}[✓] Added ~/go/bin to current session PATH${NC}"

# Check and add to shell RC file
if ! grep -q "export PATH=\$PATH:~/go/bin" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# Added by JAWS - Bug Bounty Recon Tool" >> "$SHELL_RC"
    echo 'export PATH=$PATH:~/go/bin' >> "$SHELL_RC"
    echo -e "${GREEN}[✓] Added to $SHELL_RC for future sessions${NC}"
else
    echo -e "${BLUE}[*] Already configured in $SHELL_RC${NC}"
fi

# Verify tools are now accessible
echo -e "\n${YELLOW}[*] Verifying tool access...${NC}"

TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu" "dnsx")
accessible=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}  [✓] $tool${NC}"
        ((accessible++))
    else
        echo -e "${RED}  [✗] $tool${NC}"
    fi
done

if [ $accessible -eq ${#TOOLS[@]} ]; then
    echo -e "\n${GREEN}[✓] All core tools are now accessible!${NC}"
    echo -e "${BLUE}[*] You can now run: ./JAWS.sh <domain>${NC}"
else
    echo -e "\n${YELLOW}[!] Some tools are still not accessible${NC}"
    echo -e "${YELLOW}[!] You may need to run: ./install_tools.sh${NC}"
fi

echo -e "\n${BLUE}Note: This script must be sourced, not executed${NC}"
echo -e "${BLUE}Run: ${YELLOW}source ./fix_path.sh${NC}\n"
