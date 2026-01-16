# JAWS Changelog

## Latest Updates - Fixed All Critical Issues

### Bug Fixes

#### 1. Shell Detection Issue (CRITICAL FIX)
**Problem:** Scripts were detecting bash even when user was running zsh
**Impact:** PATH added to wrong config file (.bashrc instead of .zshrc)
**Fix:** Now uses `basename "$SHELL"` to detect actual user shell

**Files Updated:**
- `install_tools.sh` - Detects user shell correctly
- `uninstall_tools.sh` - Uses correct shell RC file
- `check_tools.sh` - Shows actual user shell
- `fix_path.sh` - Detects and fixes correct shell config

#### 2. Function Definition Order (JAWS.sh)
**Problem:** `show_help` function called before it was defined
**Impact:** `./JAWS.sh -h` failed with "command not found"
**Fix:** Moved `show_help` function before argument parsing

**File Updated:**
- `JAWS.sh` - Reorganized function order

#### 3. PATH Export During Installation
**Problem:** PATH not exported during install, so verification failed
**Impact:** Tools installed but appeared as "not installed" in verification
**Fix:** Added `export PATH=$PATH:~/go/bin` in install functions

**File Updated:**
- `install_tools.sh` - Exports PATH during Go tools installation and verification

#### 4. Missing Dependencies
**Problem:** naabu requires libpcap-dev AND pkg-config
**Impact:** naabu installation failed
**Fix:** Added both dependencies to all package managers

**File Updated:**
- `install_tools.sh` - Added pkg-config to apt, dnf, and pacman commands

#### 5. Verbose Go Install Output
**Problem:** Too much output from `go install` commands
**Impact:** Hard to see what's actually happening
**Fix:** Added `grep -v "^go:"` to filter download messages

**File Updated:**
- `install_tools.sh` - Cleaner output during installation

#### 6. Wordlist Path Detection
**Problem:** Hardcoded wordlist path didn't match all installations
**Impact:** Bruteforce phase skipped
**Fix:** Checks multiple common paths in priority order

**File Updated:**
- `scan.lib` - Improved wordlist detection in `subdomain_bruteforce()`

#### 7. Better Error Messages
**Problem:** Unclear what to do when verification fails
**Impact:** Users didn't know next steps
**Fix:** Added clear instructions based on installation result

**File Updated:**
- `install_tools.sh` - Improved verification messages

---

## Summary of All Scripts

### Main Scripts
1. **JAWS.sh** - Main reconnaissance script
   - ✅ Fixed function order
   - ✅ All modes working (full, passive, active, quick, custom)

2. **scan.lib** - Tool function library
   - ✅ Fixed wordlist detection
   - ✅ All 8 phases implemented

3. **install_tools.sh** - Automated installer
   - ✅ Fixed shell detection
   - ✅ Added pkg-config dependency
   - ✅ Exports PATH during install
   - ✅ Better verification messages

4. **uninstall_tools.sh** - Clean uninstaller
   - ✅ Fixed shell detection
   - ✅ Two modes: standard and --full

5. **check_tools.sh** - Diagnostic tool
   - ✅ Fixed shell detection
   - ✅ Shows if tools exist but not in PATH

6. **fix_path.sh** - Quick PATH fix
   - ✅ Fixed shell detection
   - ✅ Must be sourced: `source ./fix_path.sh`

---

## Installation Instructions (Updated)

### Fresh Install
```bash
# 1. Clone repository
git clone https://github.com/yourusername/jaws.git
cd jaws

# 2. Make scripts executable
chmod +x *.sh

# 3. Run installer
sudo ./install_tools.sh

# 4. Update PATH (IMPORTANT!)
# For zsh users:
source ~/.zshrc
# For bash users:
source ~/.bashrc
# OR just restart your terminal

# 5. Verify everything works
./check_tools.sh

# 6. Run JAWS
./JAWS.sh -h
```

### If You Have Issues

```bash
# Diagnostic
./check_tools.sh

# Quick fix
source ./fix_path.sh

# Clean reinstall
./uninstall_tools.sh --full
sudo ./install_tools.sh
source ~/.zshrc  # or ~/.bashrc
```

---

## Known Working Configuration

**Tested on:**
- Ubuntu/Debian with zsh ✅
- Ubuntu/Debian with bash ✅

**All 15 tools verified:**
- subfinder ✅
- httpx ✅
- nuclei ✅
- katana ✅
- naabu ✅
- dnsx ✅
- assetfinder ✅
- waybackurls ✅
- gau ✅
- gowitness ✅
- puredns ✅
- amass ✅
- nmap ✅
- masscan ✅
- jq ✅

---

## What Changed From Original Version

### Before (Issues):
- ❌ Only worked with bash
- ❌ PATH not exported during install
- ❌ Function order errors
- ❌ Missing dependencies
- ❌ Confusing error messages

### After (Fixed):
- ✅ Works with both zsh and bash
- ✅ PATH exported automatically
- ✅ All functions properly ordered
- ✅ All dependencies included
- ✅ Clear, helpful error messages
- ✅ Diagnostic tools included

---

## Next Steps After Installation

1. **Verify all tools work:**
   ```bash
   ./check_tools.sh
   ```

2. **Test with help:**
   ```bash
   ./JAWS.sh -h
   ```

3. **Quick test scan:**
   ```bash
   ./JAWS.sh -m quick scanme.nmap.org
   ```

4. **Full reconnaissance:**
   ```bash
   ./JAWS.sh example.com
   ```

---

## Support

If you still have issues after these fixes:

1. Run `./check_tools.sh` and share output
2. Check `echo $SHELL` - are you using zsh or bash?
3. Check `echo $PATH | grep go/bin` - is it in PATH?
4. Try `source ./fix_path.sh` for quick fix

All critical bugs have been resolved! 
