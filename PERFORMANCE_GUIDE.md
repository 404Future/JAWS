# JAWS Performance & Filtering Guide

## New Features Overview

JAWS now includes smart filtering and parallel processing to handle large-scale targets efficiently.

---

## 🚀 Parallel Processing

### Before vs After

**Before (Sequential):**
```
[→] Running subfinder...      (2 min)
[→] Running assetfinder...    (1 min)
[→] Running amass...          (5 min)
[→] Querying crt.sh...        (30 sec)
Total: ~8.5 minutes
```

**After (Parallel):**
```
[→] Running subfinder...
[→] Running assetfinder...
[→] Running amass...
[→] Querying crt.sh...
[→] Waiting for completion...
Total: ~5 minutes (limited by slowest tool)
```

### What Runs in Parallel

**Phase 1 - Subdomain Enumeration:**
- subfinder
- assetfinder
- amass
- crt.sh

All four tools start simultaneously and run in the background.

---

## 🎯 Smart HTTP Filtering

### The Problem

When scanning large targets like Facebook:
- 17,000+ subdomains discovered
- Many return 404, 500, or other error codes
- Hard to find actual accessible resources

### The Solution

JAWS now filters HTTP responses to focus on interesting status codes.

### Status Code Categories

#### ✅ Interesting (Filtered Results)
```
200 OK              - Working resource
201 Created         - API endpoints
301 Moved           - Redirect (often to login/main page)
302 Found           - Temporary redirect
307 Temp Redirect   - Preserves method
308 Perm Redirect   - Preserves method
401 Unauthorized    - Requires auth (potential target)
403 Forbidden       - Exists but blocked (enumeration target)
```

#### ❌ Saved but Not Prioritized
```
400 Bad Request     - Client error
404 Not Found       - Doesn't exist
500 Internal Error  - Server error
502 Bad Gateway     - Proxy error
503 Unavailable     - Service down
```

### Output Files

After HTTP probing, you get:

```bash
# All results (any status code)
facebook.com_recon/httpx_results_all.txt    # 15,234 hosts
facebook.com_recon/live_hosts_all.txt       # 15,234 URLs

# Filtered results (interesting codes only)
facebook.com_recon/httpx_results.txt        # 3,456 hosts  ✅ Focus here!
facebook.com_recon/live_hosts.txt           # 3,456 URLs   ✅ Focus here!
```

### Example Output

```bash
[*] Phase 4: HTTP Probing
  [→] Probing HTTP services with httpx...
  [→] Filtering for interesting status codes...
[✓] Total live hosts: 15,234
[✓] Interesting hosts (200/30x/40x): 3,456
  [→] Status code breakdown:
      [200]: 2,145 hosts
      [301]: 876 hosts
      [404]: 8,234 hosts
      [403]: 234 hosts
      [401]: 201 hosts
      [500]: 3,544 hosts
```

---

## ⚙️ Customization

### Changing Filtered Status Codes

Edit the configuration in `scan.lib`:

```bash
nano scan.lib

# Find this section at the top:
INTERESTING_STATUS_CODES="200|201|301|302|307|308|401|403"

# Examples:

# Only successful responses
INTERESTING_STATUS_CODES="200|201"

# Include more codes
INTERESTING_STATUS_CODES="200|201|204|301|302|307|308|401|403|405"

# Include server errors for debugging
INTERESTING_STATUS_CODES="200|201|301|302|500|502|503"
```

### Adjusting Amass Timeout

Amass can be slow. Adjust the timeout:

```bash
nano scan.lib

# Find:
AMASS_TIMEOUT=300  # 5 minutes

# Change to:
AMASS_TIMEOUT=180  # 3 minutes (faster)
AMASS_TIMEOUT=600  # 10 minutes (more thorough)
```

---

## 📊 Understanding the Results

### Scenario: Scanning Facebook

```bash
./JAWS.sh facebook.com
```

**Phase 1 Output:**
```
[*] Phase 1: Subdomain Enumeration (Passive)
  [→] Running subfinder...
  [→] Running assetfinder...
  [→] Running amass (passive, 300s timeout)...
  [→] Querying crt.sh...
  [→] Waiting for all enumeration tools to complete...
  [✓] Subfinder: 3,456 subdomains
  [✓] Assetfinder: 2,134 subdomains
  [✓] Amass: 12,429 subdomains
  [✓] crt.sh: 418 subdomains
[✓] Total unique subdomains: 17,910
```

**Phase 4 Output:**
```
[*] Phase 4: HTTP Probing
  [→] Probing HTTP services with httpx...
  [→] Filtering for interesting status codes...
[✓] Total live hosts: 15,234
[✓] Interesting hosts (200/30x/40x): 3,456
  [→] Status code breakdown:
      [200]: 2,145 hosts
      [301]: 876 hosts
      [404]: 8,234 hosts
      [403]: 234 hosts
```

**What This Means:**
- 17,910 subdomains discovered
- 15,234 have web servers
- 3,456 are **worth investigating** (200/30x/40x)
- Focus your attention on those 3,456!

### Finding Targets in Results

```bash
cd facebook.com_recon

# Check interesting hosts
cat live_hosts.txt

# Find specific patterns
grep "admin" live_hosts.txt
grep "api" live_hosts.txt
grep "dev" live_hosts.txt
grep "staging" live_hosts.txt

# Check what returned 200 OK
grep "\[200\]" httpx_results.txt

# Check what requires auth (401)
grep "\[401\]" httpx_results.txt

# Check forbidden resources (403)
grep "\[403\]" httpx_results.txt
```

---

## 🔥 Performance Tips

### For Large Targets (10,000+ subdomains)

1. **Use quick mode first:**
   ```bash
   ./JAWS.sh -m quick facebook.com
   ```

2. **Reduce amass timeout:**
   ```bash
   # Edit scan.lib
   AMASS_TIMEOUT=180  # 3 minutes instead of 5
   ```

3. **Skip screenshots on first pass:**
   ```bash
   # Use custom mode and skip phase 6
   ./JAWS.sh -m custom facebook.com
   # Select: 1 2 3 4 5 7 8 9 (skip 6)
   ```

### For Small Targets (< 100 subdomains)

Use full mode with all features:
```bash
./JAWS.sh smalltarget.com
```

### For Bug Bounty Programs

**First reconnaissance:**
```bash
# Quick scan to find scope
./JAWS.sh -m passive target.com

# Review subdomains, verify in scope
cat target.com_recon/subdomains_all.txt
```

**Deep dive:**
```bash
# Full scan on verified in-scope domains
./JAWS.sh target.com
```

---

## 📈 Expected Scan Times

### Quick Mode
- Small target (< 50 subs): 1-2 minutes
- Medium target (< 500 subs): 3-5 minutes
- Large target (< 5000 subs): 5-10 minutes

### Full Mode
- Small target: 5-10 minutes
- Medium target: 15-30 minutes
- Large target: 30-60 minutes
- Very large target (Facebook/Google): 1-2 hours

*Times vary based on network speed and target responsiveness*

---

## 🎓 Best Practices

### 1. Use Filtered Results for Manual Review
Focus on `live_hosts.txt` (filtered) not `live_hosts_all.txt`

### 2. Check Status Code Breakdown
Look for unusual distributions:
- Many 403s? Might have directory listing disabled
- Many 401s? Good auth testing targets
- Few 200s? May need specific paths/parameters

### 3. Progressive Scanning
```bash
# 1. Start with passive
./JAWS.sh -m passive target.com

# 2. Review results
cat target.com_recon/subdomains_all.txt

# 3. Full scan if promising
./JAWS.sh target.com
```

### 4. Customize for Your Needs
Adjust `INTERESTING_STATUS_CODES` based on your testing focus:
- API testing: Include 405, 415
- Auth testing: Include 401, 403
- Redirect analysis: Include all 30x codes

---

## 🔧 Troubleshooting

### httpx Shows All Hosts, No Filtering
```bash
# Check if results file exists
ls -lh target_recon/httpx_results_all.txt

# Manually filter
grep -E '\[(200|301|302|401|403)\]' target_recon/httpx_results_all.txt > filtered.txt
```

### Amass Takes Too Long
```bash
# Reduce timeout in scan.lib
AMASS_TIMEOUT=120  # 2 minutes

# Or skip amass in custom mode
./JAWS.sh -m custom target.com
# Select: 1 3 4 5 6 7 8 9 (skip 2)
```

### Want All Status Codes
```bash
# Use live_hosts_all.txt instead
cat target_recon/live_hosts_all.txt

# Or modify filter to include everything
INTERESTING_STATUS_CODES="[0-9]+"
```

---

## 📚 Summary

**Key Improvements:**
1. ✅ Parallel processing (2x faster)
2. ✅ Smart filtering (focus on relevant targets)
3. ✅ Status code statistics (understand landscape)
4. ✅ Configurable behavior (customize to needs)

**Files to Focus On:**
- `live_hosts.txt` - Filtered, interesting targets
- `httpx_results.txt` - Full details on interesting hosts
- `subdomains_all.txt` - All discovered subdomains

**Customization:**
- Edit `scan.lib` configuration section
- Adjust `INTERESTING_STATUS_CODES`
- Adjust `AMASS_TIMEOUT`
