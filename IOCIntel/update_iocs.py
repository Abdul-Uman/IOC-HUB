#!/usr/bin/env python3

import os
import sys
import time
import requests
import datetime

# ---------- CONFIG ----------
OTX_API_KEY = os.getenv("OTX_API_KEY")
if not OTX_API_KEY:
    print("ERROR: OTX_API_KEY not set in environment", file=sys.stderr)
    sys.exit(2)

IOC_DIR = "IOCIntel"
STATE_DIR = ".state"
STATE_FILE = os.path.join(STATE_DIR, "otx_last_success.txt")
OTX_BASE = "https://otx.alienvault.com/api/v1"
PULSES_SUBSCRIBED = OTX_BASE + "/pulses/subscribed"

# Map OTX indicator types to files in your repo
TYPE_TO_FILE = {
    "IPv4": "ip_addresses.txt",
    "IPv6": "ip_addresses.txt",
    "domain": "domains.txt",
    "hostname": "hostnames.txt",
    "URL": "urls.txt",
    "URI": "urls.txt",
    "FileHash-MD5": "hashes.txt",
    "FileHash-SHA1": "hashes.txt",
    "FileHash-SHA256": "hashes.txt",
    "CVE": "cves.txt",
    "YARA": "commands.txt",
    "Snort": "commands.txt",
    "Suricata": "commands.txt",
    "Certificate_Serial": "signers.txt",
    # fallback type:
    "DEFAULT": "commands.txt"
}

# ---------- Helpers ----------
def ensure_paths():
    os.makedirs(IOC_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

def read_lines_set(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def write_lines(path, items):
    items_sorted = sorted(items)
    with open(path, "w", encoding="utf-8") as f:
        if items_sorted:
            f.write("\n".join(items_sorted) + "\n")
        else:
            f.write("")

def normalize(ind_type, val):
    if not val:
        return None
    v = val.strip()
    # undo common obfuscation: hxxp/hxxps and bracketed dots
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    v = v.replace("[.]", ".").replace("(.)", ".")
    # lower-case domains/hashes
    if ind_type in ("domain", "hostname"):
        return v.lower()
    if ind_type.startswith("FileHash"):
        return v.lower()
    return v

def get_last_ts(default_days=7):
    if os.path.exists(STATE_FILE):
        try:
            s = open(STATE_FILE, "r", encoding="utf-8").read().strip()
            if s:
                return s
        except:
            pass
    ts = (datetime.datetime.utcnow() - datetime.timedelta(days=default_days)).replace(microsecond=0).isoformat() + "Z"
    return ts

def write_last_ts(ts):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(ts + "\n")

# ---------- Main ----------
def main():
    ensure_paths()
    headers = {"X-OTX-API-KEY": OTX_API_KEY, "User-Agent": "otx-github-sync/1.0"}
    last_ts = get_last_ts()
    print("[+] Last run timestamp:", last_ts)

    # prepare file path map (absolute within IOC_DIR)
    file_map = {}
    for t, fname in TYPE_TO_FILE.items():
        file_map[t] = os.path.join(IOC_DIR, fname)
    file_map["DEFAULT"] = os.path.join(IOC_DIR, TYPE_TO_FILE["DEFAULT"])

    # load existing file contents
    existing = {}
    for path in set(file_map.values()):
        existing[path] = read_lines_set(path)

    # collect new indicators per file
    new_by_file = {path: set() for path in existing.keys()}

    # Page through pulses/subscribed
    page = 1
    backoff = 1
    total_indicators = 0

    while True:
        params = {"page": page, "limit": 50, "modified_since": last_ts}
        try:
            r = requests.get(PULSES_SUBSCRIBED, headers=headers, params=params, timeout=30)
        except Exception as e:
            print("ERROR fetching OTX:", e, file=sys.stderr)
            sys.exit(3)

        if r.status_code == 429:
            print("[!] Rate limited by OTX, backing off", file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
            continue

        if r.status_code != 200:
            print("ERROR response", r.status_code, r.text[:500], file=sys.stderr)
            sys.exit(4)

        data = r.json()
        results = data.get("results", [])
        if not results:
            print("[+] No more pulses on page", page)
            break

        print(f"[+] Processing page {page} ({len(results)} pulses)")
        for pulse in results:
            for ind in pulse.get("indicators", []):
                total_indicators += 1
                itype_raw = (ind.get("type") or "").strip()
                ival_raw = ind.get("indicator") or ""

                key = itype_raw if itype_raw else "DEFAULT"
                lk = key.lower()
                if lk == "ipv4":
                    key = "IPv4"
                elif lk == "ipv6":
                    key = "IPv6"
                elif lk in ("domain", "hostname"):
                    key = "domain"
                elif lk in ("url", "uri", "uri-path"):
                    key = "URL"
                elif "filehash" in lk or "sha" in lk or "md5" in lk:
                    if "sha256" in lk:
                        key = "FileHash-SHA256"
                    elif "sha1" in lk:
                        key = "FileHash-SHA1"
                    elif "md5" in lk:
                        key = "FileHash-MD5"
                    else:
                        key = "FileHash-SHA256"

                target_file = file_map.get(key, file_map["DEFAULT"])
                normalized = normalize(key, ival_raw)
                if normalized:
                    new_by_file[target_file].add(normalized)

        page += 1
        if page > 2000:
            print("Too many pages, breaking", file=sys.stderr)
            break

    print(f"[+] Collected {total_indicators} indicators from OTX")

    # merge and write
    total_added = 0
    for path, newset in new_by_file.items():
        if not newset:
            continue
        before = len(existing.get(path, set()))
        merged = existing.get(path, set()) | newset
        if len(merged) > before:
            write_lines(path, merged)
            added = len(merged) - before
            total_added += added
            print(f"[+] Updated {path}: +{added} entries (now {len(merged)})")
        else:
            print(f"[+] No new entries for {path}")

    now_iso = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    write_last_ts(now_iso)
    print("[+] Finished. New last run timestamp:", now_iso, " -- total added:", total_added)

if __name__ == "__main__":
    main()

