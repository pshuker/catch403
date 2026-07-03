#!/usr/bin/python3
"""
Hash Identifier and Cracker — inspired by hashID and Name-That-Hash.

Identifies 30+ hash types by pattern matching, then optionally cracks
them with a wordlist using Python's hashlib.

Usage:
  ../.venv/bin/python3 modules/hash_id.py -h 5d41402abc4b2a76b9719d911017c592
  ../.venv/bin/python3 modules/hash_id.py -h <hash> -w /usr/share/wordlists/rockyou.txt
  ../.venv/bin/python3 modules/hash_id.py -f hashes.txt --crack -w rockyou.txt
"""
import argparse
import hashlib
import re
import sys

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

# (name, regex, hashlib_name_or_None, description)
HASH_PATTERNS: list[tuple[str, str, str | None, str]] = [
    ("CRC32",           r"^[a-fA-F0-9]{8}$",      None,          "Checksum, not a real hash"),
    ("MD5",             r"^[a-fA-F0-9]{32}$",      "md5",         "128-bit, extremely common"),
    ("NTLM",            r"^[a-fA-F0-9]{32}$",      "md4",         "Windows authentication"),
    ("MD4",             r"^[a-fA-F0-9]{32}$",      None,          "Predecessor to MD5"),
    ("LM",              r"^[a-fA-F0-9]{32}$",      None,          "Old Windows LAN Manager"),
    ("RIPEMD-128",      r"^[a-fA-F0-9]{32}$",      None,          "128-bit RIPE MD"),
    ("MySQL 3.x",       r"^[a-fA-F0-9]{16}$",      None,          "Old MySQL password hash"),
    ("SHA-1",           r"^[a-fA-F0-9]{40}$",      "sha1",        "160-bit, widely used"),
    ("RIPEMD-160",      r"^[a-fA-F0-9]{40}$",      None,          "160-bit RIPE MD"),
    ("MySQL 4.1+",      r"^\*[a-fA-F0-9]{40}$",    None,          "MySQL password() function"),
    ("Tiger-192",       r"^[a-fA-F0-9]{48}$",      None,          "192-bit Tiger hash"),
    ("SHA-224",         r"^[a-fA-F0-9]{56}$",      "sha224",      "224-bit SHA-2"),
    ("SHA3-224",        r"^[a-fA-F0-9]{56}$",      "sha3_224",    "224-bit SHA-3"),
    ("SHA-256",         r"^[a-fA-F0-9]{64}$",      "sha256",      "256-bit SHA-2, very common"),
    ("SHA3-256",        r"^[a-fA-F0-9]{64}$",      "sha3_256",    "256-bit SHA-3"),
    ("BLAKE2s",         r"^[a-fA-F0-9]{64}$",      "blake2s",     "Fast 256-bit hash"),
    ("SHA-384",         r"^[a-fA-F0-9]{96}$",      "sha384",      "384-bit SHA-2"),
    ("SHA3-384",        r"^[a-fA-F0-9]{96}$",      "sha3_384",    "384-bit SHA-3"),
    ("SHA-512",         r"^[a-fA-F0-9]{128}$",     "sha512",      "512-bit SHA-2"),
    ("SHA3-512",        r"^[a-fA-F0-9]{128}$",     "sha3_512",    "512-bit SHA-3"),
    ("Whirlpool",       r"^[a-fA-F0-9]{128}$",     None,          "512-bit Whirlpool"),
    ("BLAKE2b",         r"^[a-fA-F0-9]{128}$",     "blake2b",     "Fast 512-bit hash"),
    ("bcrypt",          r"^\$2[abxy]\$\d{2}\$.{53}$", None,       "Adaptive key-derivation"),
    ("MD5-crypt",       r"^\$1\$.{1,8}\$.{22}$",   None,          "Unix MD5 crypt"),
    ("SHA-256-crypt",   r"^\$5\$[^\$]*\$.{43}$",   None,          "Unix SHA-256 crypt"),
    ("SHA-512-crypt",   r"^\$6\$[^\$]*\$.{86}$",   None,          "Unix SHA-512 crypt"),
    ("Argon2i",         r"^\$argon2i\$",            None,          "Argon2 (PHC winner)"),
    ("Argon2id",        r"^\$argon2id\$",           None,          "Argon2id hybrid"),
    ("scrypt",          r"^\$scrypt\$",             None,          "Memory-hard KDF"),
    ("Django-SHA1",     r"^sha1\$[a-zA-Z0-9]+\$[a-fA-F0-9]{40}$", None, "Django 1.x password"),
    ("Django-PBKDF2",   r"^pbkdf2_sha256\$\d+\$",  None,          "Django PBKDF2 password"),
    ("JWT",             r"^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*$", None, "JSON Web Token"),
    ("Base64",          r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$", None, "Base64 encoded data"),
]


def identify(hash_str: str) -> list[dict]:
    """Return list of possible hash types for the input string."""
    h = hash_str.strip()
    results = []
    seen = set()
    for name, pattern, hashlib_name, desc in HASH_PATTERNS:
        if re.match(pattern, h):
            key = (name, hashlib_name)
            if key not in seen:
                seen.add(key)
                results.append({
                    "name": name,
                    "description": desc,
                    "crackable": hashlib_name is not None,
                    "hashlib": hashlib_name,
                })
    return results


def crack(hash_str: str, wordlist_path: str, hash_types: list[str] | None = None) -> dict | None:
    """
    Try to crack a hash. Returns {"hash": ..., "plain": ..., "type": ...} or None.
    hash_types: list of hashlib names to try. Auto-detected if None.
    """
    h = hash_str.strip().lower()

    if hash_types is None:
        types = [r["hashlib"] for r in identify(h) if r["crackable"]]
    else:
        types = hash_types

    if not types:
        return None

    try:
        with open(wordlist_path, "r", errors="replace") as f:
            for line in f:
                word = line.rstrip("\n\r")
                for htype in types:
                    try:
                        candidate = hashlib.new(htype, word.encode()).hexdigest()
                        if candidate == h:
                            return {"hash": h, "plain": word, "type": htype}
                    except Exception:
                        continue
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    return None


def main():
    parser = argparse.ArgumentParser(description="Identify and optionally crack hashes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", dest="hash",  help="Single hash string")
    group.add_argument("-f", dest="file",  help="File with one hash per line")
    parser.add_argument("-w", dest="wordlist", help="Wordlist for cracking")
    parser.add_argument("--type", dest="htype",  help="Force hashlib type (e.g. sha256)")
    args = parser.parse_args()

    hashes = []
    if args.hash:
        hashes = [args.hash.strip()]
    else:
        with open(args.file) as f:
            hashes = [l.strip() for l in f if l.strip()]

    for h in hashes:
        print(f"\n{bold}{h}{end}")
        types = identify(h)
        if not types:
            print(f"  {bad} No matching hash type found")
        else:
            print(f"  {info} Possible types:")
            for t in types:
                crack_tag = f"  {green}[crackable]{end}" if t["crackable"] else ""
                print(f"    {tab}{green}{t['name']}{end} — {t['description']}{crack_tag}")

        if args.wordlist:
            print(f"  {run} Cracking…", end="\r", flush=True)
            forced = [args.htype] if args.htype else None
            result = crack(h, args.wordlist, forced)
            if result:
                print(f"  {good} {green}{bold}CRACKED{end}  {result['plain']}  (via {result['type']})")
            else:
                print(f"  {bad} Not found in wordlist                ")


if __name__ == "__main__":
    main()
