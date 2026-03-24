#!/usr/bin/env python3
"""
Super Blocker - Hard-to-bypass website blocker for Windows.

Blocks websites by modifying the system hosts file and runs a Windows service
to enforce blocks and prevent tampering.

Usage: python super_blocker.py <command> [arguments]
"""

import sys
import os
import json
import hashlib
import hmac
import secrets
import getpass
import time
import subprocess
import ctypes
import atexit
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Windows service support (optional — needed for service features)
# ---------------------------------------------------------------------------
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVICE_NAME = "SuperBlocker"
SERVICE_DISPLAY = "Super Blocker - Website Blocker"
SERVICE_DESC = "Monitors and enforces website blocking via the hosts file."

CONFIG_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SuperBlocker"
CONFIG_FILE = CONFIG_DIR / "config.json"
SHADOW_FILE = CONFIG_DIR / ".trusted_state"
LOG_FILE = CONFIG_DIR / "events.log"
HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")

MARKER_START = "# ========== SUPER BLOCKER START - DO NOT EDIT =========="
MARKER_END = "# ========== SUPER BLOCKER END =========="
BLOCK_IP = "0.0.0.0"

PROTECTED_DOMAINS = {"localhost", "localhost.localdomain", "local"}
PROTECTED_SUFFIXES = (".local", ".internal", ".localhost", ".test", ".example")

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """Exit with error if not running as admin."""
    if not is_admin():
        print("[!] This command requires administrator privileges.")
        print("    Right-click your terminal and select 'Run as Administrator'.")
        sys.exit(1)


def log_event(message):
    """Append a timestamped event to the log file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} | {message}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "password": None,
    "domains": [],
    "enabled": True,
}


def load_config():
    """Load config from disk; return defaults if missing or corrupt."""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for key, val in DEFAULT_CONFIG.items():
                if key not in cfg:
                    cfg[key] = val
            return cfg
    except (json.JSONDecodeError, OSError):
        pass
    return dict(DEFAULT_CONFIG)


def sign_config(cfg):
    """Compute an HMAC over critical config fields using the password hash as key."""
    if not cfg.get("password"):
        return ""
    key = cfg["password"]["hash"].encode()
    payload = json.dumps(
        {"enabled": cfg["enabled"], "domains": sorted(cfg["domains"])},
        sort_keys=True,
    ).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_config_signature(cfg):
    """Return True if the config signature is valid (not tampered)."""
    if not cfg.get("password"):
        return True  # No password set yet — nothing to verify
    expected = sign_config(cfg)
    return hmac.compare_digest(cfg.get("signature", ""), expected)


def save_config(cfg):
    """Sign and persist config to disk. Also updates the shadow backup."""
    cfg["signature"] = sign_config(cfg)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    tmp.replace(CONFIG_FILE)
    # Update shadow backup whenever we write a legitimately signed config
    if cfg.get("password") and cfg["domains"]:
        _save_shadow(cfg)


def _save_shadow(cfg):
    """Persist a signed shadow copy of the trusted state.

    This survives config deletion — the service falls back to it on restart.
    """
    try:
        payload = json.dumps(
            {
                "domains": sorted(cfg["domains"]),
                "enabled": cfg["enabled"],
                "password": cfg["password"],
            },
            sort_keys=True,
        )
        sig = hmac.new(
            cfg["password"]["hash"].encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        with open(SHADOW_FILE, "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "sig": sig}, f)
    except Exception:
        pass


def _load_shadow():
    """Load and verify the shadow backup. Returns (domains, enabled) or None."""
    try:
        with open(SHADOW_FILE, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
        payload_str = wrapper["payload"]
        payload = json.loads(payload_str)
        expected = hmac.new(
            payload["password"]["hash"].encode(),
            payload_str.encode(),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected, wrapper["sig"]):
            return payload["domains"], payload["enabled"]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# ACL lockdown
# ---------------------------------------------------------------------------

_config_was_locked = False


def _lockdown_config_dir():
    """Set SYSTEM-only ACLs and hide the config directory."""
    d = str(CONFIG_DIR)
    if not CONFIG_DIR.exists():
        return
    # Remove inherited ACLs
    subprocess.run(
        ["icacls", d, "/inheritance:r", "/T", "/Q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Strip access from everyone except SYSTEM
    for principal in [
        "BUILTIN\\Administrators", "BUILTIN\\Users", "Everyone", "CREATOR OWNER",
    ]:
        subprocess.run(
            ["icacls", d, "/remove:g", principal, "/T", "/Q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    # Grant SYSTEM full control (inheritable to files + subdirs)
    subprocess.run(
        ["icacls", d, "/grant", "NT AUTHORITY\\SYSTEM:(OI)(CI)F", "/T", "/Q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Hide the directory in Explorer
    subprocess.run(
        ["attrib", "+h", "+s", d],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _unlock_config_dir():
    """Temporarily grant Administrators access to the config directory."""
    d = str(CONFIG_DIR)
    if not CONFIG_DIR.exists():
        return
    # Take ownership (admin privilege allows this even without ACL access)
    subprocess.run(
        ["takeown", "/f", d, "/r", "/d", "y"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Grant Administrators full control
    subprocess.run(
        ["icacls", d, "/grant", "BUILTIN\\Administrators:(OI)(CI)F", "/T", "/Q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Unhide so file operations work normally
    subprocess.run(
        ["attrib", "-h", "-s", d],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def ensure_config_access():
    """If config dir is ACL-locked, unlock it for this CLI session and re-lock on exit."""
    global _config_was_locked
    if _config_was_locked:
        return  # Already unlocked this session
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        probe = CONFIG_DIR / ".access_probe"
        probe.write_text("t")
        probe.unlink()
    except PermissionError:
        _unlock_config_dir()
        _config_was_locked = True
        atexit.register(_lockdown_config_dir)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def hash_password(password):
    """Hash a password with PBKDF2-SHA256 (200 000 iterations)."""
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return {"salt": salt, "hash": dk.hex()}


def verify_password(password, stored):
    """Verify a password against a stored PBKDF2 hash."""
    if not stored:
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), stored["salt"].encode(), 200_000
    )
    return secrets.compare_digest(dk.hex(), stored["hash"])


def require_password(cfg):
    """Prompt for the master password. Returns True on success."""
    if not cfg.get("password"):
        print("[!] No password set. Run 'set-password' first.")
        return False
    try:
        password = getpass.getpass("Enter password (hidden): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not verify_password(password, cfg["password"]):
        print("[!] Incorrect password.")
        log_event("FAILED PASSWORD ATTEMPT")
        return False
    return True


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

def clean_domain(raw):
    """Normalize and validate a domain string (accepts full URLs too)."""
    domain = raw.strip().lower()
    # Strip protocol
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Strip path / query / fragment
    for ch in "/", "?", "#":
        idx = domain.find(ch)
        if idx != -1:
            domain = domain[:idx]
    # Strip port
    idx = domain.find(":")
    if idx != -1:
        domain = domain[:idx]
    # Strip trailing FQDN dot
    domain = domain.rstrip(".")

    if not domain:
        raise ValueError("Empty domain")
    if domain in PROTECTED_DOMAINS:
        raise ValueError(f"Cannot block protected domain: {domain}")
    for suffix in PROTECTED_SUFFIXES:
        if domain.endswith(suffix):
            raise ValueError(f"Cannot block domain with protected suffix: {domain}")
    if "." not in domain:
        raise ValueError(f"Invalid domain (missing TLD): {domain}")
    # Reject IP addresses
    parts = domain.split(".")
    if all(p.isdigit() for p in parts):
        raise ValueError(f"Cannot block IP addresses — use domain names: {domain}")
    if not all(c.isalnum() or c in ".-_" for c in domain):
        raise ValueError(f"Invalid characters in domain: {domain}")
    return domain


# ---------------------------------------------------------------------------
# Hosts-file management
# ---------------------------------------------------------------------------

def build_block_section(domains):
    """Build the text block to inject into the hosts file."""
    if not domains:
        return ""
    lines = [MARKER_START]
    for domain in sorted(set(domains)):
        lines.append(f"{BLOCK_IP} {domain}")
        if not domain.startswith("www."):
            lines.append(f"{BLOCK_IP} www.{domain}")
    lines.append(MARKER_END)
    return "\n".join(lines)


def read_hosts():
    """Return the current content of the hosts file."""
    try:
        return HOSTS_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except PermissionError:
        return ""


def strip_block_section(content):
    """Remove everything between (and including) the Super Blocker markers."""
    start = content.find(MARKER_START)
    end = content.find(MARKER_END)
    if start == -1 or end == -1:
        return content
    before = content[:start].rstrip("\n\r ")
    after = content[end + len(MARKER_END):]
    return before + after


def apply_blocks(domains):
    """Write blocked domains into the hosts file."""
    content = read_hosts()
    cleaned = strip_block_section(content).rstrip("\n\r ")
    section = build_block_section(domains)
    new_content = cleaned + "\n\n" + section + "\n" if section else cleaned + "\n"

    for attempt in range(3):
        try:
            HOSTS_FILE.write_text(new_content, encoding="utf-8")
            flush_dns()
            return True
        except PermissionError:
            if attempt < 2:
                time.sleep(0.5)
    return False


def remove_blocks():
    """Strip Super Blocker entries from the hosts file."""
    content = read_hosts()
    cleaned = strip_block_section(content).rstrip("\n\r ") + "\n"
    for attempt in range(3):
        try:
            HOSTS_FILE.write_text(cleaned, encoding="utf-8")
            flush_dns()
            return True
        except PermissionError:
            if attempt < 2:
                time.sleep(0.5)
    return False


def blocks_in_place(domains):
    """Return True if every expected block entry is present in the hosts file."""
    content = read_hosts()
    if MARKER_START not in content or MARKER_END not in content:
        return False
    for domain in domains:
        if f"{BLOCK_IP} {domain}" not in content:
            return False
        if not domain.startswith("www.") and f"{BLOCK_IP} www.{domain}" not in content:
            return False
    return True


def flush_dns():
    """Flush the Windows DNS resolver cache."""
    try:
        subprocess.run(
            ["ipconfig", "/flushdns"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Windows Service
# ---------------------------------------------------------------------------

if HAS_WIN32:

    class SuperBlockerService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESC

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            # Re-apply blocks one last time so they persist while stopped
            try:
                cfg = load_config()
                if verify_config_signature(cfg) and cfg["enabled"] and cfg["domains"]:
                    apply_blocks(cfg["domains"])
                else:
                    # Config might be tampered — use shadow backup
                    shadow = _load_shadow()
                    if shadow:
                        domains, enabled = shadow
                        if enabled and domains:
                            apply_blocks(domains)
            except Exception:
                pass
            log_event("Service stopped")
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            log_event("Service started")
            try:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
            except Exception:
                pass
            self._run_loop()

        def _run_loop(self):
            """Main enforcement loop — checks every 5 seconds."""
            # Cache the last verified-good config so tampering can't disable us
            trusted_domains = []
            trusted_enabled = True

            # Try main config first, fall back to shadow backup
            cfg = load_config()
            if verify_config_signature(cfg) and cfg.get("password"):
                trusted_domains = list(cfg["domains"])
                trusted_enabled = cfg["enabled"]
            else:
                shadow = _load_shadow()
                if shadow:
                    trusted_domains, trusted_enabled = shadow
                    log_event("Config missing/invalid — restored from shadow backup")
                else:
                    log_event("No valid config or shadow backup found")

            while True:
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                try:
                    cfg = load_config()
                    if verify_config_signature(cfg) and cfg.get("password"):
                        # Config is authentic — accept the update
                        trusted_domains = list(cfg["domains"])
                        trusted_enabled = cfg["enabled"]
                    elif not cfg.get("password") and trusted_domains:
                        # Config was deleted/reset — ignore and keep trusted state
                        log_event("Config deleted — ignoring, using cached/shadow state")
                    elif cfg.get("password"):
                        log_event("Config tampering detected — ignoring, using cached config")

                    if trusted_enabled and trusted_domains:
                        if not blocks_in_place(trusted_domains):
                            log_event("Hosts file tampering detected — re-applying blocks")
                            apply_blocks(trusted_domains)
                except Exception as exc:
                    log_event(f"Enforcement error: {exc}")
                    # On error, still try to enforce with last trusted config
                    if trusted_enabled and trusted_domains:
                        try:
                            apply_blocks(trusted_domains)
                        except Exception:
                            pass


# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

def require_win32():
    if not HAS_WIN32:
        print("[!] pywin32 is required for service features.")
        print("    Install: pip install pywin32")
        sys.exit(1)


def _service_cmd(*args):
    """Invoke win32serviceutil.HandleCommandLine with custom argv."""
    require_win32()
    saved = sys.argv[:]
    sys.argv = [saved[0]] + list(args)
    try:
        win32serviceutil.HandleCommandLine(SuperBlockerService)
    except SystemExit:
        pass
    except Exception as exc:
        print(f"[!] Service command error: {exc}")
    finally:
        sys.argv = saved


def is_service_installed():
    if not HAS_WIN32:
        return False
    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return True
    except Exception:
        return False


def is_service_running():
    if not HAS_WIN32:
        return False
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_set_password():
    cfg = load_config()
    if cfg.get("password"):
        print("Current password required to change it.")
        if not require_password(cfg):
            return

    print("(typing is hidden — characters won't appear)")
    pw1 = getpass.getpass("New password: ")
    if not pw1:
        print("[!] Password cannot be empty.")
        return
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("[!] Passwords do not match.")
        return

    cfg["password"] = hash_password(pw1)
    save_config(cfg)
    log_event("Password set/changed")
    print("[+] Password set successfully.")
    print()
    print("[!] WARNING: If you forget this password, the ONLY recovery is to")
    print("    boot into Safe Mode and manually edit the hosts file at:")
    print(f"    {HOSTS_FILE}")


def cmd_block():
    require_admin()
    if len(sys.argv) < 3:
        print("Usage: super_blocker block <domain> [domain2] ...")
        return

    cfg = load_config()
    added = []

    for raw in sys.argv[2:]:
        try:
            domain = clean_domain(raw)
        except ValueError as exc:
            print(f"[!] Skipping '{raw}': {exc}")
            continue
        if domain in cfg["domains"]:
            print(f"[-] Already blocked: {domain}")
        else:
            cfg["domains"].append(domain)
            added.append(domain)
            www = "" if domain.startswith("www.") else f" (+ www.{domain})"
            print(f"[+] Blocked: {domain}{www}")

    if added:
        save_config(cfg)
        if cfg["enabled"]:
            if apply_blocks(cfg["domains"]):
                print(f"\n[i] {len(cfg['domains'])} domain(s) now blocked.")
            else:
                print("\n[!] Failed to write hosts file. Are you running as admin?")
        log_event(f"Blocked: {', '.join(added)}")

        if is_service_running():
            print("[i] Service is running — blocks are enforced.")
        elif is_service_installed():
            print("[!] Service is installed but not running. Run: super_blocker start")
        else:
            print("[!] Service not installed — blocks applied but NOT tamper-protected.")
            print("    Run: super_blocker install")


def cmd_unblock():
    require_admin()
    if len(sys.argv) < 3:
        print("Usage: super_blocker unblock <domain>")
        return

    cfg = load_config()
    if not require_password(cfg):
        return

    removed = []
    for raw in sys.argv[2:]:
        try:
            domain = clean_domain(raw)
        except ValueError as exc:
            print(f"[!] Skipping '{raw}': {exc}")
            continue
        if domain in cfg["domains"]:
            cfg["domains"].remove(domain)
            removed.append(domain)
            print(f"[+] Unblocked: {domain}")
        else:
            print(f"[-] Not in blocklist: {domain}")

    if removed:
        save_config(cfg)
        apply_blocks(cfg["domains"])
        log_event(f"Unblocked: {', '.join(removed)}")
        print(f"\n[i] {len(cfg['domains'])} domain(s) still blocked.")


def cmd_list():
    cfg = load_config()
    if not cfg["domains"]:
        print("No domains blocked.")
        return

    print(f"Blocked domains ({len(cfg['domains'])}):")
    for domain in sorted(cfg["domains"]):
        www = "" if domain.startswith("www.") else f" (+ www.{domain})"
        print(f"  - {domain}{www}")

    print(f"\nBlocking: {'ENABLED' if cfg['enabled'] else 'DISABLED'}")
    if cfg["domains"]:
        print(f"Hosts file: {'BLOCKS IN PLACE' if blocks_in_place(cfg['domains']) else 'BLOCKS MISSING'}")


def cmd_status():
    cfg = load_config()

    print("=== Super Blocker Status ===\n")
    print(f"  Blocking:    {'ENABLED' if cfg['enabled'] else 'DISABLED'}")
    print(f"  Domains:     {len(cfg['domains'])} blocked")
    print(f"  Password:    {'SET' if cfg.get('password') else 'NOT SET'}")

    if cfg["domains"]:
        ok = blocks_in_place(cfg["domains"])
        print(f"  Hosts file:  {'ENFORCED' if ok else 'NOT ENFORCED'}")
    else:
        print("  Hosts file:  NO BLOCKS")

    if HAS_WIN32:
        if is_service_installed():
            state = "RUNNING" if is_service_running() else "STOPPED"
        else:
            state = "NOT INSTALLED"
        print(f"  Service:     {state}")
    else:
        print("  Service:     UNAVAILABLE (pywin32 not installed)")

    print(f"\n  Config:      {CONFIG_FILE}")
    print(f"  Log:         {LOG_FILE}")
    print()


def cmd_install():
    require_win32()
    require_admin()
    cfg = load_config()

    if not cfg.get("password"):
        print("[!] Set a password first:")
        print("    python super_blocker.py set-password")
        return
    if not cfg["domains"]:
        print("[!] No domains blocked yet. Add some first:")
        print("    python super_blocker.py block <domain>")
        return
    if is_service_installed():
        print("[!] Service is already installed.")
        return

    _service_cmd("--startup", "auto", "install")

    # Set recovery actions: restart on every failure
    subprocess.run(
        [
            "sc", "failure", SERVICE_NAME,
            "reset=", "0",
            "actions=", "restart/3000/restart/5000/restart/10000",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print("[+] Recovery set: auto-restart on failure (3s / 5s / 10s).")
    log_event("Service installed")

    # Auto-start
    print("[i] Starting service...")
    _service_cmd("start")
    log_event("Service started after install")


def cmd_remove():
    require_win32()
    require_admin()
    cfg = load_config()
    if not require_password(cfg):
        return

    # Stop first (ignore errors if already stopped)
    try:
        _service_cmd("stop")
    except Exception:
        pass
    time.sleep(2)

    _service_cmd("remove")

    # Clean up hosts file
    remove_blocks()
    log_event("Service removed")
    print("[+] Blocks removed from hosts file.")


def cmd_start():
    require_win32()
    require_admin()
    _service_cmd("start")
    # Re-enable recovery in case it was previously disabled
    subprocess.run(
        [
            "sc", "failure", SERVICE_NAME,
            "reset=", "0",
            "actions=", "restart/3000/restart/5000/restart/10000",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    log_event("Service started via CLI")


def cmd_stop():
    """Stop the service. It will auto-restart via recovery actions."""
    require_win32()
    require_admin()
    cfg = load_config()
    if not require_password(cfg):
        return
    _service_cmd("stop")
    log_event("Service stopped via CLI (authenticated)")
    print("[!] Note: The service will auto-restart in a few seconds (by design).")
    print("    To fully disable blocking, use: super_blocker disable")


def cmd_enable():
    require_admin()
    cfg = load_config()
    cfg["enabled"] = True
    save_config(cfg)
    if cfg["domains"]:
        apply_blocks(cfg["domains"])
    log_event("Blocking enabled")
    print("[+] Blocking enabled.")


def cmd_disable():
    require_admin()
    cfg = load_config()
    if not require_password(cfg):
        return
    cfg["enabled"] = False
    save_config(cfg)
    remove_blocks()
    log_event("Blocking disabled (authenticated)")
    print("[+] Blocking disabled. Blocks removed from hosts file.")
    print("[i] The service (if running) will NOT re-apply until you 'enable' again.")


def cmd_lockdown():
    """Apply ACL lockdown to the config directory."""
    require_admin()
    if not CONFIG_DIR.exists():
        print("[!] Config directory does not exist yet. Run 'set-password' or 'block' first.")
        return
    _lockdown_config_dir()
    log_event("ACL lockdown applied to config directory")
    print("[+] Config directory locked down to SYSTEM-only access.")
    print(f"    {CONFIG_DIR}")
    print("[i] The directory is now hidden and only the SYSTEM account can access it.")
    print("[i] CLI commands will auto-unlock/re-lock as needed (transparent to you).")


# ---------------------------------------------------------------------------
# Usage & main
# ---------------------------------------------------------------------------

USAGE = """\
Super Blocker - Website Blocker for Windows
=============================================

Usage: python super_blocker.py <command> [arguments]

  set-password              Set or change the master password
  block <domain> [...]      Block one or more domains
  unblock <domain> [...]    Unblock domains             (PASSWORD REQUIRED)
  list                      List all blocked domains
  status                    Show blocker status

  install                   Install Windows service      (auto-start + recovery)
  remove                    Remove Windows service       (PASSWORD REQUIRED)
  start                     Start the service
  stop                      Stop the service             (PASSWORD REQUIRED)

  enable                    Enable blocking
  disable                   Disable blocking             (PASSWORD REQUIRED)
  lockdown                  Lock config directory (SYSTEM-only ACL)

Examples:
  python super_blocker.py set-password
  python super_blocker.py block reddit.com youtube.com facebook.com
  python super_blocker.py block https://twitter.com/whatever
  python super_blocker.py install
  python super_blocker.py list

Recovery:
  If you forget your password, boot into Safe Mode, then manually
  edit the hosts file:  C:\\Windows\\System32\\drivers\\etc\\hosts
  and delete the lines between the SUPER BLOCKER markers.
"""

COMMANDS = {
    "set-password": cmd_set_password,
    "setpassword":  cmd_set_password,
    "password":     cmd_set_password,
    "block":        cmd_block,
    "add":          cmd_block,
    "unblock":      cmd_unblock,
    "list":         cmd_list,
    "ls":           cmd_list,
    "status":       cmd_status,
    "install":      cmd_install,
    "remove":       cmd_remove,
    "uninstall":    cmd_remove,
    "start":        cmd_start,
    "stop":         cmd_stop,
    "enable":       cmd_enable,
    "disable":      cmd_disable,
    "lockdown":     cmd_lockdown,
    "help":         lambda: print(USAGE),
}


def main():
    if len(sys.argv) < 2:
        print(USAGE)
        return

    # If config dir is ACL-locked, transparently unlock for this session
    ensure_config_access()

    cmd = sys.argv[1].lower().lstrip("-")
    handler = COMMANDS.get(cmd)
    if handler:
        handler()
    else:
        print(f"[!] Unknown command: {sys.argv[1]}")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    # When started by the Windows Service Control Manager, there are no CLI args.
    # In that case, enter service mode. Otherwise, run the CLI.
    if len(sys.argv) == 1 and HAS_WIN32:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SuperBlockerService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception:
            # Not started by SCM — show usage
            print(USAGE)
    else:
        main()
