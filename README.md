# Super Blocker

A hard-to-bypass website blocker for Windows. Built for people who want to stop themselves from wasting time on distracting websites.

It works by modifying the Windows **hosts file** to redirect blocked domains to `0.0.0.0`, and runs a **Windows service** that monitors the hosts file every 5 seconds — if someone removes the blocks, they get re-applied automatically.

## How it works

1. Blocked domains are written to `C:\Windows\System32\drivers\etc\hosts`
2. A background Windows service checks every 5 seconds that the blocks are still in place
3. If the hosts file is tampered with, the service re-applies the blocks immediately
4. Unblocking, disabling, stopping, or removing the service all require a password
5. The service auto-starts on boot and auto-restarts if killed (3s / 5s / 10s delays)

**Config and logs** are stored in `C:\ProgramData\SuperBlocker\`.

## Requirements

- Windows 10/11
- Python 3.8+
- [pywin32](https://pypi.org/project/pywin32/) (`pip install pywin32`)

## Setup

All commands must be run from an **Administrator** terminal.

```bash
# 1. Set a master password (typing is hidden — characters won't appear)
python super_blocker.py set-password

# 2. Block distracting sites
python super_blocker.py block reddit.com youtube.com facebook.com instagram.com tiktok.com twitter.com

# 3. Install and start the background service
python super_blocker.py install
```

Done. Close the terminal. The service runs independently.

## Commands

| Command | What it does | Password? |
|---|---|---|
| `set-password` | Set or change the master password | Only if changing |
| `block <domain> [...]` | Block one or more domains | No |
| `unblock <domain> [...]` | Unblock domains | **Yes** |
| `list` | List all blocked domains | No |
| `status` | Show blocker status | No |
| `install` | Install as a Windows service | No |
| `remove` | Remove the Windows service | **Yes** |
| `start` | Start the service | No |
| `stop` | Stop the service | **Yes** |
| `enable` | Enable blocking | No |
| `disable` | Disable all blocking | **Yes** |

You can pass full URLs — `https://reddit.com/r/whatever` gets cleaned to `reddit.com` automatically. Each blocked domain also blocks its `www.` variant.

## Tamper protection

- The Windows service runs in the background and **re-applies blocks within 5 seconds** if the hosts file is edited manually
- If the service process is killed, Windows **automatically restarts it** (recovery actions: 3s, 5s, 10s)
- The service **starts automatically on boot** — survives reboots
- All destructive actions (unblock, disable, stop, remove) require the master password
- Failed password attempts are logged in `C:\ProgramData\SuperBlocker\events.log`

## Risks and warnings

### You can lock yourself out

If you set a password you don't remember, you **cannot** unblock sites, disable blocking, or remove the service through normal means. This is by design.

**Emergency recovery** (requires physical access):

1. Boot into **Safe Mode** (services don't run in Safe Mode)
2. Edit `C:\Windows\System32\drivers\etc\hosts` — delete everything between the `SUPER BLOCKER START` and `SUPER BLOCKER END` markers
3. Delete `C:\ProgramData\SuperBlocker\config.json` to reset the password
4. Reboot normally

### Hosts file modification

This tool modifies your system's hosts file. It only touches lines between its own clearly marked section (`SUPER BLOCKER START` / `SUPER BLOCKER END`). Existing entries are never modified. However:

- If another program also manages the hosts file, there could be conflicts
- Antivirus software may flag hosts file modifications as suspicious — you may need to whitelist the script

### DNS and browser caches

After blocking a domain, `ipconfig /flushdns` is run automatically. However, your browser may have its own DNS cache. If a blocked site still loads briefly after blocking:

- Restart the browser
- Or clear browser DNS cache (Chrome: `chrome://net-internals/#dns`)

### What this does NOT block

- VPN or proxy traffic — if you route traffic through a VPN, hosts file blocks are bypassed
- Mobile apps on other devices — this only affects the PC it's installed on
- Subdomains not explicitly blocked — blocking `reddit.com` blocks `reddit.com` and `www.reddit.com`, but not `old.reddit.com` (add it separately)

### Service dependency on Python

The Windows service depends on your Python installation (`python.exe` path is stored at install time). If you move, uninstall, or change your Python environment, the service will break. Reinstall with `python super_blocker.py install` if that happens.

## How blocking works (technical)

The script adds entries to the hosts file in this format:

```
# ========== SUPER BLOCKER START - DO NOT EDIT ==========
0.0.0.0 reddit.com
0.0.0.0 www.reddit.com
0.0.0.0 youtube.com
0.0.0.0 www.youtube.com
# ========== SUPER BLOCKER END ==========
```

`0.0.0.0` causes instant connection failure (faster than `127.0.0.1` which attempts a loopback connection). The operating system checks the hosts file before making any DNS request, so this blocks the domain in all browsers and applications system-wide.

## License

MIT
