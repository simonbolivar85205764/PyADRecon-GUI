# PyADRecon GUI

A modern Python/Tkinter graphical interface for
[PyADRecon](https://github.com/l4rm4nd/PyADRecon) — a Python3 Active Directory
reconnaissance and audit tool.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![UI](https://img.shields.io/badge/UI-Tkinter%20%28dark%20theme%29-informational)

---

## Screenshot

> Dark theme with indigo accent, resizable log pane, and colour-coded output.

```
┌──────────────────────────────────────────────────────────────────┐
│ ⬡ PyADRecon GUI  v2.0.0                          ● Idle          │
├──────────────────────────────────────────────────────────────────┤  ← 2 px accent line
│  Connection │ Authentication │ Options │ Modules │ Offline Excel  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │  TARGET                                                      │ │
│ │  Domain Controller  [ 192.168.1.1                          ] │ │
│ │  LDAP Port          [ 389   ]                               │ │
│ │  Force SSL/LDAPS    ☐                                       │ │
│ │  ──────────────────────────────────────────────────────     │ │
│ │  OUTPUT                                                      │ │
│ │  Output Directory   [ /tmp/adrecon          ] [ Browse… ]   │ │
│ └──────────────────────────────────────────────────────────────┘ │
│  [ ▶ Run PyADRecon ]  [ ■ Stop ]    cmd: pyadrecon -dc 192…      │
├──────────────── ⠿ drag sash to resize ──────────────────── Clear │
│ $ pyadrecon -dc 192.168.1.1 -u admin -d DOMAIN.LOCAL             │
│                                                                   │
│ [INFO]  Connecting to LDAP…                                       │
│ [OK]    Collected 847 users                                       │
│ [WARN]  Channel binding detected — switching to Kerberos          │
│ ✅  Finished successfully.                                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## What's new in v2.0.0

| Change | Detail |
|---|---|
| **Resizable log pane** | Vertical `PanedWindow` sash — drag to give the log more or less space |
| **Horizontal scrollbar** | Log also scrolls horizontally when word-wrap is off |
| **Word-wrap toggle** | Check/uncheck "Wrap" in the log header without restarting |
| **Dark theme throughout** | Every widget (entries, buttons, checkboxes, scrollbars) uses the unified dark palette |
| **Custom `DE` / `DB` widgets** | `DarkEntry` and `DarkButton` with hover states replace vanilla ttk widgets |
| **Section dividers in Modules tab** | Categorised module groups with dimmed headers |
| **Smarter log colouring** | Separate `warn` (amber) tag alongside `err`, `ok`, `info`, `dim` |
| **Status indicator** | Green dot + "Running…" label in the header while a scan is active |
| **`sashwidth=7` / drag hint** | Wider, easier-to-grab sash with "⠿ drag sash to resize" label |

---

## Requirements

- **Python 3.10+** (uses `X | Y` union type hints)
- **`tkinter`** — included in the standard library on most platforms
  - Ubuntu/Debian: `sudo apt install python3-tk`
  - macOS Homebrew: `brew install python-tk`
  - Windows: bundled with the Python installer
- **PyADRecon** installed and accessible on `PATH`:
  ```bash
  pipx install pyadrecon
  # or
  pip install pyadrecon
  ```

---

## Quick start

```bash
# No extra dependencies — runs with the Python standard library only
python pyadrecon_gui.py
```

The GUI auto-discovers `pyadrecon` on your `PATH` and shows an error dialog
if it cannot be found.

---

## Tab guide

### Connection

| Field | CLI flag | Default |
|---|---|---|
| Domain Controller | `-dc` | — |
| LDAP Port | `--port` | `389` |
| Force SSL/LDAPS | `--ssl` | off |
| Output Directory | `-o` | auto timestamp |

Enabling the **Force SSL** checkbox automatically switches the port to `636`.

> PyADRecon always tries LDAPS/636 first; port 389 is used as a fallback
> only when `--ssl` is not set.

### Authentication

| Field | CLI flag | Notes |
|---|---|---|
| Username | `-u` | — |
| Password | `-p` | masked; Show checkbox to reveal |
| Domain | `-d` | Required for both auth methods |
| Auth Method | `--auth` | NTLM (default) or Kerberos |
| Workstation | `--workstation` | NTLM only; bypasses `userWorkstations` |
| TGT File | `--tgt-file` | Kerberos only; path to `.ccache` |
| TGT Base64 | `--tgt-base64` | Kerberos only; validated before use |

Kerberos fields are disabled when NTLM is selected and vice-versa.

> If LDAP channel binding is enabled on the DC, NTLM will fail with
> `strongerAuthRequired`. Switch to Kerberos in that case.

### Options

| Field | CLI flag | Default |
|---|---|---|
| LDAP Page Size | `--page-size` | `500` |
| Threads | `--threads` | auto |
| Dormant Account Days | `--dormant-days` | `90` |
| Password Age Days | `--password-age` | `180` |
| Only enabled objects | `--only-enabled` | off |
| Skip Excel report | `--no-excel` | off |
| Verbose | `-v` | off |

### Modules

Checkbox grid organised by category. Leaving all boxes unchecked runs every
module (equivalent to `--collect all`). Use **Select All** / **Deselect All**
for bulk changes.

Categories and their privilege requirements:

| Category | Privilege |
|---|---|
| Forest, Domain, Trusts, Sites, Subnets, Schema | Regular user |
| Domain Controllers | Regular user |
| Users, Groups, SPNs, KRBTGT, Roastable accounts | Regular user |
| Computers, Printers | Regular user |
| OUs, GPOs, GP Links | Regular user |
| Password Policy | Regular user |
| Fine-Grained PP, LAPS, BitLocker | 🛑 Domain Admin |
| gMSA, dMSA, ADCS, DNS | Regular user (⚡ Beta) |

### Offline Excel

Generate a fresh XLSX report from an existing CSV output directory — no AD
connection needed. Useful for re-running the report after editing CSVs.

---

## Log panel

The log panel sits below the draggable sash. Grab the sash (the thin
horizontal bar between the tabs and the log) and drag it to resize both
sections.

Colour coding:

| Colour | Meaning |
|---|---|
| 🔵 Blue `dim` | The command that was executed |
| White | Normal output |
| 🟡 Amber `warn` | Warnings |
| 🔴 Red `err` | Errors, exceptions, failures |
| 🟢 Green `ok` | Success messages |

The **Wrap** toggle switches between word-wrap and horizontal-scroll mode
without restarting. Use the horizontal scrollbar at the bottom of the log
when wrap is disabled.

---

## Security review & findings

### Original CLI (`pyadrecon.py`)

#### 🔴 HIGH — Password visible in process list
**Finding:** The `-p PASSWORD` argument is readable by any local user via
`ps aux` or `/proc/<pid>/cmdline` on Linux.

**Recommendation:** Accept the password via `getpass` (interactive stdin) or a
dedicated environment variable such as `PYADRECON_PASSWORD`, then read it
inside the tool before any LDAP bind.

#### 🔴 HIGH — TGT Base64 visible in process list
**Finding:** `--tgt-base64 <VALUE>` is similarly exposed. A captured TGT
can be replayed for lateral movement.

**Recommendation:** Write the decoded bytes to a `chmod 600` temp file, pass
`--tgt-file` instead, and delete the file after the process exits.

#### 🟡 MEDIUM — No input sanitisation on CLI arguments
**Finding:** Hostname, username, and domain fields accept any string without
format validation before the LDAP bind is attempted.

**Recommendation:** Add `argparse` type validators (regex for hostname/domain,
integer range for numeric args) so invalid values are caught immediately.

#### 🟡 MEDIUM — Plaintext LDAP used as fallback
**Finding:** Without `--ssl`, LDAP on port 389 is used as a fallback. All AD
data — including LAPS passwords — would be transmitted unencrypted.

**Recommendation:** Document that LDAPS should always be used in production.
Consider inverting the default (require `--no-ssl` to opt into cleartext).

#### 🟢 LOW — Sensitive strings in Python garbage collection
**Finding:** Python `str` objects are immutable and GC'd non-deterministically,
so passwords may linger in memory longer than expected.

**Recommendation:** Use `bytearray` for sensitive values (mutable, can be
zeroed with `buf[:] = b'\x00' * len(buf)`) or integrate `SecretStr`.

#### 🟢 LOW — Verbose output may expose sensitive data
**Finding:** `-v` can surface LDAP bind details or partial attribute values
that could land in world-readable log files in CI/CD pipelines.

**Recommendation:** Document this; recommend redirecting verbose output to
files with restricted permissions (`chmod 600`).

---

### GUI (`pyadrecon_gui.py`) — mitigations applied

| Issue | Status | Detail |
|---|---|---|
| Shell injection | ✅ Fixed | `subprocess.Popen` with `shell=False` and a Python list |
| Input validation | ✅ Fixed | DC hostname, domain, port, and numeric fields validated with regex / `isdigit()` before the command is assembled |
| TGT Base64 validation | ✅ Fixed | `base64.b64decode(..., validate=True)` before passing to CLI |
| Password masking | ✅ Fixed | `show="●"` in entry; command preview replaces password with `●●●●` |
| TGT Base64 masking | ✅ Fixed | `show="●"` on the Base64 entry widget |
| Memory clearing | ✅ Fixed | Password and TGT Base64 `StringVar`s set to `""` in `WM_DELETE_WINDOW` handler |
| Process-list exposure | ⚠ Inherited | Password is still a list arg visible in `/proc/<pid>/cmdline`; cannot be fixed in the GUI layer until the CLI supports stdin/env delivery |

---

## Legal disclaimer

This tool is intended for **authorised security assessments only**. Running
reconnaissance against an Active Directory environment without explicit written
permission is illegal. The authors accept no liability for misuse.

---

## Acknowledgements

- [l4rm4nd](https://github.com/l4rm4nd) — PyADRecon author
- [Sense-of-Security](https://github.com/sense-of-security) — original ADRecon (PowerShell)
- [ldap3](https://github.com/cannatag/ldap3) — LDAP client library
- [impacket](https://github.com/fortra/impacket) — Kerberos support

## License

MIT — see [LICENSE](LICENSE)
