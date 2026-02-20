# PyADRecon GUI

A clean Python/Tkinter graphical interface that wraps the
[PyADRecon](https://github.com/l4rm4nd/PyADRecon) CLI tool — a Python3
implementation of ADRecon for Active Directory reconnaissance and auditing.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-informational)

---

## Features

| Feature | Detail |
|---|---|
| **Tabbed interface** | Connection · Authentication · Options · Modules · Offline Excel |
| **All CLI flags exposed** | Every argument from `pyadrecon --help` is available in the GUI |
| **Module picker** | Checkbox grid — select individual modules or run all |
| **Offline Excel mode** | Generate an XLSX report from an existing CSV directory without an AD connection |
| **Live output log** | Colour-coded stdout/stderr streamed in real time |
| **Stop button** | Gracefully terminate a running scan |
| **Auto-discovers `pyadrecon`** | Searches PATH for the executable automatically |
| **Security hardened** | `shell=False`, input validation, masked password fields, memory clearing on exit |

---

## Requirements

- **Python 3.10+** (uses `X | Y` union type hints)
- **`tkinter`** — included in the standard library on most platforms
  - Ubuntu/Debian: `sudo apt install python3-tk`
  - macOS Homebrew: `brew install python-tk`
- **PyADRecon** installed and on `PATH`:
  ```
  pipx install pyadrecon
  # or
  pip install pyadrecon
  ```

---

## Installation & Usage

```bash
# 1 – Clone or download pyadrecon_gui.py
# 2 – Run directly — no extra dependencies needed
python pyadrecon_gui.py
```

The GUI will warn you if `pyadrecon` is not found on `PATH`.

---

## Tab Guide

### Connection
| Field | Description |
|---|---|
| Domain Controller | IP address or hostname of the target DC |
| LDAP Port | Default 389; auto-switches to 636 when SSL is checked |
| Force SSL/LDAPS | Adds `--ssl`; disallows insecure fallback |
| Output Directory | Where CSVs and the XLSX report are saved |

> **Tip:** PyADRecon always tries LDAPS/636 first; 389 is only used as a
> fallback unless `--ssl` is set.

### Authentication
| Field | Description |
|---|---|
| Username / Password | Credentials for LDAP bind |
| Domain | Required for both NTLM and Kerberos (e.g. `DOMAIN.LOCAL`) |
| Auth Method | NTLM (default) or Kerberos |
| Workstation | Spoof the workstation name for NTLM (bypasses `userWorkstations` restrictions) |
| TGT File | Path to a `.ccache` Kerberos ticket |
| TGT Base64 | Base64-encoded TGT (validated before use) |

> **Kerberos note:** If LDAP channel binding is enabled on the DC, NTLM will
> fail with `strongerAuthRequired`. Use Kerberos auth instead.

### Options
Fine-tune page size, threads, dormant-account threshold, password-age
threshold, and toggle `--only-enabled`, `--no-excel`, and `-v`.

### Modules
Select specific collection modules via checkboxes. Leaving all boxes
unchecked runs every module (equivalent to `--collect all`).

Legend:
- 🛑 Requires Domain Admin privileges
- ⚡ Beta — results may be incorrect

### Offline Excel
Point to an existing CSV output directory and generate a fresh XLSX report
without connecting to any domain controller.

---

## Security Review & Findings

The following issues were identified in the **original PyADRecon CLI** and
the **GUI wrapper**. Recommendations are included.

### CLI (original `pyadrecon.py`)

#### 🔴 HIGH — Password visible in process list
**Finding:** The password is accepted via `-p PASSWORD` on the command line.
On Linux/macOS any user can run `ps aux` and see the plaintext password in
another process's argument list.

**Recommendation:** Accept the password via `stdin` (interactive prompt with
`getpass`) or a dedicated environment variable (e.g. `PYADRECON_PASSWORD`).
The GUI currently passes `-p` as a list element to avoid shell interpolation,
but the value is still visible in `/proc/<pid>/cmdline`.

#### 🔴 HIGH — TGT Base64 visible in process list
**Finding:** `--tgt-base64 <VALUE>` is similarly visible in the process list.
A captured TGT can be replayed for lateral movement.

**Recommendation:** Pipe the value via stdin or write it to a temp file with
restricted permissions (`chmod 600`) and pass `--tgt-file` instead, then
delete the file after the process exits.

#### 🟡 MEDIUM — No input sanitisation on CLI arguments
**Finding:** The CLI accepts `-dc`, `-u`, `-d`, etc. without validating the
format of the values. While `ldap3` is unlikely to be vulnerable to LDAP
injection through these fields, unusual values could cause confusing failures
or unexpected LDAP query results.

**Recommendation:** Add `argparse` type validators (e.g. an IP/hostname regex)
so invalid values are rejected before any network connection is attempted.

#### 🟡 MEDIUM — LDAP (plaintext) used as fallback
**Finding:** When `--ssl` is not set, the tool falls back to plaintext LDAP
on port 389. All AD data, including password hashes retrieved via LAPS, would
be transmitted in cleartext.

**Recommendation:** Document clearly that LDAPS should always be preferred in
production. Consider making `--ssl` the default and requiring an explicit
`--no-ssl` flag to opt into plaintext.

#### 🟢 LOW — Credentials stored as plain strings in Python objects
**Finding:** Passwords and TGT material are stored as Python `str` objects.
Python strings are immutable and garbage-collected non-deterministically,
meaning sensitive data may linger in memory longer than necessary.

**Recommendation:** Use `bytearray` (mutable, can be zeroed) for sensitive
values where possible, or integrate `cryptography`'s `SecretStr` pattern.

#### 🟢 LOW — Verbose output may log sensitive data
**Finding:** With `-v`, verbose output may include LDAP bind details or
partial attribute data that could be written to shared log files.

**Recommendation:** Ensure `-v` output is not inadvertently redirected to
world-readable log files in automated pipelines.

---

### GUI (`pyadrecon_gui.py`)

#### ✅ Fixed — Shell injection
`subprocess.Popen` is called with `shell=False` and a Python list, so no
shell metacharacter expansion is possible regardless of what the user types
into any field.

#### ✅ Fixed — Input validation
DC hostname, domain, port, and numeric fields are validated with regex and
`isdigit()` checks before the command is assembled.

#### ✅ Fixed — TGT Base64 validation
The base64 string is validated with `base64.b64decode(..., validate=True)`
before being passed to the CLI.

#### ✅ Fixed — Memory clearing on exit
Password and TGT Base64 `StringVar` values are explicitly set to `""` in the
`WM_DELETE_WINDOW` handler so they are not held in memory after the window
closes.

#### ✅ Fixed — Password masking
The password field uses `show="●"` and the TGT Base64 field is also masked.
The command preview in the status bar replaces the password with `●●●●`.

#### 🟡 MEDIUM — Password still visible in `/proc/<pid>/cmdline`
The GUI inherits the upstream CLI's process-list exposure issue. Until the
CLI supports stdin or environment-variable credential delivery, this cannot
be fully mitigated in the GUI layer.

---

## Legal Disclaimer

This tool is intended for **authorised security assessments** only. Running
reconnaissance against an Active Directory environment without explicit written
permission is illegal. The authors accept no liability for misuse.

---

## Acknowledgements

- [l4rm4nd](https://github.com/l4rm4nd) — original PyADRecon author
- [Sense-of-Security](https://github.com/sense-of-security) — original ADRecon (PowerShell)
- [ldap3](https://github.com/cannatag/ldap3) — LDAP client library
- [impacket](https://github.com/fortra/impacket) — Kerberos support

## License

MIT — see [LICENSE](LICENSE)
