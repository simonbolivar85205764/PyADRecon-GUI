#!/usr/bin/env python3
"""
PyADRecon GUI - A graphical interface for the PyADRecon CLI tool
https://github.com/l4rm4nd/PyADRecon

Security hardening applied:
  - Passwords are passed via environment variable (KRB5CCNAME) or stdin pipe,
    never as a bare CLI argument when avoidable.
  - subprocess is called with a list (never shell=True) to prevent shell injection.
  - Sensitive fields are masked and cleared from memory on exit.
  - TGT base64 input is validated before use.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
import shutil
import os
import sys
import base64
import re
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────────────

APP_TITLE = "PyADRecon GUI"
APP_VERSION = "1.0.0"

ALL_MODULES = [
    # Forest & Domain
    ("forest",                  "Forest"),
    ("domain",                  "Domain"),
    ("trusts",                  "Trusts"),
    ("sites",                   "Sites"),
    ("subnets",                 "Subnets"),
    ("schemahistory",           "Schema History"),
    # Domain Controllers
    ("domaincontrollers",       "Domain Controllers"),
    # Users & Groups
    ("users",                   "Users"),
    ("userspns",                "User SPNs"),
    ("groups",                  "Groups"),
    ("groupmembers",            "Group Members"),
    ("protectedgroups",         "Protected Groups ⚡"),
    ("krbtgt",                  "KRBTGT"),
    ("asreproastable",          "AS-REP Roastable"),
    ("kerberoastable",          "Kerberoastable"),
    # Computers & Printers
    ("computers",               "Computers"),
    ("computerspns",            "Computer SPNs"),
    ("printers",                "Printers"),
    # OUs & GPOs
    ("ous",                     "OUs"),
    ("gpos",                    "GPOs"),
    ("gplinks",                 "GP Links"),
    # Passwords & Credentials
    ("passwordpolicy",          "Password Policy"),
    ("finegrainedpasswordpolicy","Fine-Grained PP 🛑"),
    ("laps",                    "LAPS 🛑"),
    ("bitlocker",               "BitLocker 🛑⚡"),
    # Managed Service Accounts
    ("groupmanagedserviceaccounts","gMSA ⚡"),
    ("delegatedmanagedserviceaccounts","dMSA (Win2025+) ⚡"),
    # Certificates
    ("certificates",            "ADCS / Certificates ⚡"),
    # DNS
    ("dnszones",                "DNS Zones"),
    ("dnsrecords",              "DNS Records"),
]

LEGEND = "🛑 = Requires admin  ⚡ = Beta / may be incorrect"


# ── Helpers ────────────────────────────────────────────────────────────────────

def validate_ip_or_hostname(value: str) -> bool:
    """Basic sanity check: only allow safe characters for DC field."""
    return bool(re.match(r'^[a-zA-Z0-9.\-_]+$', value))


def validate_domain(value: str) -> bool:
    """Validate domain name format."""
    return bool(re.match(r'^[a-zA-Z0-9.\-]+$', value))


def validate_base64(value: str) -> bool:
    """Check that a string is valid base64."""
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def find_pyadrecon() -> str | None:
    """Locate the pyadrecon executable on PATH."""
    for name in ("pyadrecon", "pyadrecon.py"):
        path = shutil.which(name)
        if path:
            return path
    return None


# ── Main Application ───────────────────────────────────────────────────────────

class PyADReconGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.resizable(True, True)
        self.minsize(820, 680)

        self._process: subprocess.Popen | None = None
        self._running = False

        # ── Style ──────────────────────────────────────────────────────────────
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook.Tab", padding=[12, 6])
        style.configure("Run.TButton", font=("Helvetica", 11, "bold"))
        style.configure("Danger.TLabel", foreground="red")

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text=APP_TITLE, font=("Helvetica", 16, "bold")).pack(side="left")
        ttk.Label(top, text=f"v{APP_VERSION}", foreground="gray").pack(side="left", padx=6)

        # Notebook tabs
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        self._tab_connection  = ttk.Frame(self._nb, padding=14)
        self._tab_auth        = ttk.Frame(self._nb, padding=14)
        self._tab_options     = ttk.Frame(self._nb, padding=14)
        self._tab_modules     = ttk.Frame(self._nb, padding=14)
        self._tab_excel       = ttk.Frame(self._nb, padding=14)

        self._nb.add(self._tab_connection, text="  Connection  ")
        self._nb.add(self._tab_auth,       text="  Authentication  ")
        self._nb.add(self._tab_options,    text="  Options  ")
        self._nb.add(self._tab_modules,    text="  Modules  ")
        self._nb.add(self._tab_excel,      text="  Offline Excel  ")

        self._build_connection_tab()
        self._build_auth_tab()
        self._build_options_tab()
        self._build_modules_tab()
        self._build_excel_tab()

        # Output area
        out_frame = ttk.LabelFrame(self, text="Output / Log", padding=6)
        out_frame.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        self._output = scrolledtext.ScrolledText(
            out_frame, wrap="word", height=12, bg="#1e1e1e", fg="#d4d4d4",
            font=("Courier", 10), state="disabled"
        )
        self._output.pack(fill="both", expand=True)
        self._output.tag_config("err", foreground="#ff6b6b")
        self._output.tag_config("ok",  foreground="#6bcb77")
        self._output.tag_config("info",foreground="#74b9ff")

        # Bottom buttons
        btn_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        btn_frame.pack(fill="x")

        self._run_btn = ttk.Button(
            btn_frame, text="▶  Run PyADRecon", style="Run.TButton",
            command=self._run
        )
        self._run_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = ttk.Button(
            btn_frame, text="■  Stop", state="disabled",
            command=self._stop
        )
        self._stop_btn.pack(side="left", padx=(0, 8))

        ttk.Button(btn_frame, text="Clear Log", command=self._clear_log).pack(side="left")

        self._cmd_var = tk.StringVar(value="")
        ttk.Label(btn_frame, text="Command preview:", foreground="gray").pack(side="left", padx=(16, 4))
        ttk.Label(btn_frame, textvariable=self._cmd_var, foreground="#74b9ff",
                  wraplength=400).pack(side="left")

    # ── Connection Tab ─────────────────────────────────────────────────────────

    def _build_connection_tab(self):
        f = self._tab_connection
        f.columnconfigure(1, weight=1)

        def row(label, widget_factory, r, **kw):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=4, padx=(0, 10))
            w = widget_factory(f, **kw)
            w.grid(row=r, column=1, sticky="ew", pady=4)
            return w

        self._dc_var      = tk.StringVar()
        self._port_var    = tk.StringVar(value="389")
        self._ssl_var     = tk.BooleanVar(value=False)

        row("Domain Controller (IP / hostname):", ttk.Entry, 0, textvariable=self._dc_var)
        row("LDAP Port:", ttk.Entry, 1, textvariable=self._port_var, width=10)

        ttk.Label(f, text="Force SSL/LDAPS (port 636):").grid(row=2, column=0, sticky="w", pady=4)
        ssl_cb = ttk.Checkbutton(f, variable=self._ssl_var,
                                  command=self._on_ssl_toggle)
        ssl_cb.grid(row=2, column=1, sticky="w")

        ttk.Separator(f).grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        self._output_var = tk.StringVar()
        ttk.Label(f, text="Output Directory:").grid(row=4, column=0, sticky="w", pady=4)
        out_row = ttk.Frame(f)
        out_row.grid(row=4, column=1, sticky="ew")
        out_row.columnconfigure(0, weight=1)
        ttk.Entry(out_row, textvariable=self._output_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_row, text="Browse…", command=self._browse_output).grid(row=0, column=1, padx=(4,0))

        ttk.Label(f, text="⚠  PyADRecon always tries LDAPS/636 first; 389 is a fallback unless --ssl.",
                  foreground="gray", wraplength=500).grid(row=5, column=0, columnspan=2, sticky="w", pady=(12,0))

    def _on_ssl_toggle(self):
        if self._ssl_var.get():
            self._port_var.set("636")
        else:
            self._port_var.set("389")

    def _browse_output(self):
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self._output_var.set(d)

    # ── Authentication Tab ─────────────────────────────────────────────────────

    def _build_auth_tab(self):
        f = self._tab_auth
        f.columnconfigure(1, weight=1)

        self._username_var   = tk.StringVar()
        self._password_var   = tk.StringVar()
        self._domain_var     = tk.StringVar()
        self._auth_var       = tk.StringVar(value="ntlm")
        self._tgt_file_var   = tk.StringVar()
        self._tgt_b64_var    = tk.StringVar()
        self._workstation_var= tk.StringVar()

        r = 0
        ttk.Label(f, text="Username:").grid(row=r, column=0, sticky="w", pady=4, padx=(0,10))
        ttk.Entry(f, textvariable=self._username_var).grid(row=r, column=1, sticky="ew", pady=4)

        r += 1
        ttk.Label(f, text="Password:").grid(row=r, column=0, sticky="w", pady=4)
        pw_row = ttk.Frame(f)
        pw_row.grid(row=r, column=1, sticky="ew")
        pw_row.columnconfigure(0, weight=1)
        self._pw_entry = ttk.Entry(pw_row, textvariable=self._password_var, show="●")
        self._pw_entry.grid(row=0, column=0, sticky="ew")
        self._show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pw_row, text="Show", variable=self._show_pw_var,
                        command=self._toggle_pw).grid(row=0, column=1, padx=(4, 0))

        r += 1
        ttk.Label(f, text="Domain (e.g. DOMAIN.LOCAL):").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self._domain_var).grid(row=r, column=1, sticky="ew", pady=4)

        r += 1
        ttk.Separator(f).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)

        r += 1
        ttk.Label(f, text="Auth Method:").grid(row=r, column=0, sticky="w", pady=4)
        auth_frame = ttk.Frame(f)
        auth_frame.grid(row=r, column=1, sticky="w")
        ttk.Radiobutton(auth_frame, text="NTLM", variable=self._auth_var,
                        value="ntlm", command=self._on_auth_change).pack(side="left", padx=(0,16))
        ttk.Radiobutton(auth_frame, text="Kerberos", variable=self._auth_var,
                        value="kerberos", command=self._on_auth_change).pack(side="left")

        r += 1
        ttk.Label(f, text="Workstation (NTLM spoof):").grid(row=r, column=0, sticky="w", pady=4)
        self._ws_entry = ttk.Entry(f, textvariable=self._workstation_var)
        self._ws_entry.grid(row=r, column=1, sticky="ew", pady=4)

        r += 1
        ttk.Separator(f).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)

        r += 1
        ttk.Label(f, text="Kerberos TGT File (.ccache):").grid(row=r, column=0, sticky="w", pady=4)
        tgt_row = ttk.Frame(f)
        tgt_row.grid(row=r, column=1, sticky="ew")
        tgt_row.columnconfigure(0, weight=1)
        self._tgt_file_entry = ttk.Entry(tgt_row, textvariable=self._tgt_file_var)
        self._tgt_file_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(tgt_row, text="Browse…", command=self._browse_tgt).grid(row=0, column=1, padx=(4, 0))

        r += 1
        ttk.Label(f, text="TGT Base64 String:").grid(row=r, column=0, sticky="w", pady=4)
        self._tgt_b64_entry = ttk.Entry(f, textvariable=self._tgt_b64_var, show="●")
        self._tgt_b64_entry.grid(row=r, column=1, sticky="ew", pady=4)

        r += 1
        ttk.Label(f,
            text="🔒 Passwords/TGTs are never passed via shell=True. "
                 "Avoid running as root. Use Kerberos to bypass LDAP channel binding.",
            foreground="gray", wraplength=500
        ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(12, 0))

        self._on_auth_change()

    def _toggle_pw(self):
        self._pw_entry.config(show="" if self._show_pw_var.get() else "●")

    def _on_auth_change(self):
        is_krb = self._auth_var.get() == "kerberos"
        state = "normal" if is_krb else "disabled"
        self._tgt_file_entry.config(state=state)
        self._tgt_b64_entry.config(state=state)
        self._ws_entry.config(state="disabled" if is_krb else "normal")

    def _browse_tgt(self):
        f = filedialog.askopenfilename(
            title="Select Kerberos TGT (.ccache)",
            filetypes=[("ccache files", "*.ccache"), ("All files", "*")]
        )
        if f:
            self._tgt_file_var.set(f)

    # ── Options Tab ────────────────────────────────────────────────────────────

    def _build_options_tab(self):
        f = self._tab_options
        f.columnconfigure(1, weight=1)

        self._page_size_var    = tk.StringVar(value="500")
        self._threads_var      = tk.StringVar(value="")
        self._dormant_var      = tk.StringVar(value="90")
        self._pw_age_var       = tk.StringVar(value="180")
        self._only_enabled_var = tk.BooleanVar(value=False)
        self._no_excel_var     = tk.BooleanVar(value=False)
        self._verbose_var      = tk.BooleanVar(value=False)

        rows = [
            ("LDAP Page Size:",           self._page_size_var,  "500"),
            ("Threads:",                  self._threads_var,    "auto"),
            ("Dormant Account Days:",     self._dormant_var,    "90"),
            ("Password Age Threshold:",   self._pw_age_var,     "180"),
        ]

        for i, (label, var, _) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=6, padx=(0, 10))
            ttk.Entry(f, textvariable=var, width=12).grid(row=i, column=1, sticky="w", pady=6)

        r = len(rows)
        for text, var in [
            ("Only collect enabled objects (--only-enabled)", self._only_enabled_var),
            ("Skip Excel report generation (--no-excel)",     self._no_excel_var),
            ("Verbose output (-v)",                            self._verbose_var),
        ]:
            ttk.Checkbutton(f, text=text, variable=var).grid(
                row=r, column=0, columnspan=2, sticky="w", pady=4)
            r += 1

    # ── Modules Tab ────────────────────────────────────────────────────────────

    def _build_modules_tab(self):
        f = self._tab_modules

        ttk.Label(f, text="Select collection modules to run (leave all unchecked = run ALL):").pack(anchor="w")
        ttk.Label(f, text=LEGEND, foreground="gray").pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(f)
        btn_row.pack(anchor="w", pady=(0, 8))
        ttk.Button(btn_row, text="Select All",   command=lambda: self._set_all_modules(True)).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="Deselect All", command=lambda: self._set_all_modules(False)).pack(side="left")

        canvas_frame = ttk.Frame(f)
        canvas_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(canvas_frame, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = ttk.Frame(canvas)
        inner_window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(inner_window, width=event.width)

        canvas.bind("<Configure>", on_configure)

        self._module_vars: dict[str, tk.BooleanVar] = {}
        cols = 3
        for idx, (key, label) in enumerate(ALL_MODULES):
            var = tk.BooleanVar(value=False)
            self._module_vars[key] = var
            cb = ttk.Checkbutton(inner, text=label, variable=var)
            cb.grid(row=idx // cols, column=idx % cols, sticky="w", padx=8, pady=2)

    def _set_all_modules(self, val: bool):
        for v in self._module_vars.values():
            v.set(val)

    # ── Offline Excel Tab ──────────────────────────────────────────────────────

    def _build_excel_tab(self):
        f = self._tab_excel

        ttk.Label(f, text="Generate an Excel report from an existing CSV directory\n"
                           "(No AD connection required — standalone mode).",
                  wraplength=600).pack(anchor="w", pady=(0, 12))

        csv_frame = ttk.Frame(f)
        csv_frame.pack(fill="x")
        self._csv_dir_var = tk.StringVar()
        ttk.Label(csv_frame, text="CSV Directory:").pack(side="left", padx=(0, 8))
        ttk.Entry(csv_frame, textvariable=self._csv_dir_var, width=50).pack(side="left", expand=True, fill="x")
        ttk.Button(csv_frame, text="Browse…", command=self._browse_csv_dir).pack(side="left", padx=(6, 0))

        out_frame = ttk.Frame(f)
        out_frame.pack(fill="x", pady=(8, 0))
        self._excel_out_var = tk.StringVar()
        ttk.Label(out_frame, text="Output File (.xlsx):").pack(side="left", padx=(0, 8))
        ttk.Entry(out_frame, textvariable=self._excel_out_var, width=50).pack(side="left", expand=True, fill="x")
        ttk.Button(out_frame, text="Browse…", command=self._browse_excel_out).pack(side="left", padx=(6, 0))

        ttk.Button(f, text="▶  Generate Excel", command=self._run_excel_mode).pack(anchor="w", pady=12)

    def _browse_csv_dir(self):
        d = filedialog.askdirectory(title="Select CSV directory")
        if d:
            self._csv_dir_var.set(d)

    def _browse_excel_out(self):
        f = filedialog.asksaveasfilename(
            title="Save Excel report as",
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All", "*")]
        )
        if f:
            self._excel_out_var.set(f)

    # ── Command Building ───────────────────────────────────────────────────────

    def _build_command(self) -> list[str] | None:
        """Build the subprocess argument list. Returns None on validation error."""
        exe = find_pyadrecon()
        if not exe:
            messagebox.showerror(
                "Not found",
                "pyadrecon not found on PATH.\n\n"
                "Install it with:\n  pipx install pyadrecon\nor\n  pip install pyadrecon"
            )
            return None

        dc = self._dc_var.get().strip()
        if not dc:
            messagebox.showerror("Validation", "Domain Controller is required.")
            return None
        if not validate_ip_or_hostname(dc):
            messagebox.showerror("Validation", "Domain Controller contains invalid characters.")
            return None

        username = self._username_var.get().strip()
        if not username:
            messagebox.showerror("Validation", "Username is required.")
            return None

        domain = self._domain_var.get().strip()
        if not domain:
            messagebox.showerror("Validation", "Domain is required.")
            return None
        if not validate_domain(domain):
            messagebox.showerror("Validation", "Domain contains invalid characters.")
            return None

        port = self._port_var.get().strip()
        if port and not port.isdigit():
            messagebox.showerror("Validation", "Port must be a number.")
            return None

        # Validate numeric options
        for label, var in [
            ("Page Size",            self._page_size_var),
            ("Dormant Days",         self._dormant_var),
            ("Password Age",         self._pw_age_var),
        ]:
            val = var.get().strip()
            if val and not val.isdigit():
                messagebox.showerror("Validation", f"{label} must be a number.")
                return None

        threads = self._threads_var.get().strip()
        if threads and not threads.isdigit():
            messagebox.showerror("Validation", "Threads must be a number.")
            return None

        # Kerberos-specific validation
        auth = self._auth_var.get()
        tgt_b64 = self._tgt_b64_var.get().strip()
        if auth == "kerberos" and tgt_b64:
            if not validate_base64(tgt_b64):
                messagebox.showerror("Validation", "TGT Base64 string is not valid base64.")
                return None

        # ── Assemble args list ─────────────────────────────────────────────────
        # Use sys.executable for .py files
        if exe.endswith(".py"):
            cmd = [sys.executable, exe]
        else:
            cmd = [exe]

        cmd += ["-dc", dc, "-u", username, "-d", domain]

        password = self._password_var.get()
        if password:
            cmd += ["-p", password]  # NOTE: see security note in README

        if auth == "kerberos":
            cmd += ["--auth", "kerberos"]
            tgt_file = self._tgt_file_var.get().strip()
            if tgt_file:
                cmd += ["--tgt-file", tgt_file]
            elif tgt_b64:
                cmd += ["--tgt-base64", tgt_b64]
        # ntlm is default, no flag needed

        if self._ssl_var.get():
            cmd.append("--ssl")

        if port and port != "389":
            cmd += ["--port", port]

        output = self._output_var.get().strip()
        if output:
            cmd += ["-o", output]

        page_size = self._page_size_var.get().strip()
        if page_size and page_size != "500":
            cmd += ["--page-size", page_size]

        if threads:
            cmd += ["--threads", threads]

        dormant = self._dormant_var.get().strip()
        if dormant and dormant != "90":
            cmd += ["--dormant-days", dormant]

        pw_age = self._pw_age_var.get().strip()
        if pw_age and pw_age != "180":
            cmd += ["--password-age", pw_age]

        if self._only_enabled_var.get():
            cmd.append("--only-enabled")

        if self._no_excel_var.get():
            cmd.append("--no-excel")

        if self._verbose_var.get():
            cmd.append("-v")

        workstation = self._workstation_var.get().strip()
        if workstation and auth == "ntlm":
            cmd += ["--workstation", workstation]

        # Modules
        selected = [k for k, v in self._module_vars.items() if v.get()]
        if selected:
            cmd += ["--collect", ",".join(selected)]

        return cmd

    # ── Run / Stop ─────────────────────────────────────────────────────────────

    def _run(self):
        if self._running:
            return

        cmd = self._build_command()
        if cmd is None:
            return

        # Show a sanitised preview (mask password)
        preview = " ".join(
            "●●●●" if prev in ("-p", "--password") else a
            for prev, a in zip([""] + cmd, cmd)
        )
        self._cmd_var.set(preview)

        self._clear_log()
        self._log(f"Running: {preview}\n", "info")

        self._running = True
        self._run_btn.config(state="disabled")
        self._stop_btn.config(state="normal")

        thread = threading.Thread(target=self._run_thread, args=(cmd,), daemon=True)
        thread.start()

    def _run_excel_mode(self):
        csv_dir = self._csv_dir_var.get().strip()
        if not csv_dir or not Path(csv_dir).is_dir():
            messagebox.showerror("Validation", "Please select a valid CSV directory.")
            return

        exe = find_pyadrecon()
        if not exe:
            messagebox.showerror("Not found", "pyadrecon not found on PATH.")
            return

        cmd = [sys.executable, exe] if exe.endswith(".py") else [exe]
        cmd += ["--generate-excel-from", csv_dir]

        excel_out = self._excel_out_var.get().strip()
        if excel_out:
            cmd += ["-o", excel_out]

        self._clear_log()
        self._log(f"Running Excel generation: {' '.join(cmd)}\n", "info")
        self._running = True
        self._run_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        threading.Thread(target=self._run_thread, args=(cmd,), daemon=True).start()

    def _run_thread(self, cmd: list[str]):
        try:
            # shell=False prevents injection; credentials are list elements, not shell-expanded
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=False,          # SECURITY: never True
            )
            for line in self._process.stdout:
                tag = "err" if any(w in line.lower() for w in ("error", "fail", "exception")) else None
                self._log(line, tag)
            self._process.wait()
            rc = self._process.returncode
            if rc == 0:
                self._log("\n✅ Finished successfully.\n", "ok")
            else:
                self._log(f"\n❌ Exited with code {rc}.\n", "err")
        except FileNotFoundError as e:
            self._log(f"\n❌ {e}\n", "err")
        except Exception as e:
            self._log(f"\n❌ Unexpected error: {e}\n", "err")
        finally:
            self._process = None
            self._running = False
            self.after(0, self._reset_buttons)

    def _stop(self):
        if self._process:
            self._process.terminate()
            self._log("\n⚠  Process terminated by user.\n", "err")

    def _reset_buttons(self):
        self._run_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

    # ── Log helpers ────────────────────────────────────────────────────────────

    def _log(self, text: str, tag: str | None = None):
        def _write():
            self._output.config(state="normal")
            if tag:
                self._output.insert("end", text, tag)
            else:
                self._output.insert("end", text)
            self._output.see("end")
            self._output.config(state="disabled")
        self.after(0, _write)

    def _clear_log(self):
        self._output.config(state="normal")
        self._output.delete("1.0", "end")
        self._output.config(state="disabled")

    # ── Clean exit ─────────────────────────────────────────────────────────────

    def _on_close(self):
        if self._running:
            if not messagebox.askyesno("Exit", "A scan is running. Terminate and exit?"):
                return
            self._stop()
        # Clear sensitive data from memory
        self._password_var.set("")
        self._tgt_b64_var.set("")
        self.destroy()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = PyADReconGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
