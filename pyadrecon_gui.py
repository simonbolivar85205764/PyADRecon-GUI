#!/usr/bin/env python3
"""
PyADRecon GUI - A graphical interface for the PyADRecon CLI tool
https://github.com/l4rm4nd/PyADRecon

Security hardening applied:
  - subprocess is called with a list (never shell=True) to prevent shell injection.
  - Sensitive fields are masked and cleared from memory on exit.
  - TGT base64 input is validated before use.
  - Input fields are validated with regex before the command is assembled.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import shutil
import sys
import base64
import re
from pathlib import Path


# ── Palette ────────────────────────────────────────────────────────────────────

C = {
    "bg":           "#0f1117",
    "surface":      "#1a1d27",
    "surface2":     "#22263a",
    "border":       "#2e3250",
    "accent":       "#5865f2",
    "accent_hover": "#4752c4",
    "accent_dim":   "#3b4189",
    "success":      "#3ba55d",
    "danger":       "#ed4245",
    "danger_hover": "#c03537",
    "warn":         "#faa61a",
    "text":         "#e3e5e8",
    "text_muted":   "#8e9297",
    "text_dim":     "#5c6070",
    "log_bg":       "#0b0d12",
    "log_fg":       "#c9d1d9",
    "log_err":      "#f87171",
    "log_ok":       "#4ade80",
    "log_info":     "#60a5fa",
    "log_warn":     "#fbbf24",
    "log_dim":      "#4a5065",
    "input_bg":     "#13151f",
    "tab_sel":      "#1e2235",
}

FONT_MAIN   = ("Segoe UI", 10)
FONT_BOLD   = ("Segoe UI", 10, "bold")
FONT_SMALL  = ("Segoe UI", 9)
FONT_SECTION= ("Segoe UI", 8, "bold")
FONT_MONO   = ("Cascadia Code", 10) if sys.platform == "win32" else ("Menlo", 10)

APP_TITLE   = "PyADRecon GUI"
APP_VERSION = "2.0.0"

ALL_MODULES = [
    # (key, display_label)  — key=None → section header
    (None,                          "── Forest & Domain ──"),
    ("forest",                      "Forest"),
    ("domain",                      "Domain"),
    ("trusts",                      "Trusts"),
    ("sites",                       "Sites"),
    ("subnets",                     "Subnets"),
    ("schemahistory",               "Schema History"),
    (None,                          "── Domain Controllers ──"),
    ("domaincontrollers",           "Domain Controllers"),
    (None,                          "── Users & Groups ──"),
    ("users",                       "Users"),
    ("userspns",                    "User SPNs"),
    ("groups",                      "Groups"),
    ("groupmembers",                "Group Members"),
    ("protectedgroups",             "Protected Groups ⚡"),
    ("krbtgt",                      "KRBTGT"),
    ("asreproastable",              "AS-REP Roastable"),
    ("kerberoastable",              "Kerberoastable"),
    (None,                          "── Computers & Printers ──"),
    ("computers",                   "Computers"),
    ("computerspns",                "Computer SPNs"),
    ("printers",                    "Printers"),
    (None,                          "── OUs & GPOs ──"),
    ("ous",                         "OUs"),
    ("gpos",                        "GPOs"),
    ("gplinks",                     "GP Links"),
    (None,                          "── Passwords & Credentials ──"),
    ("passwordpolicy",              "Password Policy"),
    ("finegrainedpasswordpolicy",   "Fine-Grained PP 🛑"),
    ("laps",                        "LAPS 🛑"),
    ("bitlocker",                   "BitLocker 🛑⚡"),
    (None,                          "── Managed Service Accounts ──"),
    ("groupmanagedserviceaccounts", "gMSA ⚡"),
    ("delegatedmanagedserviceaccounts", "dMSA (Win2025+) ⚡"),
    (None,                          "── Certificates ──"),
    ("certificates",                "ADCS / Certificates ⚡"),
    (None,                          "── DNS ──"),
    ("dnszones",                    "DNS Zones"),
    ("dnsrecords",                  "DNS Records"),
]

LABEL_W = 26   # fixed width for form labels (chars)


# ── Validators ─────────────────────────────────────────────────────────────────

def validate_ip_or_hostname(v: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-_]+$', v))

def validate_domain(v: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-]+$', v))

def validate_base64(v: str) -> bool:
    try:
        base64.b64decode(v, validate=True)
        return True
    except Exception:
        return False

def find_pyadrecon() -> str | None:
    for name in ("pyadrecon", "pyadrecon.py"):
        p = shutil.which(name)
        if p:
            return p
    return None


# ── Custom widgets ─────────────────────────────────────────────────────────────

class DE(tk.Entry):
    """Dark-themed entry."""
    def __init__(self, parent, **kw):
        kw.setdefault("bg",               C["input_bg"])
        kw.setdefault("fg",               C["text"])
        kw.setdefault("insertbackground", C["text"])
        kw.setdefault("highlightthickness", 1)
        kw.setdefault("highlightcolor",   C["accent"])
        kw.setdefault("highlightbackground", C["border"])
        kw.setdefault("relief",           "flat")
        kw.setdefault("font",             FONT_MAIN)
        kw.setdefault("bd",               6)
        super().__init__(parent, **kw)


class DB(tk.Button):
    """Dark flat button with hover effect."""
    def __init__(self, parent, primary=True, danger=False, **kw):
        if danger:
            bg, hv = C["danger"], C["danger_hover"]
        elif primary:
            bg, hv = C["accent"], C["accent_hover"]
        else:
            bg, hv = C["surface2"], C["border"]

        kw.setdefault("bg",               bg)
        kw.setdefault("fg",               C["text"])
        kw.setdefault("activebackground", hv)
        kw.setdefault("activeforeground", C["text"])
        kw.setdefault("relief",           "flat")
        kw.setdefault("bd",               0)
        kw.setdefault("padx",             14)
        kw.setdefault("pady",             7)
        kw.setdefault("cursor",           "hand2")
        kw.setdefault("font",             FONT_BOLD if primary else FONT_MAIN)
        super().__init__(parent, **kw)
        self._bg, self._hv = bg, hv
        self.bind("<Enter>", lambda _: self._hover(True))
        self.bind("<Leave>", lambda _: self._hover(False))

    def _hover(self, on: bool):
        if str(self.cget("state")) != "disabled":
            self.config(bg=self._hv if on else self._bg)


# ── Main app ───────────────────────────────────────────────────────────────────

class PyADReconGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.minsize(860, 600)
        self.geometry("1100x860")

        self._process: subprocess.Popen | None = None
        self._running = False

        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── TTK style ──────────────────────────────────────────────────────────────

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure(".",
            background=C["bg"], foreground=C["text"],
            troughcolor=C["surface"], font=FONT_MAIN)

        s.configure("TNotebook",
            background=C["bg"], borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab",
            background=C["surface"], foreground=C["text_muted"],
            padding=[18, 9], borderwidth=0, font=FONT_MAIN)
        s.map("TNotebook.Tab",
            background=[("selected", C["tab_sel"]), ("active", C["surface2"])],
            foreground=[("selected", C["text"]),    ("active", C["text"])],
        )

        s.configure("Card.TFrame", background=C["surface"])
        s.configure("TFrame",      background=C["bg"])

        s.configure("TLabelframe",
            background=C["surface"], bordercolor=C["border"], relief="flat")
        s.configure("TLabelframe.Label",
            background=C["surface"], foreground=C["text_muted"],
            font=FONT_SECTION)

        s.configure("TCheckbutton",
            background=C["surface"], foreground=C["text"])
        s.map("TCheckbutton",
            background=[("active", C["surface"])],
            indicatorcolor=[("selected", C["accent"]),
                            ("!selected", C["input_bg"])])

        s.configure("TRadiobutton",
            background=C["surface"], foreground=C["text"])
        s.map("TRadiobutton",
            background=[("active", C["surface"])],
            indicatorcolor=[("selected", C["accent"]),
                            ("!selected", C["input_bg"])])

        s.configure("TSeparator", background=C["border"])

        s.configure("Vertical.TScrollbar",
            background=C["surface2"], troughcolor=C["surface"],
            arrowcolor=C["text_dim"], borderwidth=0, relief="flat", width=10)
        s.map("Vertical.TScrollbar",
            background=[("active", C["border"])])

        s.configure("Horizontal.TScrollbar",
            background=C["surface2"], troughcolor=C["surface"],
            arrowcolor=C["text_dim"], borderwidth=0, relief="flat", height=10)
        s.map("Horizontal.TScrollbar",
            background=[("active", C["border"])])

    # ── Main layout ────────────────────────────────────────────────────────────

    def _build(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=C["surface"], pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  " + APP_TITLE,
                 bg=C["surface"], fg=C["text"],
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=16)
        tk.Label(hdr, text=f"v{APP_VERSION}",
                 bg=C["surface"], fg=C["text_dim"],
                 font=FONT_SMALL).pack(side="left")

        # Status indicator (right)
        self._status_var = tk.StringVar(value="Idle")
        self._status_dot = tk.Label(hdr, text="●",
                                    bg=C["surface"], fg=C["text_dim"],
                                    font=("Segoe UI", 14))
        self._status_dot.pack(side="right", padx=(0, 12))
        tk.Label(hdr, textvariable=self._status_var,
                 bg=C["surface"], fg=C["text_muted"],
                 font=FONT_SMALL).pack(side="right", padx=(16, 2))

        tk.Frame(self, bg=C["accent"], height=2).pack(fill="x")

        # ── Vertical PanedWindow (top = tabs, bottom = log) ───────────────────
        self._pw = tk.PanedWindow(
            self, orient="vertical",
            bg=C["border"],
            sashwidth=7,
            sashpad=0,
            sashrelief="flat",
            opaqueresize=True,
            showhandle=False,
        )
        self._pw.pack(fill="both", expand=True)

        # TOP pane
        top = tk.Frame(self._pw, bg=C["bg"])
        self._pw.add(top, stretch="always", minsize=320)

        # Notebook
        self._nb = ttk.Notebook(top)
        self._nb.pack(fill="both", expand=True, padx=12, pady=(10, 0))

        self._tab_conn    = ttk.Frame(self._nb, style="Card.TFrame", padding=18)
        self._tab_auth    = ttk.Frame(self._nb, style="Card.TFrame", padding=18)
        self._tab_opts    = ttk.Frame(self._nb, style="Card.TFrame", padding=18)
        self._tab_mods    = ttk.Frame(self._nb, style="Card.TFrame", padding=18)
        self._tab_excel   = ttk.Frame(self._nb, style="Card.TFrame", padding=18)

        self._nb.add(self._tab_conn,  text="  Connection  ")
        self._nb.add(self._tab_auth,  text="  Authentication  ")
        self._nb.add(self._tab_opts,  text="  Options  ")
        self._nb.add(self._tab_mods,  text="  Modules  ")
        self._nb.add(self._tab_excel, text="  Offline Excel  ")

        self._build_conn()
        self._build_auth()
        self._build_opts()
        self._build_mods()
        self._build_excel()

        # Action bar
        self._build_action_bar(top)

        # BOTTOM pane (log)
        bot = tk.Frame(self._pw, bg=C["surface"])
        self._pw.add(bot, stretch="always", minsize=110)
        self._build_log(bot)

        # Place sash after first draw
        self.after(120, lambda: self._pw.sash_place(0, 0, 490))

    # ── Action bar ─────────────────────────────────────────────────────────────

    def _build_action_bar(self, parent):
        bar = tk.Frame(parent, bg=C["bg"], pady=10, padx=12)
        bar.pack(fill="x")

        self._run_btn = DB(bar, text="▶  Run PyADRecon", command=self._run)
        self._run_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = DB(bar, primary=False, danger=True,
                            text="■  Stop", state="disabled",
                            command=self._stop)
        self._stop_btn.pack(side="left")

        self._cmd_var = tk.StringVar(value="")
        tk.Label(bar, text="cmd:", bg=C["bg"], fg=C["text_dim"],
                 font=FONT_SMALL).pack(side="left", padx=(20, 4))
        tk.Label(bar, textvariable=self._cmd_var, bg=C["bg"],
                 fg=C["accent"], font=("Segoe UI", 9),
                 anchor="w", wraplength=560).pack(side="left", fill="x", expand=True)

    # ── Log panel ──────────────────────────────────────────────────────────────

    def _build_log(self, parent):
        # Log header
        lhdr = tk.Frame(parent, bg=C["surface"], pady=7, padx=10)
        lhdr.pack(fill="x")

        tk.Label(lhdr, text="Output / Log",
                 bg=C["surface"], fg=C["text_muted"],
                 font=FONT_SECTION).pack(side="left")

        # Drag hint
        tk.Label(lhdr, text="⠿ drag sash to resize",
                 bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 8)).pack(side="left", padx=12)

        DB(lhdr, primary=False, text="Clear",
           pady=3, padx=10, command=self._clear_log).pack(side="right")

        self._wrap_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            lhdr, text="Wrap", variable=self._wrap_var,
            bg=C["surface"], fg=C["text_muted"],
            selectcolor=C["surface2"], activebackground=C["surface"],
            font=FONT_SMALL, bd=0, relief="flat",
            command=self._toggle_wrap,
        ).pack(side="right", padx=(0, 8))

        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x")

        # Text + scrollbars
        frame = tk.Frame(parent, bg=C["log_bg"])
        frame.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")

        self._output = tk.Text(
            frame,
            wrap="word",
            bg=C["log_bg"], fg=C["log_fg"],
            insertbackground=C["text"],
            font=FONT_MONO,
            state="disabled",
            relief="flat", bd=0,
            selectbackground=C["accent_dim"],
            padx=12, pady=10,
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=self._output.yview)
        hsb.config(command=self._output.xview)

        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._output.pack(side="left", fill="both", expand=True)

        self._output.tag_config("err",  foreground=C["log_err"])
        self._output.tag_config("ok",   foreground=C["log_ok"])
        self._output.tag_config("info", foreground=C["log_info"])
        self._output.tag_config("warn", foreground=C["log_warn"])
        self._output.tag_config("dim",  foreground=C["log_dim"])

    def _toggle_wrap(self):
        self._output.config(wrap="word" if self._wrap_var.get() else "none")

    # ── Connection tab ─────────────────────────────────────────────────────────

    def _build_conn(self):
        f = self._tab_conn

        self._dc_var         = tk.StringVar()
        self._port_var       = tk.StringVar(value="389")
        self._ssl_var        = tk.BooleanVar(value=False)
        self._output_dir_var = tk.StringVar()

        self._sec(f, "Target")
        self._row(f, "Domain Controller:", DE, textvariable=self._dc_var)
        self._row(f, "LDAP Port:", DE, textvariable=self._port_var, width=8)

        r = tk.Frame(f, bg=C["surface"])
        r.pack(fill="x", pady=3)
        self._lbl(r, "Force SSL / LDAPS:")
        ttk.Checkbutton(r, variable=self._ssl_var,
                        command=self._on_ssl_toggle).pack(side="left")

        self._div(f)
        self._sec(f, "Output")

        r2 = tk.Frame(f, bg=C["surface"])
        r2.pack(fill="x", pady=3)
        self._lbl(r2, "Output Directory:")
        DE(r2, textvariable=self._output_dir_var).pack(
            side="left", fill="x", expand=True)
        DB(r2, primary=False, text="Browse…", pady=5, padx=10,
           command=self._browse_output).pack(side="left", padx=(6, 0))

        self._div(f)
        tk.Label(f, text="⚠  PyADRecon always tries LDAPS/636 first; 389 is a fallback "
                         "unless --ssl is set.",
                 bg=C["surface"], fg=C["text_dim"], font=FONT_SMALL,
                 wraplength=620, justify="left").pack(anchor="w")

    def _on_ssl_toggle(self):
        self._port_var.set("636" if self._ssl_var.get() else "389")

    def _browse_output(self):
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self._output_dir_var.set(d)

    # ── Authentication tab ─────────────────────────────────────────────────────

    def _build_auth(self):
        f = self._tab_auth

        self._username_var    = tk.StringVar()
        self._password_var    = tk.StringVar()
        self._domain_var      = tk.StringVar()
        self._auth_var        = tk.StringVar(value="ntlm")
        self._tgt_file_var    = tk.StringVar()
        self._tgt_b64_var     = tk.StringVar()
        self._workstation_var = tk.StringVar()

        self._sec(f, "Credentials")
        self._row(f, "Username:", DE, textvariable=self._username_var)

        # Password row with show/hide
        pw_row = tk.Frame(f, bg=C["surface"])
        pw_row.pack(fill="x", pady=3)
        self._lbl(pw_row, "Password:")
        self._pw_entry = DE(pw_row, textvariable=self._password_var, show="●")
        self._pw_entry.pack(side="left", fill="x", expand=True)
        self._show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(
            pw_row, text="Show", variable=self._show_pw,
            bg=C["surface"], fg=C["text_muted"],
            selectcolor=C["surface2"], activebackground=C["surface"],
            font=FONT_SMALL, bd=0, relief="flat",
            command=lambda: self._pw_entry.config(
                show="" if self._show_pw.get() else "●"),
        ).pack(side="left", padx=(6, 0))

        self._row(f, "Domain (e.g. DOMAIN.LOCAL):", DE,
                  textvariable=self._domain_var)

        self._div(f)
        self._sec(f, "Method")

        auth_row = tk.Frame(f, bg=C["surface"])
        auth_row.pack(anchor="w", pady=3)
        self._lbl(auth_row, "Auth Method:")
        for val, label in (("ntlm", "NTLM"), ("kerberos", "Kerberos")):
            ttk.Radiobutton(auth_row, text=label,
                            variable=self._auth_var, value=val,
                            command=self._on_auth_change
                            ).pack(side="left", padx=(0, 16))

        self._row(f, "Workstation (NTLM spoof):", DE,
                  textvariable=self._workstation_var)

        self._div(f)
        self._sec(f, "Kerberos TGT")

        tgt_row = tk.Frame(f, bg=C["surface"])
        tgt_row.pack(fill="x", pady=3)
        self._lbl(tgt_row, "TGT File (.ccache):")
        self._tgt_file_entry = DE(tgt_row, textvariable=self._tgt_file_var)
        self._tgt_file_entry.pack(side="left", fill="x", expand=True)
        self._tgt_browse_btn = DB(tgt_row, primary=False, text="Browse…",
                                  pady=5, padx=10, command=self._browse_tgt)
        self._tgt_browse_btn.pack(side="left", padx=(6, 0))

        b64_row = tk.Frame(f, bg=C["surface"])
        b64_row.pack(fill="x", pady=3)
        self._lbl(b64_row, "TGT Base64:")
        self._tgt_b64_entry = DE(b64_row, textvariable=self._tgt_b64_var,
                                 show="●")
        self._tgt_b64_entry.pack(side="left", fill="x", expand=True)

        self._div(f)
        tk.Label(f,
            text="🔒  shell=False ensures no shell injection. Passwords are list "
                 "args, never shell-expanded. Use Kerberos to bypass LDAP channel binding.",
            bg=C["surface"], fg=C["text_dim"], font=FONT_SMALL,
            wraplength=620, justify="left").pack(anchor="w")

        self._on_auth_change()

    def _on_auth_change(self):
        is_krb = self._auth_var.get() == "kerberos"
        st = "normal" if is_krb else "disabled"
        for w in (self._tgt_file_entry, self._tgt_b64_entry,
                  self._tgt_browse_btn):
            w.config(state=st)

    def _browse_tgt(self):
        fp = filedialog.askopenfilename(
            title="Select Kerberos TGT",
            filetypes=[("ccache files", "*.ccache"), ("All files", "*")],
        )
        if fp:
            self._tgt_file_var.set(fp)

    # ── Options tab ────────────────────────────────────────────────────────────

    def _build_opts(self):
        f = self._tab_opts

        self._page_size_var    = tk.StringVar(value="500")
        self._threads_var      = tk.StringVar(value="")
        self._dormant_var      = tk.StringVar(value="90")
        self._pw_age_var       = tk.StringVar(value="180")
        self._only_enabled_var = tk.BooleanVar(value=False)
        self._no_excel_var     = tk.BooleanVar(value=False)
        self._verbose_var      = tk.BooleanVar(value=False)

        self._sec(f, "Performance")
        self._row(f, "LDAP Page Size:", DE, textvariable=self._page_size_var, width=12)
        self._row(f, "Threads:", DE, textvariable=self._threads_var, width=12)

        self._div(f)
        self._sec(f, "Thresholds")
        self._row(f, "Dormant Account Days:", DE, textvariable=self._dormant_var, width=12)
        self._row(f, "Password Age Days:", DE, textvariable=self._pw_age_var, width=12)

        self._div(f)
        self._sec(f, "Flags")
        for text, var in [
            ("Only collect enabled objects  (--only-enabled)", self._only_enabled_var),
            ("Skip Excel report generation  (--no-excel)",     self._no_excel_var),
            ("Verbose output  (-v)",                            self._verbose_var),
        ]:
            r = tk.Frame(f, bg=C["surface"])
            r.pack(anchor="w", pady=2)
            ttk.Checkbutton(r, text=text, variable=var).pack(side="left")

    # ── Modules tab ────────────────────────────────────────────────────────────

    def _build_mods(self):
        f = self._tab_mods

        tk.Label(f, text="Select modules to collect — leave all unchecked to run ALL",
                 bg=C["surface"], fg=C["text_muted"], font=FONT_SMALL
                 ).pack(anchor="w")
        tk.Label(f, text="🛑 Requires admin   ⚡ Beta",
                 bg=C["surface"], fg=C["text_dim"], font=FONT_SMALL
                 ).pack(anchor="w", pady=(2, 8))

        btn_row = tk.Frame(f, bg=C["surface"])
        btn_row.pack(anchor="w", pady=(0, 8))
        DB(btn_row, text="Select All", pady=4, padx=10,
           command=lambda: self._set_all_mods(True)).pack(side="left", padx=(0, 6))
        DB(btn_row, primary=False, text="Deselect All", pady=4, padx=10,
           command=lambda: self._set_all_mods(False)).pack(side="left")

        # Scrollable canvas
        outer = tk.Frame(f, bg=C["surface"])
        outer.pack(fill="both", expand=True)

        cv = tk.Canvas(outer, bg=C["surface"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(cv, bg=C["surface"])
        wid = cv.create_window((0, 0), window=inner, anchor="nw")

        def _on_resize(e):
            cv.configure(scrollregion=cv.bbox("all"))
            cv.itemconfig(wid, width=e.width)

        cv.bind("<Configure>", _on_resize)
        cv.bind("<MouseWheel>",
                lambda e: cv.yview_scroll(-1*(e.delta//120), "units"))

        self._module_vars: dict[str, tk.BooleanVar] = {}
        COLS = 3
        col = row = 0

        for key, label in ALL_MODULES:
            if key is None:
                tk.Label(inner, text=label,
                         bg=C["surface"], fg=C["text_dim"],
                         font=FONT_SECTION, anchor="w",
                         ).grid(row=row, column=0, columnspan=COLS,
                                sticky="w", padx=8, pady=(10, 2))
                row += 1
                col = 0
            else:
                var = tk.BooleanVar(value=False)
                self._module_vars[key] = var
                ttk.Checkbutton(inner, text=label, variable=var
                                ).grid(row=row, column=col,
                                       sticky="w", padx=8, pady=2)
                col += 1
                if col >= COLS:
                    col = 0
                    row += 1

    def _set_all_mods(self, val: bool):
        for v in self._module_vars.values():
            v.set(val)

    # ── Offline Excel tab ──────────────────────────────────────────────────────

    def _build_excel(self):
        f = self._tab_excel

        tk.Label(f, text="Generate an Excel report from an existing CSV directory "
                         "— no AD connection required.",
                 bg=C["surface"], fg=C["text_muted"], font=FONT_SMALL,
                 wraplength=640, justify="left").pack(anchor="w", pady=(0, 12))

        self._sec(f, "Input")
        r = tk.Frame(f, bg=C["surface"])
        r.pack(fill="x", pady=3)
        self._csv_dir_var = tk.StringVar()
        self._lbl(r, "CSV Directory:")
        DE(r, textvariable=self._csv_dir_var).pack(side="left", fill="x", expand=True)
        DB(r, primary=False, text="Browse…", pady=5, padx=10,
           command=self._browse_csv_dir).pack(side="left", padx=(6, 0))

        self._div(f)
        self._sec(f, "Output")
        r2 = tk.Frame(f, bg=C["surface"])
        r2.pack(fill="x", pady=3)
        self._excel_out_var = tk.StringVar()
        self._lbl(r2, "Output File (.xlsx):")
        DE(r2, textvariable=self._excel_out_var).pack(side="left", fill="x", expand=True)
        DB(r2, primary=False, text="Browse…", pady=5, padx=10,
           command=self._browse_excel_out).pack(side="left", padx=(6, 0))

        self._div(f)
        DB(f, text="▶  Generate Excel",
           command=self._run_excel_mode).pack(anchor="w")

    def _browse_csv_dir(self):
        d = filedialog.askdirectory(title="Select CSV directory")
        if d:
            self._csv_dir_var.set(d)

    def _browse_excel_out(self):
        fp = filedialog.asksaveasfilename(
            title="Save Excel as",
            defaultextension=".xlsx",
            filetypes=[("Excel", "*.xlsx"), ("All", "*")],
        )
        if fp:
            self._excel_out_var.set(fp)

    # ── Layout helpers ─────────────────────────────────────────────────────────

    def _sec(self, parent, text: str):
        tk.Label(parent, text=text.upper(),
                 bg=C["surface"], fg=C["text_dim"],
                 font=FONT_SECTION).pack(anchor="w", pady=(4, 4))

    def _div(self, parent):
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", pady=10)

    def _lbl(self, parent, text: str):
        tk.Label(parent, text=text,
                 bg=C["surface"], fg=C["text_muted"],
                 font=FONT_SMALL, width=LABEL_W, anchor="w").pack(side="left")

    def _row(self, parent, label: str, widget_cls, **kw):
        r = tk.Frame(parent, bg=C["surface"])
        r.pack(fill="x", pady=3)
        self._lbl(r, label)
        w = widget_cls(r, **kw)
        w.pack(side="left", fill="x", expand=True)
        return w

    # ── Command building ───────────────────────────────────────────────────────

    def _build_command(self) -> list[str] | None:
        exe = find_pyadrecon()
        if not exe:
            messagebox.showerror(
                "Not Found",
                "pyadrecon not found on PATH.\n\n"
                "Install with:\n  pipx install pyadrecon\nor\n  pip install pyadrecon",
            )
            return None

        dc = self._dc_var.get().strip()
        if not dc:
            messagebox.showerror("Validation", "Domain Controller is required.")
            return None
        if not validate_ip_or_hostname(dc):
            messagebox.showerror("Validation",
                "Domain Controller contains invalid characters.")
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
            messagebox.showerror("Validation",
                "Domain contains invalid characters.")
            return None

        port = self._port_var.get().strip()
        if port and not port.isdigit():
            messagebox.showerror("Validation", "Port must be a number.")
            return None

        for lbl, var in [
            ("Page Size",    self._page_size_var),
            ("Dormant Days", self._dormant_var),
            ("Password Age", self._pw_age_var),
        ]:
            v = var.get().strip()
            if v and not v.isdigit():
                messagebox.showerror("Validation", f"{lbl} must be a number.")
                return None

        threads = self._threads_var.get().strip()
        if threads and not threads.isdigit():
            messagebox.showerror("Validation", "Threads must be a number.")
            return None

        auth    = self._auth_var.get()
        tgt_b64 = self._tgt_b64_var.get().strip()
        if auth == "kerberos" and tgt_b64 and not validate_base64(tgt_b64):
            messagebox.showerror("Validation",
                "TGT Base64 string is not valid base64.")
            return None

        cmd = [sys.executable, exe] if exe.endswith(".py") else [exe]
        cmd += ["-dc", dc, "-u", username, "-d", domain]

        pw = self._password_var.get()
        if pw:
            cmd += ["-p", pw]

        if auth == "kerberos":
            cmd += ["--auth", "kerberos"]
            tgt_file = self._tgt_file_var.get().strip()
            if tgt_file:
                cmd += ["--tgt-file", tgt_file]
            elif tgt_b64:
                cmd += ["--tgt-base64", tgt_b64]

        if self._ssl_var.get():
            cmd.append("--ssl")
        if port and port != "389":
            cmd += ["--port", port]

        out = self._output_dir_var.get().strip()
        if out:
            cmd += ["-o", out]

        ps = self._page_size_var.get().strip()
        if ps and ps != "500":
            cmd += ["--page-size", ps]
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

        ws = self._workstation_var.get().strip()
        if ws and auth == "ntlm":
            cmd += ["--workstation", ws]

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

        # Sanitised preview (mask password)
        preview = " ".join(
            "●●●●" if prev in ("-p", "--password") else a
            for prev, a in zip([""] + cmd, cmd)
        )
        self._cmd_var.set(preview)
        self._clear_log()
        self._log(f"$ {preview}\n\n", "dim")
        self._set_running(True)
        threading.Thread(target=self._run_thread, args=(cmd,), daemon=True).start()

    def _run_excel_mode(self):
        csv_dir = self._csv_dir_var.get().strip()
        if not csv_dir or not Path(csv_dir).is_dir():
            messagebox.showerror("Validation",
                "Please select a valid CSV directory.")
            return
        exe = find_pyadrecon()
        if not exe:
            messagebox.showerror("Not Found", "pyadrecon not found on PATH.")
            return

        cmd = [sys.executable, exe] if exe.endswith(".py") else [exe]
        cmd += ["--generate-excel-from", csv_dir]
        xl_out = self._excel_out_var.get().strip()
        if xl_out:
            cmd += ["-o", xl_out]

        self._clear_log()
        self._log(f"$ {' '.join(cmd)}\n\n", "dim")
        self._set_running(True)
        threading.Thread(target=self._run_thread, args=(cmd,), daemon=True).start()

    def _run_thread(self, cmd: list[str]):
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=False,          # SECURITY: never True
            )
            for line in self._process.stdout:
                lo = line.lower()
                if any(w in lo for w in ("error", "fail", "exception", "traceback")):
                    tag = "err"
                elif any(w in lo for w in ("warn", "warning")):
                    tag = "warn"
                elif any(w in lo for w in ("success", "done", "finish", "complete")):
                    tag = "ok"
                else:
                    tag = None
                self._log(line, tag)
            self._process.wait()
            rc = self._process.returncode
            self._log(
                f"\n{'✅' if rc == 0 else '❌'}  Exited with code {rc}.\n",
                "ok" if rc == 0 else "err",
            )
        except FileNotFoundError as e:
            self._log(f"\n❌  {e}\n", "err")
        except Exception as e:
            self._log(f"\n❌  Unexpected error: {e}\n", "err")
        finally:
            self._process = None
            self.after(0, lambda: self._set_running(False))

    def _stop(self):
        if self._process:
            self._process.terminate()
            self._log("\n⚠  Process terminated by user.\n", "warn")

    def _set_running(self, running: bool):
        self._running = running
        if running:
            self._run_btn.config(state="disabled")
            self._stop_btn.config(state="normal")
            self._status_var.set("Running…")
            self._status_dot.config(fg=C["success"])
        else:
            self._run_btn.config(state="normal")
            self._stop_btn.config(state="disabled")
            self._status_var.set("Idle")
            self._status_dot.config(fg=C["text_dim"])

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

    # ── Exit ───────────────────────────────────────────────────────────────────

    def _on_close(self):
        if self._running:
            if not messagebox.askyesno("Exit",
                    "A scan is running. Terminate and exit?"):
                return
            self._stop()
        self._password_var.set("")
        self._tgt_b64_var.set("")
        self.destroy()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = PyADReconGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
