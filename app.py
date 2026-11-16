"""Aegis OSINT Multi-Tool Website Analyzer GUI.

Run with: python app.py
Requires: pip install -r requirements.txt
"""
from __future__ import annotations

import os
import queue
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import osint_core as core
from exporter import export_xlsx


BG = "#080D17"
SIDEBAR = "#0B1220"
SURFACE = "#111B2B"
SURFACE2 = "#162235"
BORDER = "#263449"
TEXT = "#F1F5F9"
MUTED = "#94A3B8"
ACCENT = "#38BDF8"
GREEN = "#22C55E"
RED = "#EF4444"
FONT = "Segoe UI"

# Build the API-key form directly from the provider registry in osint_core.py.
# This keeps the GUI in sync with the actual providers used during analysis.
KEY_ENV = {name: config[1] for name, config in core.PROVIDERS.items()}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aegis | OSINT Intelligence Workbench")
        self.geometry("1280x820")
        self.minsize(950, 650)
        self.configure(bg=BG)

        self.events = queue.Queue()
        self.report = None
        self.busy = False
        self.key_vars = {}
        self.page_frames = {}
        self.nav_buttons = {}

        self._configure_style()
        self._build_shell()
        self.show_page("overview")
        self.after(100, self._poll_events)

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=(FONT, 10))
        style.configure("TEntry", fieldbackground="#0C1626", foreground=TEXT,
                        insertcolor=TEXT, padding=8)
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                        foreground=TEXT, rowheight=30, borderwidth=0, font=(FONT, 9))
        style.configure("Treeview.Heading", background=SURFACE2, foreground=TEXT,
                        font=(FONT, 9, "bold"), padding=8)
        style.map("Treeview", background=[("selected", "#16415B")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SURFACE2, foreground=MUTED,
                        padding=(12, 8), font=(FONT, 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", SURFACE)],
                  foreground=[("selected", ACCENT)])
        style.configure("TProgressbar", troughcolor=SURFACE2, background=ACCENT)
        style.configure("TButton", font=(FONT, 9, "bold"), padding=(12, 8))
        style.map("TButton", background=[("active", "#0EA5E9")])

    def _label(self, parent, text, size=10, color=TEXT, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", SURFACE), fg=color,
                        font=(FONT, size, "bold" if bold else "normal"), **kwargs)

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg=SURFACE, highlightthickness=1,
                        highlightbackground=BORDER, bd=0, **kwargs)

    def _button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command, cursor="hand2",
            bg=ACCENT if primary else SURFACE2,
            fg="#06111D" if primary else TEXT,
            activebackground="#0EA5E9" if primary else "#263449",
            activeforeground=TEXT, relief="flat", bd=0,
            padx=16, pady=9, font=(FONT, 9, "bold")
        )

    def _build_shell(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        side = tk.Frame(self, bg=SIDEBAR, width=225)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        brand = tk.Frame(side, bg=SIDEBAR, padx=20, pady=24)
        brand.pack(fill="x")
        self._label(brand, "◈  AEGIS", 18, ACCENT, True, bg=SIDEBAR).pack(anchor="w")
        self._label(brand, "INTELLIGENCE WORKBENCH", 8, MUTED, True, bg=SIDEBAR).pack(anchor="w", pady=(4, 0))

        self._label(side, "WORKSPACE", 8, MUTED, True, bg=SIDEBAR).pack(anchor="w", padx=20, pady=(28, 10))
        for key, title in [
            ("overview", "Overview"),
            ("investigation", "New investigation"),
            ("results", "Intelligence results"),
            ("activity", "Activity log"),
            ("providers", "API providers"),
        ]:
            btn = tk.Button(side, text=title, anchor="w", command=lambda k=key: self.show_page(k),
                            bg=SIDEBAR, fg=MUTED, activebackground=SURFACE2,
                            activeforeground=TEXT, relief="flat", bd=0,
                            padx=20, pady=12, font=(FONT, 10), cursor="hand2")
            btn.pack(fill="x", padx=8, pady=2)
            self.nav_buttons[key] = btn

        foot = tk.Frame(side, bg=SIDEBAR, padx=18, pady=18)
        foot.pack(side="bottom", fill="x")
        self._label(foot, "PASSIVE RESEARCH MODE", 8, GREEN, True, bg=SIDEBAR).pack(anchor="w")
        self._label(foot, "Third-party API lookups only", 8, MUTED, bg=SIDEBAR).pack(anchor="w", pady=(5, 0))

        self.main = tk.Frame(self, bg=BG, padx=26, pady=22)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        self.header = tk.Frame(self.main, bg=BG)
        self.header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        self.page_title = self._label(self.header, "Overview", 21, TEXT, True, bg=BG)
        self.page_title.pack(anchor="w")
        self.page_subtitle = self._label(self.header, "OSINT website analysis dashboard", 9, MUTED, bg=BG)
        self.page_subtitle.pack(anchor="w", pady=(4, 0))

        self.content = tk.Frame(self.main, bg=BG)
        self.content.grid(row=1, column=0, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self._build_overview()
        self._build_investigation()
        self._build_results()
        self._build_activity()
        self._build_providers()

    def _build_overview(self):
        page = tk.Frame(self.content, bg=BG)
        self.page_frames["overview"] = page
        card = self._card(page, padx=24, pady=24)
        card.pack(fill="x", pady=(0, 16))
        self._label(card, "Website intelligence, in one workspace", 17, TEXT, True).pack(anchor="w")
        self._label(card, "Compare findings from five passive OSINT providers and export an evidence workbook.",
                    10, MUTED, wraplength=800, justify="left").pack(anchor="w", pady=(9, 18))
        self._button(card, "Start an investigation", lambda: self.show_page("investigation"), True).pack(anchor="w")

        grid = tk.Frame(page, bg=BG)
        grid.pack(fill="x")
        items = [
            (str(len(core.PROVIDERS)), "OSINT providers"),
            ("12", "Comparison attributes"),
            ("5", "Excel report sheets"),
        ]
        for i, (value, label) in enumerate(items):
            c = self._card(grid, padx=18, pady=18)
            c.grid(row=0, column=i, sticky="ew", padx=(0, 12))
            grid.grid_columnconfigure(i, weight=1)
            self._label(c, value, 24, ACCENT, True).pack(anchor="w")
            self._label(c, label, 9, MUTED).pack(anchor="w", pady=(5, 0))

        note = self._card(page, padx=18, pady=16)
        note.pack(fill="x", pady=16)
        self._label(note, "Important", 10, GREEN, True).pack(anchor="w")
        self._label(note, "Use only domains you are authorised to research. Results are provider outputs, not independently verified facts.",
                    9, MUTED, wraplength=850, justify="left").pack(anchor="w", pady=(6, 0))

    def _build_investigation(self):
        page = tk.Frame(self.content, bg=BG)
        self.page_frames["investigation"] = page
        card = self._card(page, padx=20, pady=20)
        card.pack(fill="x")
        self._label(card, "Target website or domain", 11, TEXT, True).pack(anchor="w")
        self.target_var = tk.StringVar()
        entry = ttk.Entry(card, textvariable=self.target_var, font=(FONT, 11))
        entry.pack(fill="x", pady=(8, 14), ipady=4)
        entry.bind("<Return>", lambda _e: self.start_analysis())
        row = tk.Frame(card, bg=SURFACE)
        row.pack(fill="x")
        self.run_button = self._button(row, "Analyze target", self.start_analysis, True)
        self.run_button.pack(side="left")
        self._button(row, "Open API providers", lambda: self.show_page("providers")).pack(side="left", padx=9)
        self.progress = ttk.Progressbar(card, mode="indeterminate")
        self.progress.pack(fill="x", pady=(18, 5))
        self.status_var = tk.StringVar(value="Ready. Enter a domain to begin.")
        self._label(card, "", 9, MUTED).pack_forget()
        tk.Label(card, textvariable=self.status_var, bg=SURFACE, fg=MUTED,
                 font=(FONT, 9), anchor="w").pack(fill="x")

        hint = self._card(page, padx=18, pady=16)
        hint.pack(fill="x", pady=16)
        self._label(hint, "Before you begin", 10, TEXT, True).pack(anchor="w")
        self._label(hint, "Add API keys on the API providers page. Providers without keys are safely skipped. DNS resolution is performed locally; provider lookups are sent to their respective APIs.",
                    9, MUTED, wraplength=850, justify="left").pack(anchor="w", pady=(7, 0))

    def _build_results(self):
        page = tk.Frame(self.content, bg=BG)
        self.page_frames["results"] = page
        top = tk.Frame(page, bg=BG)
        top.pack(fill="x", pady=(0, 12))
        self.result_target = tk.StringVar(value="No analysis has been run yet.")
        tk.Label(top, textvariable=self.result_target, bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(side="left")
        self._button(top, "Export Excel", self.export_report, True).pack(side="right")

        wrap = self._card(page, padx=10, pady=10)
        wrap.pack(fill="both", expand=True)
        columns = ("attribute",) + tuple(core.PROVIDERS.keys())
        self.tree = ttk.Treeview(wrap, columns=columns, show="headings")
        self.tree.heading("attribute", text="Attribute")
        self.tree.column("attribute", width=210, minwidth=160, stretch=False)
        for name in core.PROVIDERS:
            self.tree.heading(name, text=name)
            self.tree.column(name, width=190, minwidth=130, stretch=True)
        yscroll = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.pack(side="top", fill="both", expand=True)
        xscroll.pack(side="bottom", fill="x")
        yscroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self.show_selected_detail)

    def _build_activity(self):
        page = tk.Frame(self.content, bg=BG)
        self.page_frames["activity"] = page
        card = self._card(page, padx=14, pady=14)
        card.pack(fill="both", expand=True)
        self.log = tk.Text(card, bg="#0C1626", fg=TEXT, insertbackground=TEXT,
                           relief="flat", wrap="word", font=("Consolas", 9), padx=12, pady=12)
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")
        self._log("Aegis initialized. Waiting for an investigation.")

    def _build_providers(self):
        page = tk.Frame(self.content, bg=BG)
        self.page_frames["providers"] = page

        intro = self._card(page, padx=18, pady=14)
        intro.pack(fill="x", pady=(0, 10))
        self._label(intro, "API provider configuration", 13, TEXT, True).pack(anchor="w")
        self._label(
            intro,
            f"{len(KEY_ENV)} providers loaded from osint_core.py. Paste your API keys below.",
            9, MUTED
        ).pack(anchor="w", pady=(5, 0))

        # Put provider cards in a scrollable area so the last provider cannot
        # be hidden below the bottom edge of smaller screens.
        scroll_area = tk.Frame(page, bg=BG)
        scroll_area.pack(fill="both", expand=True)
        canvas = tk.Canvas(scroll_area, bg=BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(scroll_area, orient="vertical", command=canvas.yview)
        cards_frame = tk.Frame(canvas, bg=BG)

        cards_window = canvas.create_window((0, 0), window=cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def update_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def fit_cards_width(event):
            canvas.itemconfigure(cards_window, width=event.width)

        cards_frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", fit_cards_width)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for name, env_name in KEY_ENV.items():
            row = self._card(cards_frame, padx=14, pady=9)
            row.pack(fill="x", pady=4, padx=(0, 8))
            self._label(row, name, 10, TEXT, True).pack(anchor="w")
            var = tk.StringVar(value=os.getenv(env_name, ""))
            self.key_vars[name] = var
            ent = ttk.Entry(row, textvariable=var, show="•")
            ent.pack(fill="x", pady=(6, 0), ipady=3)
            ent.bind("<FocusIn>", lambda _e, w=ent: w.configure(show=""))
            ent.bind("<FocusOut>", lambda _e, w=ent: w.configure(show="•"))

        actions = tk.Frame(cards_frame, bg=BG)
        actions.pack(fill="x", pady=(7, 12), padx=(0, 8))
        self._button(actions, "Save keys for this session", self.save_keys, True).pack(side="left")
        self._label(
            actions,
            "For persistent configuration, add these variables to a local .env file.",
            9, MUTED, wraplength=600, justify="left", bg=BG
        ).pack(side="left", padx=12)

        # Mouse-wheel scrolling (Windows and Linux).
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))

    def show_page(self, name):
        for frame in self.page_frames.values():
            frame.grid_forget()
        self.page_frames[name].grid(row=0, column=0, sticky="nsew")
        titles = {
            "overview": ("Overview", "OSINT website analysis dashboard"),
            "investigation": ("New investigation", "Run a passive multi-provider lookup"),
            "results": ("Intelligence results", "Compare normalized provider findings"),
            "activity": ("Activity log", "Progress and diagnostic messages"),
            "providers": ("API providers", "Configure provider credentials"),
        }
        self.page_title.configure(text=titles[name][0])
        self.page_subtitle.configure(text=titles[name][1])
        for key, btn in self.nav_buttons.items():
            btn.configure(fg=ACCENT if key == name else MUTED,
                          bg="#13263A" if key == name else SIDEBAR)

    def save_keys(self):
        for name, env_name in KEY_ENV.items():
            os.environ[env_name] = self.key_vars[name].get().strip()
        self._log("API keys updated for this application session.")
        messagebox.showinfo("API providers", "API keys saved for this session.")

    def start_analysis(self):
        if self.busy:
            return
        target = self.target_var.get().strip()
        try:
            core.normalise_target(target)
        except ValueError as exc:
            messagebox.showwarning("Invalid target", str(exc))
            return

        keys = {name: var.get().strip() for name, var in self.key_vars.items()}
        self.busy = True
        self.run_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Analysis running…")
        self._log(f"Starting analysis for {target}")
        self.show_page("investigation")

        def worker():
            try:
                report = core.analyse(target, keys, progress=lambda msg: self.events.put(("log", msg)))
                self.events.put(("complete", report))
            except Exception:
                self.events.put(("fatal", traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._log(payload)
                    self.status_var.set(payload)
                elif kind == "complete":
                    self.report = payload
                    self.busy = False
                    self.progress.stop()
                    self.run_button.configure(state="normal")
                    self.status_var.set("Analysis completed.")
                    self.result_target.set(f"Target: {payload['target']}  |  Collected: {payload['collected_utc']}")
                    self._populate_results()
                    self._log("Analysis completed successfully.")
                    self.show_page("results")
                elif kind == "fatal":
                    self.busy = False
                    self.progress.stop()
                    self.run_button.configure(state="normal")
                    self.status_var.set("Analysis failed. See Activity log.")
                    self._log(payload)
                    messagebox.showerror("Analysis failed", "The analysis could not be completed. See Activity log for details.")
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _populate_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        header, rows = core.comparison_rows(self.report)
        for row in rows:
            values = [str(value) for value in row]
            self.tree.insert("", "end", values=values)

    def show_selected_detail(self, _event=None):
        selection = self.tree.selection()
        if not selection or not self.report:
            return
        values = self.tree.item(selection[0], "values")
        messagebox.showinfo(str(values[0]), "\n\n".join(
            f"{name}: {values[i + 1]}" for i, name in enumerate(core.PROVIDERS)
        ))

    def export_report(self):
        if not self.report:
            messagebox.showinfo("Export", "Run an analysis before exporting.")
            return
        path = filedialog.asksaveasfilename(
            title="Save OSINT report",
            defaultextension=".xlsx",
            filetypes=[("Excel workbook", "*.xlsx")],
            initialfile="osint_analysis_report.xlsx",
        )
        if not path:
            return
        try:
            export_xlsx(self.report, path)
            self._log(f"Excel report exported: {path}")
            messagebox.showinfo("Export complete", f"Report saved successfully:\n{path}")
        except Exception as exc:
            self._log(f"Export error: {type(exc).__name__}: {exc}")
            messagebox.showerror("Export failed", str(exc))

    def _log(self, message):
        if not hasattr(self, "log"):
            return
        self.log.configure(state="normal")
        self.log.insert("end", str(message) + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")


def main():
    try:
        app = App()
        app.mainloop()
    except Exception:
        # Keep startup errors visible when launched from a terminal.
        traceback.print_exc()
        try:
            input("The application encountered an error. Press Enter to close...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
