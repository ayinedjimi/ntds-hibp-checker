"""
Interface graphique (CustomTkinter) du NTDS HIBP Checker.

Soigne les microinteractions : effets de survol, barre de progression animee
et lissee, pulsation pendant l'extraction, apparition en fondu des resultats,
compteurs animes.

Auteur : Ayi NEDJIMI Consultants - https://ayinedjimi-consultants.fr
"""

from __future__ import annotations

import json
import math
import os
import queue
import struct
import sys
import tempfile
import threading
import time
import webbrowser
from typing import Optional

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:                                   # glisser-deposer (Windows, optionnel)
    import windnd
    _HAS_DND = True
except Exception:                      # pragma: no cover
    _HAS_DND = False

from . import __app_name__, __author__, __url__, __version__
from .analyzer import (Analyzer, AnalysisReport, Phase, Progress)
from .downloader import download_hibp_ntlm
from .extractor import CancelledError
from .report import (UNIQUE_COLOR, reuse_distribution, to_csv, to_html,
                     to_json)
from .security import SECURITY_WARNINGS, sdelete_command, secure_delete

# ----------------------------- Theme ------------------------------------- #
ACCENT = "#2563eb"
ACCENT_HOVER = "#1d4ed8"
DANGER = "#dc2626"
DANGER_HOVER = "#b91c1c"
WARN = "#d97706"
OK = "#16a34a"
BG_CARD = ("#ffffff", "#1b1d23")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def resource_dir() -> str:
    """Dossier de l'exe (PyInstaller) ou du script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.getcwd()


def search_bases() -> list:
    """Dossiers fouilles au lancement : dossier de l'exe ET dossier courant."""
    bases = []
    for b in (resource_dir(), os.getcwd()):
        if b and b not in bases:
            bases.append(b)
    return bases


def autodetect(filename_options, subdirs=("", "Active Directory", "registry")):
    """Cherche un fichier par nom exact dans le(s) dossier(s) de lancement."""
    wanted = [f.lower() for f in filename_options]
    for base in search_bases():
        for sub in subdirs:
            d = os.path.join(base, sub) if sub else base
            if not os.path.isdir(d):
                continue
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for name in entries:
                if name.lower() in wanted:
                    return os.path.join(d, name)
    return ""


# Indices de nom pour reconnaitre un fichier de hash HIBP NTLM telecharge.
_HIBP_NAME_HINTS = ("ntlm", "pwnedpasswords", "pwned-passwords",
                    "pwned_passwords")
_HIBP_EXCLUDE_EXT = (".exe", ".py", ".pyc", ".zip", ".7z", ".rar", ".gz",
                     ".log", ".md", ".dll")


def autodetect_hibp(subdirs=("", "hibp", "HIBP", "pwnedpasswords")):
    """Cherche un fichier HIBP NTLM (par motif de nom) dans le(s) dossier(s)
    de lancement. En cas de plusieurs candidats, retient le plus volumineux
    (le vrai fichier de hash fait plusieurs Go)."""
    candidates = []
    for base in search_bases():
        for sub in subdirs:
            d = os.path.join(base, sub) if sub else base
            if not os.path.isdir(d):
                continue
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for name in entries:
                low = name.lower()
                if not any(h in low for h in _HIBP_NAME_HINTS):
                    continue
                if low.endswith(_HIBP_EXCLUDE_EXT):
                    continue
                path = os.path.join(d, name)
                if not os.path.isfile(path):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                candidates.append((size, path))
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1]
    return ""


class Tooltip:
    """Info-bulle legere avec apparition/disparition en fondu.

    Independante de CustomTkinter : s'attache a n'importe quel widget Tk via
    les evenements <Enter>/<Leave> (add='+' pour ne pas ecraser les binds
    existants). L'opacite est animee a ~60 fps pour un rendu fluide.
    """

    _OPEN = None  # une seule info-bulle visible a la fois

    def __init__(self, widget, text: str, delay: int = 450):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tip: Optional[tk.Toplevel] = None
        self._after_id = None
        self._fade_id = None
        self._alpha = 0.0
        self._dir = 0
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _=None):
        self._cancel_timer()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel_timer(self):
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self):
        if self._tip is not None or not self.text:
            return
        # fermer une eventuelle bulle deja ouverte ailleurs
        if Tooltip._OPEN is not None and Tooltip._OPEN is not self:
            Tooltip._OPEN._hide()
        Tooltip._OPEN = self
        x = self.widget.winfo_pointerx() + 16
        y = self.widget.winfo_pointery() + 20
        self._tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        try:
            tw.attributes("-alpha", 0.0)
            tw.attributes("-topmost", True)
        except Exception:
            pass
        # widgets Tk purs (pas de CustomTkinter) : evite que le tracker DPI de
        # CTk s'attache a ce Toplevel ephemere. Le fond du Toplevel sert de
        # bordure fine de 1 px autour du cadre interieur.
        tw.configure(bg="#334155")
        frame = tk.Frame(tw, bg="#0f172a")
        frame.pack(padx=1, pady=1)
        tk.Label(frame, text=self.text, justify="left", wraplength=340,
                 bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9),
                 padx=11, pady=7).pack()
        self._alpha = 0.0
        self._set_direction(+1)

    def _set_direction(self, direction: int):
        """(Re)lance le fondu dans un sens donne, en annulant celui en cours
        pour eviter que les chaines d'entree et de sortie se concurrencent."""
        self._dir = direction
        self._cancel_fade()
        self._fade()

    def _cancel_fade(self):
        if self._fade_id is not None and self._tip is not None:
            try:
                self._tip.after_cancel(self._fade_id)
            except Exception:
                pass
        self._fade_id = None

    def _fade(self):
        if self._tip is None:
            return
        self._alpha = max(0.0, min(0.97, self._alpha + self._dir * 0.16))
        try:
            self._tip.attributes("-alpha", self._alpha)
        except Exception:
            pass
        if self._dir > 0 and self._alpha < 0.97:
            self._fade_id = self._tip.after(12, self._fade)
        elif self._dir < 0 and self._alpha > 0.0:
            self._fade_id = self._tip.after(12, self._fade)
        elif self._dir < 0:
            self._destroy()

    def _hide(self, _=None):
        self._cancel_timer()
        if self._tip is not None:
            self._set_direction(-1)   # disparition en fondu

    def _destroy(self):
        self._cancel_fade()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None
        if Tooltip._OPEN is self:
            Tooltip._OPEN = None


def attach_tooltip(widgets, text: str):
    """Attache la meme info-bulle a un ou plusieurs widgets."""
    if not isinstance(widgets, (list, tuple)):
        widgets = [widgets]
    for w in widgets:
        Tooltip(w, text)


# --------------------------------------------------------------------------- #
#  Persistance des preferences (taille fenetre, theme...)
# --------------------------------------------------------------------------- #
CONFIG_PATH = os.path.join(os.path.expanduser("~"),
                           ".ntds_hibp_checker.json")


def load_config() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  Generation d'une icone .ico (32x32) sans dependance externe
# --------------------------------------------------------------------------- #
def make_app_icon() -> Optional[str]:
    """Cree une petite icone (bouclier bleu + coche) et renvoie son chemin."""
    size = 32
    accent = (0x25, 0x63, 0xeb)        # RGB de ACCENT

    def _seg_dist(px, py, ax, ay, bx, by):
        dx, dy = bx - ax, by - ay
        if dx == dy == 0:
            return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
        t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy)
                         / (dx * dx + dy * dy)))
        return ((px - (ax + t * dx)) ** 2 + (py - (ay + t * dy)) ** 2) ** 0.5

    def pixel(x, y):
        r = 7
        inside = (r <= x <= size - 1 - r or r <= y <= size - 1 - r or
                  ((x - r) ** 2 + (y - r) ** 2 <= r * r) or
                  ((x - (size - 1 - r)) ** 2 + (y - r) ** 2 <= r * r) or
                  ((x - r) ** 2 + (y - (size - 1 - r)) ** 2 <= r * r) or
                  ((x - (size - 1 - r)) ** 2 +
                   (y - (size - 1 - r)) ** 2 <= r * r))
        if not (1 <= x <= size - 2 and 1 <= y <= size - 2 and inside):
            return (0, 0, 0, 0)
        check = min(_seg_dist(x, y, 9, 17, 14, 22),
                    _seg_dist(x, y, 14, 22, 23, 10))
        if check <= 1.7:
            return (255, 255, 255, 255)
        return (accent[0], accent[1], accent[2], 255)

    # XOR (BGRA, bottom-up)
    xor = bytearray()
    for yy in range(size):
        y = size - 1 - yy
        for x in range(size):
            r, g, b, a = pixel(x, y)
            xor += bytes((b, g, r, a))
    and_mask = bytes(4 * size)          # 32-bit -> masque tout opaque (0)

    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         len(xor) + len(and_mask), 0, 0, 0, 0)
    img = header + bytes(xor) + and_mask
    icondir = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32,
                        len(img), 6 + 16)
    try:
        path = os.path.join(tempfile.gettempdir(), "ntds_hibp_checker.ico")
        with open(path, "wb") as fh:
            fh.write(icondir + entry + img)
        return path
    except Exception:
        return None


# Police bitmap 5x7 minimale pour le titre du splash.
_FONT5x7 = {
    " ": ["00000"] * 7,
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
}


def make_splash_png(path: str, w: int = 480, h: int = 270) -> Optional[str]:
    """Genere l'image du splash (logo bouclier + coche + titre) en PNG
    pur-Python (zlib) — sert au splash natif PyInstaller."""
    import zlib
    accent = (0x25, 0x63, 0xeb)
    bg = (0x0f, 0x17, 0x2a)
    white = (0xe2, 0xe8, 0xf0)
    cx, cy, S, r = w // 2, 82, 96, 20
    half = S / 2
    grid = [[bg for _ in range(w)] for _ in range(h)]

    def seg(px, py, ax, ay, bx, by):
        dx, dy = bx - ax, by - ay
        if dx == dy == 0:
            return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
        t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy)
                         / (dx * dx + dy * dy)))
        return ((px - (ax + t * dx)) ** 2 + (py - (ay + t * dy)) ** 2) ** 0.5

    # bouclier + coche
    for y in range(int(cy - half), int(cy + half) + 1):
        for x in range(int(cx - half), int(cx + half) + 1):
            lx, ly = x - (cx - half), y - (cy - half)
            rounded = (r <= lx <= S - r or r <= ly <= S - r or
                       (lx - r) ** 2 + (ly - r) ** 2 <= r * r or
                       (lx - (S - r)) ** 2 + (ly - r) ** 2 <= r * r or
                       (lx - r) ** 2 + (ly - (S - r)) ** 2 <= r * r or
                       (lx - (S - r)) ** 2 + (ly - (S - r)) ** 2 <= r * r)
            if rounded and 0 <= x < w and 0 <= y < h:
                d = min(seg(lx, ly, S * 0.30, S * 0.52, S * 0.45, S * 0.68),
                        seg(lx, ly, S * 0.45, S * 0.68, S * 0.72, S * 0.32))
                grid[y][x] = (0xff, 0xff, 0xff) if d <= S * 0.06 else accent

    def text(s, top, scale, color):
        gw = (len(s) * 6 - 1) * scale
        x0 = (w - gw) // 2
        for i, ch in enumerate(s):
            glyph = _FONT5x7.get(ch, _FONT5x7[" "])
            for ry, bits in enumerate(glyph):
                for rx, b in enumerate(bits):
                    if b == "1":
                        for dy in range(scale):
                            for dx in range(scale):
                                px = x0 + (i * 6 + rx) * scale + dx
                                py = top + ry * scale + dy
                                if 0 <= px < w and 0 <= py < h:
                                    grid[py][px] = color

    text("NTDS HIBP CHECKER", 150, 4, white)
    # barre d'accent sous le titre
    for y in range(208, 213):
        for x in range((w - 240) // 2, (w + 240) // 2):
            grid[y][x] = accent

    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            c = grid[y][x]
            row += bytes((c[0], c[1], c[2], 255))
        rows.append(bytes(row))
    raw = b"".join(b"\x00" + rr for rr in rows)
    comp = zlib.compress(raw, 9)

    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data +
                struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))

    png = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
           chunk(b"IDAT", comp) + chunk(b"IEND", b""))
    try:
        with open(path, "wb") as fh:
            fh.write(png)
        return path
    except Exception:
        return None


class FileSelector(ctk.CTkFrame):
    """Champ de selection de fichier avec bouton Parcourir anime."""

    def __init__(self, master, label, default="", tooltip: str = "", **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(1, weight=1)
        self.label = ctk.CTkLabel(self, text=label, width=140, anchor="w",
                                  font=ctk.CTkFont(size=12, weight="bold"))
        self.label.grid(row=0, column=0, padx=(0, 8), pady=4, sticky="w")
        self.var = ctk.StringVar(value=default)
        self.entry = ctk.CTkEntry(self, textvariable=self.var,
                                  placeholder_text="Aucun fichier selectionne")
        self.entry.grid(row=0, column=1, padx=(0, 8), pady=4, sticky="ew")
        self.btn = ctk.CTkButton(self, text="Parcourir", width=100,
                                 command=self._browse,
                                 fg_color=ACCENT, hover_color=ACCENT_HOVER)
        self.btn.grid(row=0, column=2, pady=4)
        # indicateur d'etat : vert si le fichier existe, rouge s'il est saisi
        # mais introuvable. Met a jour automatiquement (detection, saisie...).
        self.status = ctk.CTkLabel(self, text="", width=18,
                                   font=ctk.CTkFont(size=16, weight="bold"))
        self.status.grid(row=0, column=3, padx=(6, 0))
        self.var.trace_add("write", lambda *a: self._update_status())
        self._update_status()
        self._enable_drop()
        if tooltip:
            tip = tooltip + ("  (Astuce : glissez-deposez le fichier ici.)"
                             if _HAS_DND else "")
            attach_tooltip([self.label, self.entry], tip)
            attach_tooltip(self.btn, "Parcourir pour choisir le fichier")

    def _update_status(self):
        p = self.var.get().strip()
        if p and os.path.isfile(p):
            self.status.configure(text="✓", text_color="#22c55e")
        elif p:
            self.status.configure(text="✗", text_color="#ef4444")
        else:
            self.status.configure(text="")

    # -- glisser-deposer de fichiers (Windows) -- #
    def _enable_drop(self):
        if not _HAS_DND:
            return
        try:
            windnd.hook_dropfiles(self.entry, func=self._on_drop)
        except Exception:
            pass

    def _on_drop(self, files):
        if not files:
            return
        raw = files[0]
        path = None
        if isinstance(raw, bytes):
            for enc in ("utf-8", "mbcs", "latin-1"):
                try:
                    path = raw.decode(enc)
                    break
                except Exception:
                    continue
        else:
            path = str(raw)
        if not path:
            return
        self.var.set(path.strip().strip('"'))
        self._flash_ok()

    def _flash_ok(self):
        """Flash vert bref du champ pour confirmer le depot."""
        try:
            orig = self.entry.cget("border_color")
            self.entry.configure(border_color="#22c55e")
            self.after(650, lambda: self.entry.configure(border_color=orig))
        except Exception:
            pass

    def _browse(self):
        path = filedialog.askopenfilename(title="Selectionner un fichier")
        if path:
            self.var.set(path)

    def get(self) -> str:
        return self.var.get().strip()

    def set(self, value: str):
        self.var.set(value)


class App(ctk.CTk):
    FRAME_MS = 16        # ~60 fps pour des animations fluides

    def __init__(self):
        super().__init__()
        self._config = load_config()
        mode = self._config.get("appearance", "dark")
        if mode in ("dark", "light"):
            ctk.set_appearance_mode(mode)
        self.title(f"{__app_name__} v{__version__} - {__author__}")
        self._apply_initial_geometry()
        # icone generee a la volee (best effort)
        try:
            ico = make_app_icon()
            if ico:
                self.iconbitmap(ico)
        except Exception:
            pass

        self._queue: "queue.Queue" = queue.Queue()
        self._analyzer: Optional[Analyzer] = None
        self._worker: Optional[threading.Thread] = None
        self._report: Optional[AnalysisReport] = None

        # etat d'animation de la barre de progression
        self._bar_target = 0.0
        self._bar_value = 0.0
        self._last_drawn = None           # derniere valeur reellement dessinee
        self._pulse_on = False
        self._pulse_phase = 0.0
        self._risk_pulse = False          # halo pulsant sur la carte "Compromis"
        self._risk_phase = 0.0
        self._downloading = False         # telechargement de la base HIBP
        self._dl_cancel = False

        self._build_ui()
        self._build_menu()
        self._bind_shortcuts()
        self._announce_discovery()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # apparition de la fenetre en fondu + fermeture du splash natif
        try:
            self.attributes("-alpha", 0.0)
            self.after(40, self._fade_in_app)
        except Exception:
            pass
        self.after(120, self._close_splash)
        self.after(self.FRAME_MS, self._tick)   # boucle d'animation + queue

    def _close_splash(self):
        """Ferme le splash natif PyInstaller une fois l'interface affichee."""
        try:
            import pyi_splash      # fourni par PyInstaller si build --splash
            pyi_splash.update_text("Pret.")
            pyi_splash.close()
        except Exception:
            pass

    def _apply_initial_geometry(self):
        """Adapte la fenetre a la resolution ecran : taille relative, minsize
        reduit pour les petits ecrans, et geometrie sauvegardee bornee a
        l'ecran courant (evite une fenetre hors champ ou plus grande que
        l'ecran)."""
        sw = max(640, self.winfo_screenwidth())
        sh = max(480, self.winfo_screenheight())
        # marge pour la barre des taches / decorations
        avail_w, avail_h = sw - 20, sh - 70

        # minsize adaptatif (ne jamais imposer plus grand que l'ecran)
        self.minsize(min(820, avail_w), min(560, avail_h))

        geo = self._parse_geometry(self._config.get("geometry"))
        if geo:
            w, h, x, y = geo
        else:
            w = min(1040, int(sw * 0.92))
            h = min(820, int(sh * 0.92))
            x, y = (sw - w) // 2, max(0, (sh - h) // 3)
        # bornage a l'ecran
        w = max(min(w, avail_w), min(820, avail_w))
        h = max(min(h, avail_h), min(560, avail_h))
        x = min(max(0, x), max(0, sw - w))
        y = min(max(0, y), max(0, sh - h))
        self.geometry(f"{w}x{h}+{x}+{y}")
        # tres petit ecran : demarrer maximise pour tout afficher
        if sh <= 800 or sw <= 1100:
            try:
                self.state("zoomed")
            except Exception:
                pass

    @staticmethod
    def _parse_geometry(geo):
        """Parse 'WxH+X+Y' -> (w, h, x, y) ; None si invalide."""
        if not geo or "x" not in geo:
            return None
        try:
            size, _, rest = geo.partition("+")
            w, h = (int(v) for v in size.split("x"))
            x = y = 0
            if rest:
                px, _, py = rest.partition("+")
                x, y = int(px or 0), int(py or 0)
            return w, h, x, y
        except (ValueError, TypeError):
            return None

    # ----------------------------------------- menu / raccourcis / theme - #
    def _build_menu(self):
        menubar = tk.Menu(self)
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Exporter le rapport...   (Ctrl+E)",
                           command=self._export)
        m_file.add_command(label="Telecharger la base HIBP...",
                           command=self._download_hibp)
        m_file.add_separator()
        m_file.add_command(label="Quitter", command=self._on_close)
        menubar.add_cascade(label="Fichier", menu=m_file)

        m_view = tk.Menu(menubar, tearoff=0)
        m_view.add_command(label="Basculer theme clair/sombre   (Ctrl+T)",
                           command=self._toggle_theme)
        menubar.add_cascade(label="Affichage", menu=m_view)

        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="Comment recuperer ntds.dit ?   (F1)",
                           command=self._show_help)
        m_help.add_command(label="A propos", command=self._show_about)
        menubar.add_cascade(label="Aide", menu=m_help)
        try:
            self.config(menu=menubar)
        except Exception:
            pass

    def _bind_shortcuts(self):
        self.bind("<F5>", lambda e: self._shortcut_analyze())
        self.bind("<Control-Return>", lambda e: self._shortcut_analyze())
        self.bind("<Control-e>", lambda e: self._export())
        self.bind("<Control-t>", lambda e: self._toggle_theme())
        self.bind("<F1>", lambda e: self._show_help())
        self.bind("<Escape>", lambda e: self._shortcut_escape())

    def _shortcut_analyze(self):
        if str(self.btn_analyze.cget("state")) == "normal":
            self._start()

    def _shortcut_escape(self):
        if self._downloading or (self._worker and self._worker.is_alive()):
            self._cancel()

    def _apply_theme(self, mode: str):
        ctk.set_appearance_mode(mode)
        self._config["appearance"] = mode
        self._style_tree(mode)

    def _on_theme_switch(self):
        self._apply_theme("light" if bool(self.theme_switch.get()) else "dark")

    def _toggle_theme(self):
        to_light = str(ctk.get_appearance_mode()).lower() == "dark"
        if to_light:
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()
        self._apply_theme("light" if to_light else "dark")

    def _update_chip(self):
        if not hasattr(self, "chip"):
            return
        if self.mode_var.get() == "online":
            self.chip.configure(text="● API en ligne", fg_color="#1e3a8a",
                                text_color="#bfdbfe")
        elif self.sel_hibp.get() and os.path.isfile(self.sel_hibp.get()):
            self.chip.configure(text="● Base locale prete", fg_color="#064e3b",
                                text_color="#6ee7b7")
        else:
            self.chip.configure(text="● Base locale manquante",
                                fg_color="#7f1d1d", text_color="#fecaca")

    def _on_close(self):
        try:
            self._dl_cancel = True
            if self._analyzer:
                self._analyzer.cancel()
            self._config["geometry"] = self.geometry()
            self._config["appearance"] = ctk.get_appearance_mode().lower()
            save_config(self._config)
        except Exception:
            pass
        self.destroy()

    def _fade_in_app(self, alpha: float = 0.0):
        alpha = min(1.0, alpha + 0.10)
        try:
            self.attributes("-alpha", alpha)
        except Exception:
            return
        if alpha < 1.0:
            self.after(16, lambda: self._fade_in_app(alpha))

    # --------------------------------------------------------------- UI -- #
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        # la zone resultats (onglets) garde la priorite ET une hauteur minimale
        # raisonnable (sans forcer un debordement sous l'ecran).
        self.grid_rowconfigure(3, weight=1, minsize=200)

        self._build_header()
        self._build_inputs()
        self._build_progress()
        self._build_results()

    def _build_header(self):
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=("#1e293b", "#0f172a"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="  NTDS  HIBP  CHECKER",
                     font=ctk.CTkFont(size=26, weight="bold"),
                     text_color="#e2e8f0").grid(
            row=0, column=0, sticky="w", padx=20, pady=(14, 0))
        sub = ctk.CTkFrame(header, fg_color="transparent")
        sub.grid(row=1, column=0, sticky="w", padx=22, pady=(0, 12))
        ctk.CTkLabel(sub,
                     text="Analyse ntds.dit  -  comparaison HaveIBeenPwned "
                          "(NTLM)",
                     font=ctk.CTkFont(size=13), text_color="#94a3b8").pack(
            side="left")
        # chip d'etat connexion / base locale (Lot E)
        self.chip = ctk.CTkLabel(sub, text="", corner_radius=10,
                                 font=ctk.CTkFont(size=11, weight="bold"),
                                 fg_color="#1e3a8a", text_color="#bfdbfe",
                                 padx=10, pady=2)
        self.chip.pack(side="left", padx=12)

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=1, rowspan=2, sticky="e", padx=18)
        link = ctk.CTkLabel(right, text=f"{__author__}   {__url__}",
                            font=ctk.CTkFont(size=12, underline=True),
                            text_color="#60a5fa", cursor="hand2")
        link.pack(anchor="e", pady=(2, 6))
        link.bind("<Button-1>", lambda e: webbrowser.open(__url__))
        link.bind("<Enter>", lambda e: link.configure(text_color="#93c5fd"))
        link.bind("<Leave>", lambda e: link.configure(text_color="#60a5fa"))
        attach_tooltip(link, f"Ouvrir {__url__} dans le navigateur")

        row = ctk.CTkFrame(right, fg_color="transparent")
        row.pack(anchor="e")
        self.theme_switch = ctk.CTkSwitch(
            row, text="Theme clair", command=self._on_theme_switch,
            width=40)
        self.theme_switch.pack(side="left", padx=(0, 12))
        if str(ctk.get_appearance_mode()).lower() == "light":
            self.theme_switch.select()
        attach_tooltip(self.theme_switch, "Basculer clair/sombre (Ctrl+T)")
        self.btn_help = ctk.CTkButton(
            row, text="❔  Aide", width=90, height=28,
            fg_color="#0f766e", hover_color="#115e59",
            command=self._show_help)
        self.btn_help.pack(side="left", padx=(0, 8))
        attach_tooltip(self.btn_help,
                       "Comment recuperer ntds.dit et la ruche SYSTEM "
                       "(ntdsutil IFM, VSS, diskshadow...). (F1)")
        self.btn_about = ctk.CTkButton(
            row, text="ℹ  A propos", width=100, height=28,
            fg_color="#334155", hover_color="#475569",
            command=self._show_about)
        self.btn_about.pack(side="left")
        attach_tooltip(self.btn_about,
                       "Informations sur l'application, l'auteur et les "
                       "mentions techniques.")

    def _build_inputs(self):
        card = ctk.CTkFrame(self, corner_radius=12)
        card.grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 8))
        card.grid_columnconfigure(0, weight=1)

        self._inputs_collapsed = False
        self._inputs_title = ctk.CTkLabel(
            card, text="▾  \U0001F4C1  Fichiers a analyser",
            font=ctk.CTkFont(size=14, weight="bold"), cursor="hand2")
        self._inputs_title.grid(row=0, column=0, sticky="w", padx=16,
                                pady=(8, 2))
        self._inputs_title.bind("<Button-1>", lambda e: self._toggle_inputs())
        attach_tooltip(self._inputs_title,
                       "Cliquer pour replier/deplier cette section "
                       "(repliee automatiquement apres l'analyse).")

        self.sel_ntds = FileSelector(
            card, "Fichier ntds.dit", default=autodetect(["ntds.dit"]),
            tooltip="Base Active Directory a analyser. Detectee automatiquement "
                    "dans le dossier de l'exe (ou Active Directory\\ntds.dit).")
        self.sel_ntds.grid(row=1, column=0, sticky="ew", padx=16)

        self.sel_system = FileSelector(
            card, "Ruche SYSTEM", default=autodetect(["SYSTEM"]),
            tooltip="Ruche de registre SYSTEM contenant la boot key (SYSKEY) "
                    "necessaire pour dechiffrer ntds.dit. Souvent dans "
                    "registry\\SYSTEM de l'export IFM.")
        self.sel_system.grid(row=2, column=0, sticky="ew", padx=16)

        # --- mode HIBP --- #
        mode_frame = ctk.CTkFrame(card, fg_color="transparent")
        mode_frame.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 2))
        mode_frame.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(mode_frame, text="Source HIBP", width=140, anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=0, column=0, sticky="w")
        self.mode_var = ctk.StringVar(value="online")
        rb_online = ctk.CTkRadioButton(
            mode_frame, text="API en ligne (k-anonymity)",
            variable=self.mode_var, value="online",
            command=self._on_mode_change)
        rb_online.grid(row=0, column=1, padx=(0, 16))
        rb_local = ctk.CTkRadioButton(
            mode_frame, text="Fichier local (hors-ligne)",
            variable=self.mode_var, value="local",
            command=self._on_mode_change)
        rb_local.grid(row=0, column=2, sticky="w")
        attach_tooltip(rb_online,
                       "Interroge l'API HaveIBeenPwned : seuls les 5 premiers "
                       "caracteres de chaque hash sont envoyes (k-anonymity). "
                       "Necessite une connexion Internet.")
        attach_tooltip(rb_local,
                       "Recherche dans un fichier HIBP NTLM telecharge "
                       "(100% hors-ligne, ideal en environnement isole). "
                       "Choisir le format 'NTLM (ordered by hash)'.")

        self.ignore_machine_var = ctk.BooleanVar(value=True)
        cb_machine = ctk.CTkCheckBox(
            mode_frame, text="Ignorer les comptes machine ($) dans HIBP",
            variable=self.ignore_machine_var, font=ctk.CTkFont(size=12),
            checkbox_width=20, checkbox_height=20)
        cb_machine.grid(row=1, column=1, columnspan=2, sticky="w",
                        pady=(2, 0))
        attach_tooltip(cb_machine,
                       "Les comptes ordinateurs/service (...$) ont un mot de "
                       "passe aleatoire jamais present dans HIBP : les exclure "
                       "accelere fortement l'analyse sur un vrai domaine.")

        self.sel_hibp = FileSelector(
            card, "Fichier HIBP NTLM", default=autodetect_hibp(),
            tooltip="Fichier pwnedpasswords NTLM trie par hash "
                    "(~30 Go). Requis uniquement en mode local.")
        self.sel_hibp.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 2))
        # si un fichier HIBP local a ete decouvert, on bascule en mode local
        # (hors-ligne, recommande) ; sinon on reste sur l'API en ligne.
        if self.sel_hibp.get():
            self.mode_var.set("local")
        self._set_hibp_enabled(self.mode_var.get() == "local")

        # --- boutons d'action --- #
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=5, column=0, sticky="ew", padx=16, pady=(6, 8))
        self.btn_analyze = ctk.CTkButton(
            actions, text="\U0001F50D  Lancer l'analyse", height=34,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self._start)
        self.btn_analyze.pack(side="left")
        self.btn_cancel = ctk.CTkButton(
            actions, text="⏹  Annuler", height=34, width=110, state="disabled",
            fg_color=DANGER, hover_color=DANGER_HOVER, command=self._cancel)
        self.btn_cancel.pack(side="left", padx=10)
        self.btn_export = ctk.CTkButton(
            actions, text="\U0001F4BE  Exporter", height=34, width=150,
            state="disabled", fg_color="#475569", hover_color="#334155",
            command=self._export)
        self.btn_export.pack(side="left")
        attach_tooltip(self.btn_analyze,
                       "Extrait les hash du ntds.dit puis les compare a HIBP. "
                       "(F5)")
        attach_tooltip(self.btn_cancel,
                       "Interrompt l'analyse en cours (effet differe a la "
                       "ligne suivante pendant l'extraction).")
        attach_tooltip(self.btn_export,
                       "Enregistre le rapport en HTML (designe, avec "
                       "camembert), JSON, CSV ou TXT.")
        self.btn_download = ctk.CTkButton(
            actions, text="⬇  Telecharger la base HIBP", height=34, width=220,
            fg_color="#0f766e", hover_color="#115e59",
            command=self._download_hibp)
        self.btn_download.pack(side="right")
        attach_tooltip(self.btn_download,
                       "Telecharge localement la base HaveIBeenPwned NTLM "
                       "complete (format trie par hash, pret pour le mode "
                       "local). Volumineux (dizaines de Go) et long.")

        # champs repliables (la barre d'actions reste toujours visible).
        # grid_remove conserve la position pour un grid() ulterieur.
        self._inputs_body = [self.sel_ntds, self.sel_system, mode_frame,
                             self.sel_hibp]

    def _toggle_inputs(self):
        self._set_inputs_collapsed(not self._inputs_collapsed)

    def _set_inputs_collapsed(self, collapsed: bool):
        if collapsed == self._inputs_collapsed:
            return
        self._inputs_collapsed = collapsed
        for w in self._inputs_body:
            if collapsed:
                w.grid_remove()
            else:
                w.grid()
        arrow = "▸" if collapsed else "▾"
        self._inputs_title.configure(
            text=f"{arrow}  \U0001F4C1  Fichiers a analyser" +
                 ("   (replie - cliquer pour deplier)" if collapsed else ""))

    def _build_progress(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 4))
        frame.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkProgressBar(frame, height=16, corner_radius=8,
                                           progress_color=ACCENT)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress.set(0)
        attach_tooltip(self.progress,
                       "Pulsation = extraction du ntds.dit en cours ; "
                       "progression chiffree = comparaison HIBP.")
        self.lbl_status = ctk.CTkLabel(
            frame, text="Pret.", font=ctk.CTkFont(size=12),
            text_color="#94a3b8", anchor="w")
        self.lbl_status.grid(row=1, column=0, sticky="ew", pady=(4, 0))

    def _build_results(self):
        self.tabs = ctk.CTkTabview(self, corner_radius=12)
        self.tabs.grid(row=3, column=0, sticky="nsew", padx=20, pady=8)
        self.tab_summary = self.tabs.add("Resultats")
        self.tab_report = self.tabs.add("Rapport")
        self.tab_warn = self.tabs.add("Avertissements")
        self.tab_log = self.tabs.add("Journal")

        # grille directe : stats (haut) + camembert/jauge + tableau (prioritaire).
        # Le tableau possede son propre defilement ; sur petits ecrans il
        # raccourcit mais reste visible et scrollable.
        self.tab_summary.grid_columnconfigure(0, weight=1)
        self.tab_summary.grid_rowconfigure(2, weight=1, minsize=150)
        self._build_stat_cards(self.tab_summary)
        self._build_viz(self.tab_summary)
        self._build_table(self.tab_summary)
        self._build_report_tab()
        self._build_warn_tab()
        self._build_log_tab()

    # --- onglet rapport (synthese texte) --- #
    def _build_report_tab(self):
        self.tab_report.grid_columnconfigure(0, weight=1)
        self.tab_report.grid_rowconfigure(0, weight=1)
        self.report_box = ctk.CTkTextbox(
            self.tab_report, wrap="none",
            font=ctk.CTkFont(family="Consolas", size=12))
        self.report_box.grid(row=0, column=0, sticky="nsew", pady=8)
        self.report_box.insert("end", "Lancez une analyse pour afficher "
                                       "le rapport detaille.")
        self.report_box.configure(state="disabled")

    # --- cartes de statistiques (Lot F : icones) --- #
    def _build_stat_cards(self, parent):
        self.stats_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.stats_frame.grid(row=0, column=0, sticky="ew", pady=(8, 4))
        self._stat_cards = {}
        self._stat_card_frames = {}
        specs = [
            ("total", "\U0001F465  Comptes", "#94a3b8",
             "Nombre total de comptes extraits du ntds.dit."),
            ("pwned", "☠  Compromis HIBP", DANGER,
             "Comptes dont le mot de passe figure dans HaveIBeenPwned."),
            ("blank", "⚠  Sans mot de passe", WARN,
             "Comptes dont le hash NT correspond a un mot de passe vide."),
            ("lm", "\U0001F513  Hash LM", WARN,
             "Comptes possedant encore un hash LM (obsolete, faible)."),
            ("reuse", "\U0001F501  Reutilises", WARN,
             "Groupes de comptes partageant un meme mot de passe."),
            ("machine", "\U0001F5A5  Machine", "#64748b",
             "Comptes ordinateurs/service (...$)."),
        ]
        for i, (key, label, color, tip) in enumerate(specs):
            self.stats_frame.grid_columnconfigure(i, weight=1)
            card = ctk.CTkFrame(self.stats_frame, corner_radius=10,
                                border_width=2, border_color="#262a33")
            card.grid(row=0, column=i, sticky="ew", padx=4)
            val = ctk.CTkLabel(card, text="0",
                               font=ctk.CTkFont(size=22, weight="bold"),
                               text_color=color)
            val.pack(pady=(5, 0))
            lbl = ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=11),
                               text_color="#94a3b8")
            lbl.pack(pady=(0, 6))
            self._stat_cards[key] = val
            self._stat_card_frames[key] = card
            self._add_hover_lift(card)
            attach_tooltip([card, val, lbl], tip)

    # --- visualisations : camembert + jauge de risque (Lots B/F) --- #
    def _build_viz(self, parent):
        self._pie_segments = []
        self._pie_t = 1.0
        self._pie_highlight = None
        self._gauge_score = 0
        self._gauge_t = 1.0

        viz = ctk.CTkFrame(parent, fg_color="transparent")
        viz.grid(row=1, column=0, sticky="ew", pady=(4, 6))
        viz.grid_columnconfigure(0, weight=3)
        viz.grid_columnconfigure(1, weight=2)

        # camembert
        pie_card = ctk.CTkFrame(viz, corner_radius=10, fg_color="#15171d")
        pie_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        pie_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(pie_card, text="\U0001F511  Comptes a mot de passe identique",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#e2e8f0").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 2))
        self.pie_canvas = tk.Canvas(pie_card, width=160, height=160,
                                    bg="#15171d", highlightthickness=0)
        self.pie_canvas.grid(row=1, column=0, padx=16, pady=(0, 14))
        self.legend_frame = ctk.CTkFrame(pie_card, fg_color="transparent")
        self.legend_frame.grid(row=1, column=1, sticky="nw", padx=(4, 16),
                               pady=(0, 14))
        attach_tooltip(self.pie_canvas,
                       "Repartition des comptes : chaque part = un groupe "
                       "partageant le meme mot de passe ; gris = uniques.")

        # jauge de risque
        gauge_card = ctk.CTkFrame(viz, corner_radius=10, fg_color="#15171d")
        gauge_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        gauge_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(gauge_card, text="\U0001F4CA  Score de risque",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#e2e8f0").grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        self.gauge_canvas = tk.Canvas(gauge_card, width=220, height=132,
                                      bg="#15171d", highlightthickness=0)
        self.gauge_canvas.grid(row=1, column=0, pady=(0, 6))
        self.lbl_actifs = ctk.CTkLabel(gauge_card, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color="#94a3b8")
        self.lbl_actifs.grid(row=2, column=0, pady=(0, 12))
        attach_tooltip(self.gauge_canvas,
                       "Part des comptes a risque (compromis, vides ou LM) "
                       "sur l'ensemble des comptes.")

    # --- tableau de resultats interactif (Lot A) --- #
    def _build_table(self, parent):
        self._table_findings = []        # findings affiches (apres filtre)
        self._row_finding = {}           # iid -> finding
        self._sort_col = None
        self._sort_desc = True

        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=2, column=0, sticky="nsew", pady=(2, 8))
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(wrap, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(bar, text="\U0001F50D", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(2, 6))
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(
            bar, textvariable=self.search_var,
            placeholder_text="Filtrer par nom de compte...")
        self.search_entry.grid(row=0, column=1, sticky="ew")
        self.search_var.trace_add("write", lambda *a: self._refresh_table())
        self.only_risk_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(bar, text="Comptes a risque seulement",
                        variable=self.only_risk_var,
                        font=ctk.CTkFont(size=12), checkbox_width=18,
                        checkbox_height=18,
                        command=self._refresh_table).grid(
            row=0, column=2, padx=12)

        table_holder = tk.Frame(wrap, bg="#1b1d23")
        table_holder.grid(row=1, column=0, sticky="nsew")
        table_holder.grid_columnconfigure(0, weight=1)
        table_holder.grid_rowconfigure(0, weight=1)

        cols = ("compte", "rid", "actif", "hibp", "reuse", "etat")
        self.tree = ttk.Treeview(table_holder, columns=cols, show="headings",
                                 selectmode="browse", height=8)
        heads = [("compte", "Compte", 260), ("rid", "RID", 70),
                 ("actif", "Actif", 60), ("hibp", "HIBP", 90),
                 ("reuse", "Reutil.", 70), ("etat", "Etat", 180)]
        for key, title, width in heads:
            self.tree.heading(key, text=title,
                              command=lambda k=key: self._sort_table(k))
            anchor = "e" if key in ("hibp", "reuse", "rid") else "w"
            self.tree.column(key, width=width, anchor=anchor,
                             stretch=(key in ("compte", "etat")))
        vsb = ttk.Scrollbar(table_holder, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Double-1>", self._on_row_activate)
        self.tree.bind("<Return>", self._on_row_activate)

        # severite -> couleur de ligne
        self.tree.tag_configure("pwned", foreground="#fca5a5")
        self.tree.tag_configure("blank", foreground="#fdba74")
        self.tree.tag_configure("lm", foreground="#fde68a")
        self.tree.tag_configure("ok", foreground="#94a3b8")
        self.tree.tag_configure("odd", background="#191b21")
        self.tree.tag_configure("even", background="#1b1d23")

        # etat vide illustre (Lot E)
        self.empty_label = ctk.CTkLabel(
            table_holder,
            text="\U0001F50E\n\nLancez une analyse pour afficher les comptes.\n"
                 "Les fichiers du dossier courant sont detectes automatiquement.",
            font=ctk.CTkFont(size=14), text_color="#64748b", justify="center")
        self.empty_label.place(relx=0.5, rely=0.5, anchor="center")

        self._style_tree(ctk.get_appearance_mode())

    def _style_tree(self, mode: str):
        dark = str(mode).lower() == "dark"
        bg = "#1b1d23" if dark else "#f1f5f9"
        fg = "#e2e8f0" if dark else "#0f172a"
        head_bg = "#262a33" if dark else "#e2e8f0"
        sel = ACCENT
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", background=bg, fieldbackground=bg,
                        foreground=fg, rowheight=26, borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=head_bg, foreground=fg,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading",
                  background=[("active", "#334155" if dark else "#cbd5e1")])
        style.map("Treeview", background=[("selected", sel)],
                  foreground=[("selected", "#ffffff")])

    # --- onglet avertissements --- #
    def _build_warn_tab(self):
        self.tab_warn.grid_columnconfigure(0, weight=1)
        self.tab_warn.grid_rowconfigure(0, weight=1)
        warn_box = ctk.CTkTextbox(self.tab_warn, wrap="word",
                                  font=ctk.CTkFont(size=13))
        warn_box.grid(row=0, column=0, sticky="nsew", pady=8)
        warn_box.insert("end", "⚠  AVERTISSEMENTS DE SECURITE\n")
        for i, w in enumerate(SECURITY_WARNINGS, 1):
            warn_box.insert("end", f"\n  [{i}]  {w}\n")
        warn_box.configure(state="disabled")

        del_frame = ctk.CTkFrame(self.tab_warn, fg_color="transparent")
        del_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.btn_sdelete = ctk.CTkButton(
            del_frame, text="\U0001F5D1  Supprimer les fichiers (sdelete -p 7)",
            height=38, fg_color=DANGER, hover_color=DANGER_HOVER,
            command=self._secure_delete)
        self.btn_sdelete.pack(side="left")
        attach_tooltip(self.btn_sdelete,
                       "Efface ntds.dit et SYSTEM avec SDelete (7 passes, "
                       "irreversible). Necessite sdelete64.exe dans le PATH "
                       "ou a cote de l'application.")
        ctk.CTkLabel(del_frame, text="  Efface ntds.dit + SYSTEM de facon "
                     "irreversible (7 passes).", text_color="#94a3b8",
                     font=ctk.CTkFont(size=11)).pack(side="left", padx=8)

    # --- onglet journal (Lot E) --- #
    def _build_log_tab(self):
        self.tab_log.grid_columnconfigure(0, weight=1)
        self.tab_log.grid_rowconfigure(0, weight=1)
        self.log_box = ctk.CTkTextbox(
            self.tab_log, wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11))
        self.log_box.grid(row=0, column=0, sticky="nsew", pady=8)
        self.log_box.insert("end", "Journal d'execution\n")
        self.log_box.configure(state="disabled")

    def _log(self, message: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _build_footer(self):
        footer = ctk.CTkLabel(
            self, text=f"{__app_name__} v{__version__}  -  {__author__}  -  "
                       f"{__url__}",
            font=ctk.CTkFont(size=11), text_color="#64748b")
        footer.grid(row=4, column=0, sticky="ew", pady=(0, 6))

    # ----------------------------------------------------------- Modes -- #
    def _on_mode_change(self):
        self._set_hibp_enabled(self.mode_var.get() == "local")
        self._update_chip()

    def _set_hibp_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.sel_hibp.entry.configure(state=state)
        self.sel_hibp.btn.configure(state=state)

    # -------------------------------------------------------- Analyse --- #
    def _start(self):
        ntds = self.sel_ntds.get()
        system = self.sel_system.get()
        online = self.mode_var.get() == "online"
        hibp_file = self.sel_hibp.get()

        if not ntds or not os.path.isfile(ntds):
            messagebox.showerror("Fichier manquant",
                                 "Veuillez selectionner un fichier ntds.dit valide.")
            return
        if not system or not os.path.isfile(system):
            messagebox.showerror("Fichier manquant",
                                 "Veuillez selectionner une ruche SYSTEM valide.")
            return
        if not online and (not hibp_file or not os.path.isfile(hibp_file)):
            messagebox.showerror("Fichier manquant",
                                 "Mode local : selectionnez le fichier HIBP NTLM.")
            return
        if online:
            if not messagebox.askyesno(
                    "Mode en ligne",
                    "En mode en ligne, les 5 premiers caracteres de chaque "
                    "hash NT seront envoyes a l'API HaveIBeenPwned "
                    "(k-anonymity). Le hash complet ne quitte jamais le poste.\n\n"
                    "Continuer ?"):
                return

        self._report = None
        self._set_running(True)
        self._clear_results()
        self._analyzer = Analyzer(
            ntds_path=ntds, system_path=system, use_online=online,
            local_hibp_file=hibp_file or None,
            ignore_machine=bool(self.ignore_machine_var.get()),
            on_progress=lambda p: self._queue.put(("progress", p)),
            on_log=lambda m: self._queue.put(("log", m)))

        def _run():
            try:
                report = self._analyzer.run()
                self._queue.put(("done", report))
            except CancelledError:
                self._queue.put(("cancelled", None))
            except Exception as exc:        # noqa
                self._queue.put(("error", str(exc)))

        self._worker = threading.Thread(target=_run, daemon=True)
        self._worker.start()

    def _cancel(self):
        if self._downloading:
            self._dl_cancel = True
            self._set_status("Annulation du telechargement...")
        elif self._analyzer:
            self._analyzer.cancel()
            self._set_status("Annulation en cours...")

    # ----------------------------------------- telechargement base HIBP - #
    def _download_hibp(self):
        if self._downloading or (self._worker and self._worker.is_alive()):
            return
        if not messagebox.askyesno(
                "Telecharger la base HIBP",
                "Telecharge l'integralite de la base HaveIBeenPwned NTLM via "
                "l'API officielle (1 048 576 plages), au format trie pret pour "
                "le mode local.\n\n"
                "- Taille finale : plusieurs dizaines de Go\n"
                "- Duree : de 30 min a plusieurs heures selon la connexion\n"
                "- Connexion Internet requise\n\n"
                "Continuer ?"):
            return
        path = filedialog.asksaveasfilename(
            title="Enregistrer la base HIBP NTLM", defaultextension=".txt",
            initialdir=resource_dir(), initialfile="pwnedpasswords_ntlm.txt",
            filetypes=[("Texte", "*.txt")])
        if not path:
            return
        self._downloading = True
        self._dl_cancel = False
        self.btn_analyze.configure(state="disabled")
        self.btn_download.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self._pulse_on = False
        self._bar_value = self._bar_target = 0.0
        self._last_drawn = None
        self._dl_start = time.monotonic()
        self.progress.configure(progress_color="#14b8a6")
        self._set_status("Telechargement de la base HIBP NTLM... (estimation "
                         "du temps en cours)")

        def _run():
            try:
                download_hibp_ntlm(
                    path,
                    on_progress=lambda d, t: self._queue.put(
                        ("dl_progress", (d, t))),
                    should_cancel=lambda: self._dl_cancel)
                self._queue.put(("dl_done", path))
            except CancelledError:
                self._queue.put(("dl_cancelled", path))
            except Exception as exc:        # noqa
                self._queue.put(("dl_error", str(exc)))

        self._worker = threading.Thread(target=_run, daemon=True)
        self._worker.start()

    def _download_finished(self):
        self._downloading = False
        self.btn_analyze.configure(state="normal")
        self.btn_download.configure(state="normal")
        self.btn_cancel.configure(state="disabled")

    def _set_running(self, running: bool):
        self.btn_analyze.configure(state="disabled" if running else "normal")
        self.btn_cancel.configure(state="normal" if running else "disabled")
        self.btn_download.configure(state="disabled" if running else "normal")
        self.btn_export.configure(
            state="disabled" if running else
            ("normal" if self._report else "disabled"))
        if running:
            self._pulse_on = True       # extraction = barre pulsante
            self._bar_target = 0.0
            self._bar_value = 0.0
            self._risk_pulse = False
            self.progress.configure(progress_color=ACCENT)
            # eteindre un eventuel halo de risque precedent
            if "pwned" in self._stat_card_frames:
                self._stat_card_frames["pwned"].configure(border_color="#262a33")

    def _add_hover_lift(self, card, base="#262a33", hover=ACCENT):
        """Microinteraction : la bordure de la carte s'illumine au survol.

        L'etat est determine par la position reelle du pointeur (et non par les
        seuls evenements) pour eviter le scintillement quand la souris passe
        d'un enfant a l'autre."""
        children = card.winfo_children()

        def refresh(_=None):
            x, y = card.winfo_pointerxy()
            try:
                under = card.winfo_containing(x, y)
            except Exception:
                under = None
            inside = under is not None and (
                under is card or str(under).startswith(str(card)))
            card.configure(border_color=hover if inside else base)

        for w in (card, *children):
            w.bind("<Enter>", refresh, add="+")
            w.bind("<Leave>", refresh, add="+")

    # ----------------------------------------------- boucle d'animation - #
    def _tick(self):
        # 1) traiter les messages du worker
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass

        # 2) animer la barre de progression + halo de risque
        self._animate_bar()
        self._animate_risk()

        # au repos (rien a animer), on ralentit la boucle pour economiser le
        # CPU tout en continuant a relever la file d'attente regulierement.
        animating = (self._pulse_on or self._risk_pulse or
                     abs(self._bar_target - self._bar_value) > 0.0015)
        self.after(self.FRAME_MS if animating else 60, self._tick)

    def _animate_risk(self):
        """Halo rouge pulsant sur la carte 'Compromis HIBP' lorsqu'il y a des
        comptes compromis : attire l'oeil sans etre agressif."""
        card = self._stat_card_frames.get("pwned")
        if not self._risk_pulse or card is None:
            return
        self._risk_phase = (self._risk_phase + 0.03) % 1.0
        v = 0.5 - 0.5 * math.cos(self._risk_phase * 2 * math.pi)
        # interpolation entre un rouge sombre et un rouge vif
        c1 = (0x40, 0x10, 0x10)
        c2 = (0xef, 0x44, 0x44)
        col = "#%02x%02x%02x" % tuple(
            int(a + (b - a) * v) for a, b in zip(c1, c2))
        card.configure(border_color=col)

    def _animate_bar(self):
        if self._pulse_on:
            # pulsation respirante et reguliere pendant l'extraction
            self._pulse_phase = (self._pulse_phase + 0.02) % 1.0
            v = 0.5 - 0.5 * math.cos(self._pulse_phase * 2 * math.pi)
            self._draw_bar(0.12 + 0.76 * v)
        else:
            # easing exponentiel vers la cible
            delta = self._bar_target - self._bar_value
            if abs(delta) > 0.0015:
                self._bar_value += delta * 0.22
            else:
                self._bar_value = self._bar_target
            self._draw_bar(self._bar_value)

    def _draw_bar(self, value: float):
        """Ne redessine la barre que si la valeur a sensiblement change."""
        value = max(0.0, min(1.0, value))
        if self._last_drawn is None or abs(value - self._last_drawn) > 0.001:
            self.progress.set(value)
            self._last_drawn = value

    def _leave_pulse(self):
        """Quitte la pulsation sans saut : l'easing repart de la position visible."""
        self._pulse_on = False
        if self._last_drawn is not None:
            self._bar_value = self._last_drawn

    def _handle(self, kind: str, payload):
        if kind == "log":
            self._set_status(payload)
            self._log(payload)
        elif kind == "progress":
            p: Progress = payload
            if p.phase == Phase.EXTRACTION:
                self._pulse_on = True
            elif p.phase == Phase.HIBP:
                self._leave_pulse()
                if p.total > 0:
                    self._bar_target = p.current / p.total
            elif p.phase == Phase.DONE:
                self._leave_pulse()
                self._bar_target = 1.0
            self._set_status(p.message)
        elif kind == "done":
            self._leave_pulse()
            self._bar_target = 1.0
            self._report = payload
            self._set_running(False)
            self.btn_export.configure(state="normal")
            # barre coloree selon le resultat : rouge si comptes a risque,
            # vert si l'analyse est propre
            at_risk = bool(payload.at_risk)
            self.progress.configure(progress_color=DANGER if at_risk else OK)
            self._risk_pulse = payload.pwned_accounts > 0
            self._render_report(payload)
            # sur ecran peu haut, replier le formulaire pour laisser la place
            # aux resultats (camembert + tableau).
            if self.winfo_height() < 900:
                self._set_inputs_collapsed(True)
            self._set_status("Analyse terminee.")
        elif kind == "cancelled":
            self._leave_pulse()
            self._bar_target = 0.0
            self._set_running(False)
            self._set_status("Analyse annulee.")
        elif kind == "error":
            self._leave_pulse()
            self._bar_target = 0.0
            self._set_running(False)
            self._set_status(f"Erreur : {payload}")
            messagebox.showerror("Erreur d'analyse", str(payload))
        elif kind == "sdelete":
            ok, msg = payload
            self._on_sdelete_done(ok, msg)
        elif kind == "dl_progress":
            d, t = payload
            self._pulse_on = False
            self._bar_target = (d / t) if t else 0.0
            pct = (d / t * 100.0) if t else 0.0
            elapsed = time.monotonic() - getattr(self, "_dl_start",
                                                 time.monotonic())
            eta_txt = ""
            if d > 0 and elapsed > 1.0:
                rate = d / elapsed                  # plages / seconde
                remaining = (t - d) / rate if rate > 0 else 0
                eta_txt = (f" - reste ~{self._fmt_duration(remaining)} "
                           f"({rate * 60:.0f} plages/min)")
            self._set_status(
                (f"Telechargement base HIBP : {d:,}/{t:,} plages "
                 f"({pct:.1f} %)" + eta_txt).replace(",", " "))
        elif kind == "dl_done":
            self._download_finished()
            self._bar_target = 1.0
            self.progress.configure(progress_color=OK)
            self.sel_hibp.set(payload)
            self.mode_var.set("local")
            self._set_hibp_enabled(True)
            self._update_chip()
            self._set_status("Base HIBP telechargee - mode local active.")
            self._toast(
                f"Base HIBP enregistree : {os.path.basename(payload)}", "ok")
        elif kind == "dl_cancelled":
            self._download_finished()
            self._bar_target = 0.0
            self.progress.configure(progress_color=ACCENT)
            self._set_status("Telechargement annule (fichier .part conserve).")
        elif kind == "dl_error":
            self._download_finished()
            self._bar_target = 0.0
            self.progress.configure(progress_color=ACCENT)
            self._set_status(f"Echec du telechargement : {payload}")
            self._toast(f"Echec du telechargement : {payload}", "error")

    def _set_status(self, text: str):
        self.lbl_status.configure(text=text)

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        seconds = int(max(0, seconds))
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h} h {m:02d} min"
        if m:
            return f"{m} min {s:02d} s"
        return f"{s} s"

    def _announce_discovery(self):
        """Resume, au lancement, les fichiers decouverts dans le dossier."""
        found, missing = [], []
        (found if self.sel_ntds.get() else missing).append("ntds.dit")
        (found if self.sel_system.get() else missing).append("SYSTEM")
        if self.sel_hibp.get():
            found.append("HIBP NTLM (mode local active)")
        if not found:
            self._set_status("Aucun fichier detecte dans le dossier courant - "
                             "selectionnez ntds.dit et la ruche SYSTEM.")
            self._update_chip()
            return
        parts = ["Detecte : " + ", ".join(found) + "."]
        if missing:
            parts.append("Manquant : " + ", ".join(missing) + ".")
        self._set_status("  ".join(parts))
        self._update_chip()

    # ------------------------------------------------------- A propos --- #
    def _show_about(self):
        # eviter d'ouvrir plusieurs fenetres
        existing = getattr(self, "_about_win", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus()
            return

        win = ctk.CTkToplevel(self)
        self._about_win = win
        win.title(f"A propos - {__app_name__}")
        win.resizable(False, False)
        win.transient(self)
        try:
            win.attributes("-alpha", 0.0)
        except Exception:
            pass

        wrap = ctk.CTkFrame(win, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=24, pady=20)

        ctk.CTkLabel(wrap, text="NTDS  HIBP  CHECKER",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#e2e8f0").pack(anchor="w")
        ctk.CTkLabel(wrap, text=f"Version {__version__}",
                     font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(
            anchor="w", pady=(0, 12))

        ctk.CTkLabel(
            wrap, justify="left", wraplength=470,
            font=ctk.CTkFont(size=12), text_color="#cbd5e1",
            text="Analyse un fichier ntds.dit (base Active Directory) et "
                 "compare les hash NT des comptes du domaine a la base "
                 "HaveIBeenPwned (Pwned Passwords - NTLM) afin d'identifier "
                 "les mots de passe compromis, vides, faibles (LM) ou "
                 "reutilises.").pack(anchor="w", pady=(0, 12))

        sep = ctk.CTkFrame(wrap, height=1, fg_color="#334155")
        sep.pack(fill="x", pady=4)

        ctk.CTkLabel(wrap, text="Auteur", font=ctk.CTkFont(size=12,
                     weight="bold"), text_color="#94a3b8").pack(
            anchor="w", pady=(8, 0))
        ctk.CTkLabel(wrap, text=__author__, font=ctk.CTkFont(size=14,
                     weight="bold"), text_color="#e2e8f0").pack(anchor="w")
        link = ctk.CTkLabel(wrap, text=__url__, cursor="hand2",
                            font=ctk.CTkFont(size=12, underline=True),
                            text_color="#60a5fa")
        link.pack(anchor="w", pady=(0, 12))
        link.bind("<Button-1>", lambda e: webbrowser.open(__url__))
        link.bind("<Enter>", lambda e: link.configure(text_color="#93c5fd"))
        link.bind("<Leave>", lambda e: link.configure(text_color="#60a5fa"))

        ctk.CTkLabel(
            wrap, justify="left", wraplength=470,
            font=ctk.CTkFont(size=11), text_color="#94a3b8",
            text="Technologies : extraction via impacket - comparaison "
                 "HaveIBeenPwned (k-anonymity ou fichier local) - interface "
                 "CustomTkinter.").pack(anchor="w", pady=(4, 8))

        ctk.CTkLabel(
            wrap, justify="left", wraplength=470,
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#f59e0b",
            text="A utiliser uniquement sur des systemes dont vous etes "
                 "proprietaire ou pour lesquels vous disposez d'une "
                 "autorisation explicite.").pack(anchor="w", pady=(0, 12))

        ctk.CTkButton(wrap, text="Fermer", width=120, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER,
                      command=win.destroy).pack(anchor="e")

        # dimensionne la fenetre a la taille REELLE de son contenu (sinon
        # CTkToplevel garde sa taille par defaut et le contenu est tronque),
        # puis centre par rapport a la fenetre principale + fondu d'apparition.
        win.update_idletasks()
        w = wrap.winfo_reqwidth() + 48
        h = wrap.winfo_reqheight() + 40
        x = self.winfo_rootx() + max(0, (self.winfo_width() - w) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - h) // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.after(120, lambda: self._fade_window(win, 0.0))
        win.after(150, win.grab_set)      # modal apres affichage

    def _fade_window(self, win, alpha: float):
        if not win.winfo_exists():
            return
        alpha = min(1.0, alpha + 0.12)
        try:
            win.attributes("-alpha", alpha)
        except Exception:
            pass
        if alpha < 1.0:
            win.after(12, lambda: self._fade_window(win, alpha))

    # --------------------------------------------------------- aide ----- #
    def _show_help(self):
        existing = getattr(self, "_help_win", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus()
            return
        win = ctk.CTkToplevel(self)
        self._help_win = win
        win.title("Aide - Recuperer ntds.dit et SYSTEM")
        win.geometry("760x620")
        win.transient(self)
        try:
            win.attributes("-alpha", 0.0)
        except Exception:
            pass

        scroll = ctk.CTkScrollableFrame(win, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=18, pady=14)

        def title(text):
            ctk.CTkLabel(scroll, text=text,
                         font=ctk.CTkFont(size=15, weight="bold"),
                         text_color="#e2e8f0", justify="left",
                         wraplength=680).pack(anchor="w", pady=(14, 2))

        def para(text, color="#cbd5e1"):
            ctk.CTkLabel(scroll, text=text, font=ctk.CTkFont(size=12),
                         text_color=color, justify="left",
                         wraplength=680).pack(anchor="w", pady=(0, 4))

        def code(cmd):
            box = ctk.CTkTextbox(scroll, height=1 + 22 * (cmd.count("\n") + 1),
                                 font=ctk.CTkFont(family="Consolas", size=11),
                                 fg_color="#0b1220", wrap="none")
            box.pack(fill="x", pady=(2, 6))
            box.insert("end", cmd)
            box.configure(state="disabled")

        ctk.CTkLabel(scroll, text="\U0001F4D8  Recuperer ntds.dit et la ruche "
                     "SYSTEM", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="#e2e8f0").pack(anchor="w")
        para("L'analyse necessite DEUX fichiers, a recuperer sur un "
             "controleur de domaine (DC), en tant qu'administrateur du "
             "domaine :", "#94a3b8")
        para("  -  ntds.dit  : la base Active Directory\n"
             "  -  SYSTEM    : la ruche de registre contenant la boot key "
             "(SYSKEY) qui dechiffre ntds.dit")
        para("ntds.dit est verrouille pendant que le DC fonctionne : on ne "
             "peut pas le copier directement. Les methodes ci-dessous "
             "contournent ce verrou.", "#94a3b8")

        title("Methode 1 - ntdsutil IFM  (recommandee, officielle)")
        para("Cree un instantane coherent (Install From Media) contenant "
             "ntds.dit ET la ruche SYSTEM. A executer dans une invite "
             "elevee sur le DC :")
        code('ntdsutil "activate instance ntds" "ifm" '
             '"create full C:\\export" quit quit')
        para("Resultat : C:\\export\\Active Directory\\ntds.dit  et  "
             "C:\\export\\registry\\SYSTEM. Copiez ces deux elements a cote "
             "de l'application (detection automatique).")

        title("Methode 2 - Volume Shadow Copy (vssadmin)")
        para("Cree un cliche du volume systeme, puis copie ntds.dit depuis "
             "le cliche et exporte la ruche SYSTEM :")
        code("vssadmin create shadow /for=C:\n"
             "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\"
             "Windows\\NTDS\\ntds.dit C:\\export\\ntds.dit\n"
             "reg save HKLM\\SYSTEM C:\\export\\SYSTEM")
        para("Remplacez HarddiskVolumeShadowCopyN par l'identifiant renvoye "
             "par 'vssadmin list shadows'.", "#94a3b8")

        title("Methode 3 - diskshadow (scriptable, Windows Server)")
        para("Equivalent VSS via diskshadow, utile en script :")
        code("diskshadow /s script.txt\n"
             "# script.txt :\n"
             "set context persistent nowriters\n"
             "add volume C: alias sys\n"
             "create\n"
             "expose %sys% Z:\n"
             "exec cmd.exe /c copy Z:\\Windows\\NTDS\\ntds.dit "
             "C:\\export\\ntds.dit\n"
             "reset")
        para("Puis exporter la ruche : reg save HKLM\\SYSTEM "
             "C:\\export\\SYSTEM")

        title("Methode 4 - Instantane ntdsutil (snapshot + mount)")
        code('ntdsutil snapshot "activate instance ntds" create quit quit\n'
             'ntdsutil snapshot "mount {GUID}" quit quit\n'
             '# copier ntds.dit depuis le point de montage, puis :\n'
             'ntdsutil snapshot "unmount {GUID}" quit quit')

        title("Ruche SYSTEM seule (si besoin)")
        para("Si vous avez deja ntds.dit mais pas SYSTEM :")
        code("reg save HKLM\\SYSTEM C:\\export\\SYSTEM")

        title("⚠  Rappels de securite")
        para("Ces fichiers contiennent TOUS les secrets du domaine. "
             "Operez sur un poste dedie/isole, ne les laissez jamais trainer, "
             "et supprimez-les avec sdelete apres l'analyse (onglet "
             "Avertissements).", "#fbbf24")
        para("N'utilisez ces techniques que sur des systemes dont vous etes "
             "proprietaire ou pour lesquels vous avez une autorisation "
             "explicite.", "#fbbf24")

        btns = ctk.CTkFrame(win, fg_color="transparent")
        btns.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkButton(btns, text="Ouvrir la doc Microsoft (ntdsutil)",
                      fg_color="#334155", hover_color="#475569",
                      command=lambda: webbrowser.open(
                          "https://learn.microsoft.com/windows-server/"
                          "administration/windows-commands/ntdsutil")).pack(
            side="left")
        ctk.CTkButton(btns, text="Fermer", width=110, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, command=win.destroy).pack(
            side="right")

        win.update_idletasks()
        x = self.winfo_rootx() + max(0, (self.winfo_width() - 760) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - 620) // 2)
        win.geometry(f"760x620+{x}+{y}")
        win.after(120, lambda: self._fade_window(win, 0.0))

    # ------------------------------------------------------- resultats -- #
    def _clear_results(self):
        for v in self._stat_cards.values():
            v.configure(text="0")
        self._pie_segments = []
        self._pie_highlight = None
        self._gauge_score = 0
        if hasattr(self, "pie_canvas"):
            self.pie_canvas.delete("all")
        if hasattr(self, "gauge_canvas"):
            self.gauge_canvas.delete("all")
        if hasattr(self, "lbl_actifs"):
            self.lbl_actifs.configure(text="")
        for w in self.legend_frame.winfo_children():
            w.destroy()
        self._table_findings = []
        self._row_finding = {}
        if hasattr(self, "tree"):
            self.tree.delete(*self.tree.get_children())
            self._show_empty_label(True)
        if hasattr(self, "report_box"):
            self.report_box.configure(state="normal")
            self.report_box.delete("1.0", "end")
            self.report_box.configure(state="disabled")

    def _animate_counter(self, widget, target: int, current: float = 0.0):
        """Microanimation ease-out (~60 fps) : le compteur monte vers la cible
        en ralentissant a l'approche, avec un petit 'pop' final."""
        if target <= 0:
            widget.configure(text="0")
            return
        current += max(1.0, (target - current) * 0.18)
        if current >= target:
            widget.configure(text=str(target))
            self._counter_pop(widget)
            return
        widget.configure(text=str(int(current)))
        self.after(self.FRAME_MS, lambda: self._animate_counter(
            widget, target, current))

    def _counter_pop(self, widget, size: int = 28):
        """Petit rebond de taille de police a la fin du comptage."""
        widget.configure(font=ctk.CTkFont(size=size, weight="bold"))
        self.after(90, lambda: widget.configure(
            font=ctk.CTkFont(size=22, weight="bold")))

    def _render_report(self, report: AnalysisReport):
        self._animate_counter(self._stat_cards["total"], report.total_accounts)
        self._animate_counter(self._stat_cards["pwned"], report.pwned_accounts)
        self._animate_counter(self._stat_cards["blank"], report.blank_accounts)
        self._animate_counter(self._stat_cards["lm"], report.lm_accounts)
        self._animate_counter(self._stat_cards["reuse"], report.reused_groups)
        self._animate_counter(self._stat_cards["machine"],
                              report.machine_accounts)

        self._render_pie(report)
        self._render_gauge(report)
        self._fill_table(report)
        # onglet Rapport (synthese texte)
        self.report_box.configure(state="normal")
        self.report_box.delete("1.0", "end")
        self.report_box.insert("end", self._report_text(report))
        self.report_box.configure(state="disabled")
        self.tabs.set("Resultats")

    # ----------------------------------------------------------- table - #
    def _fill_table(self, report: AnalysisReport):
        self._all_findings = list(report.findings)
        self._refresh_table()

    def _refresh_table(self):
        if not hasattr(self, "tree"):
            return
        query = self.search_var.get().strip().lower()
        only_risk = bool(self.only_risk_var.get())
        rows = []
        for f in getattr(self, "_all_findings", []):
            if only_risk and not f.is_at_risk:
                continue
            if query and query not in f.account.name.lower():
                continue
            rows.append(f)
        self._table_findings = rows
        self._sort_and_populate()

    @staticmethod
    def _finding_state(f) -> str:
        flags = []
        if f.account.is_blank:
            flags.append("VIDE")
        if f.pwned_count > 0 and not f.account.is_blank:
            flags.append("COMPROMIS")
        if f.account.has_lm:
            flags.append("LM")
        if f.reuse_count > 1:
            flags.append(f"reutilise x{f.reuse_count}")
        return ", ".join(flags) if flags else "OK"

    def _sort_and_populate(self):
        rows = self._table_findings
        col, desc = self._sort_col, self._sort_desc
        keyfns = {
            "compte": lambda f: f.account.name.lower(),
            "rid": lambda f: int(f.account.rid) if f.account.rid.isdigit()
            else 0,
            "actif": lambda f: f.account.enabled,
            "hibp": lambda f: f.pwned_count,
            "reuse": lambda f: f.reuse_count,
            "etat": lambda f: (f.pwned_count, f.reuse_count),
        }
        if col in keyfns:
            rows = sorted(rows, key=keyfns[col], reverse=desc)
        else:
            # tri par defaut : plus a risque d'abord
            rows = sorted(rows, key=lambda f: (-f.pwned_count, -f.reuse_count,
                                               not f.account.is_blank))
        self.tree.delete(*self.tree.get_children())
        self._row_finding = {}
        for i, f in enumerate(rows):
            sev = ("pwned" if (f.pwned_count > 0 and not f.account.is_blank)
                   else "blank" if f.account.is_blank
                   else "lm" if f.account.has_lm else "ok")
            stripe = "odd" if i % 2 else "even"
            iid = self.tree.insert(
                "", "end",
                values=(f.account.name, f.account.rid,
                        "oui" if f.account.enabled else "non",
                        f"{f.pwned_count:,}".replace(",", " ")
                        if f.pwned_count else "-",
                        f.reuse_count if f.reuse_count > 1 else "-",
                        self._finding_state(f)),
                tags=(sev, stripe))
            self._row_finding[iid] = f
        self._show_empty_label(not self.tree.get_children())

    def _show_empty_label(self, show: bool):
        """Affiche/masque l'etat vide via place() (sans ambiguite d'empilement)."""
        if show:
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.empty_label.place_forget()

    def _sort_table(self, col: str):
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = True
        self._sort_and_populate()

    def _on_row_activate(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        f = self._row_finding.get(sel[0])
        if f:
            self._show_account_details(f)

    # --------------------------------------------------------- camembert - #
    def _render_pie(self, report: AnalysisReport):
        self._pie_segments = reuse_distribution(report)
        self._pie_highlight = None
        for w in self.legend_frame.winfo_children():
            w.destroy()
        if not self._pie_segments:
            ctk.CTkLabel(self.legend_frame,
                         text="Aucun mot de passe reutilise.",
                         font=ctk.CTkFont(size=12),
                         text_color="#94a3b8").pack(anchor="w")
        else:
            for idx, s in enumerate(self._pie_segments):
                row = ctk.CTkFrame(self.legend_frame, fg_color="transparent")
                row.pack(anchor="w", fill="x", pady=1)
                dot = ctk.CTkFrame(row, width=14, height=14, corner_radius=3,
                                   fg_color=s["color"])
                dot.pack(side="left", padx=(0, 8))
                dot.pack_propagate(False)
                lab = ctk.CTkLabel(row, text=f"{s['label']}  ({s['count']})",
                                   font=ctk.CTkFont(size=12),
                                   text_color="#cbd5e1")
                lab.pack(side="left")
                # legende interactive : survol = mise en evidence de la part
                for wdg in (row, dot, lab):
                    wdg.bind("<Enter>", lambda e, i=idx: self._highlight_pie(i))
                    wdg.bind("<Leave>", lambda e: self._highlight_pie(None))
        self._pie_t = 0.0
        self._animate_pie()

    def _highlight_pie(self, index):
        self._pie_highlight = index
        self._paint_pie(self._pie_t)

    def _animate_pie(self):
        if not self.pie_canvas.winfo_exists():
            return
        self._pie_t = min(1.0, self._pie_t + 0.06)
        self._paint_pie(self._pie_t)
        if self._pie_t < 1.0:
            self.after(self.FRAME_MS, self._animate_pie)

    @staticmethod
    def _dim(color: str, factor: float = 0.35) -> str:
        """Assombrit une couleur hex vers le fond (pour estomper une part)."""
        try:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
        except Exception:
            return color
        bg = (0x15, 0x17, 0x1d)
        return "#%02x%02x%02x" % (
            int(bg[0] + (r - bg[0]) * factor),
            int(bg[1] + (g - bg[1]) * factor),
            int(bg[2] + (b - bg[2]) * factor))

    def _paint_pie(self, t: float):
        c = self.pie_canvas
        c.delete("all")
        segs = self._pie_segments
        w = int(c.cget("width"))
        h = int(c.cget("height"))
        pad = 8
        x0, y0, x1, y1 = pad, pad, w - pad, h - pad
        total = sum(s["count"] for s in segs)
        if total <= 0:
            c.create_oval(x0, y0, x1, y1, fill=UNIQUE_COLOR, outline="")
            return
        start = 90.0
        for idx, s in enumerate(segs):
            ext = (s["count"] / total) * 360.0 * t
            if ext <= 0:
                continue
            color = s["color"]
            if self._pie_highlight is not None and idx != self._pie_highlight:
                color = self._dim(color)
            c.create_arc(x0, y0, x1, y1, start=start, extent=-ext,
                         fill=color, outline="")
            start -= ext
        cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
        hr = (x1 - x0) * 0.30
        c.create_oval(cx - hr, cy - hr, cx + hr, cy + hr,
                      fill="#15171d", outline="")
        if self._pie_highlight is not None \
                and 0 <= self._pie_highlight < len(segs):
            s = segs[self._pie_highlight]
            c.create_text(cx, cy - 7, text=str(s["count"]), fill="#e2e8f0",
                          font=("Segoe UI", 18, "bold"))
            c.create_text(cx, cy + 13, text="comptes", fill="#94a3b8",
                          font=("Segoe UI", 8))
        else:
            reused = sum(s["count"] for s in segs if s.get("reuse"))
            c.create_text(cx, cy - 7, text=str(reused), fill="#e2e8f0",
                          font=("Segoe UI", 18, "bold"))
            c.create_text(cx, cy + 13, text="reutilises", fill="#94a3b8",
                          font=("Segoe UI", 8))

    # ------------------------------------------------------ jauge risque - #
    @staticmethod
    def _compute_risk_score(report: AnalysisReport) -> int:
        if report.total_accounts <= 0:
            return 0
        base = max(1, report.total_accounts)
        at_risk = len(report.at_risk)
        return int(round(100 * at_risk / base))

    def _render_gauge(self, report: AnalysisReport):
        self._gauge_score = self._compute_risk_score(report)
        active = sum(1 for f in report.findings if f.account.enabled)
        disabled = report.total_accounts - active
        self.lbl_actifs.configure(
            text=f"Actifs : {active}    Desactives : {disabled}")
        self._gauge_t = 0.0
        self._animate_gauge()

    def _animate_gauge(self):
        if not self.gauge_canvas.winfo_exists():
            return
        self._gauge_t = min(1.0, self._gauge_t + 0.05)
        self._paint_gauge(self._gauge_t)
        if self._gauge_t < 1.0:
            self.after(self.FRAME_MS, self._animate_gauge)

    def _paint_gauge(self, t: float):
        c = self.gauge_canvas
        c.delete("all")
        w = int(c.cget("width"))
        h = int(c.cget("height"))
        pad = 18
        x0, y0 = pad, 16
        x1, y1 = w - pad, 16 + 2 * (h - 40)
        score = self._gauge_score
        color = (OK if score < 25 else WARN if score < 60 else DANGER)
        # arc de fond (demi-cercle superieur)
        c.create_arc(x0, y0, x1, y1, start=0, extent=180, style="arc",
                     outline="#2a2e37", width=16)
        # arc colore proportionnel au score (anime)
        sweep = 180.0 * (score / 100.0) * t
        if sweep > 0:
            c.create_arc(x0, y0, x1, y1, start=180, extent=-sweep,
                         style="arc", outline=color, width=16)
        cx = (x0 + x1) / 2
        cy = y0 + (y1 - y0) / 2
        c.create_text(cx, cy - 6, text=f"{int(score * t)}",
                      fill=color, font=("Segoe UI", 30, "bold"))
        c.create_text(cx, cy + 22, text="/ 100  risque",
                      fill="#94a3b8", font=("Segoe UI", 10))

    # --------------------------------------------------- detail compte - #
    def _show_account_details(self, finding):
        existing = getattr(self, "_detail_win", None)
        if existing is not None and existing.winfo_exists():
            existing.destroy()
        win = ctk.CTkToplevel(self)
        self._detail_win = win
        win.title(f"Compte - {finding.account.name}")
        win.resizable(False, False)
        win.transient(self)
        try:
            win.attributes("-alpha", 0.0)
        except Exception:
            pass

        wrap = ctk.CTkFrame(win, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        ctk.CTkLabel(wrap, text=finding.account.name,
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#e2e8f0").pack(anchor="w")

        def field(label, value, color="#e2e8f0"):
            row = ctk.CTkFrame(wrap, fg_color="transparent")
            row.pack(anchor="w", fill="x", pady=2)
            ctk.CTkLabel(row, text=label, width=180, anchor="w",
                         font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(
                side="left")
            ctk.CTkLabel(row, text=value, anchor="w",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=color).pack(side="left")

        acc = finding.account
        field("RID", acc.rid)
        field("Statut", "Active" if acc.enabled else "Desactive",
              OK if acc.enabled else "#94a3b8")
        field("Mot de passe vide", "OUI" if acc.is_blank else "non",
              DANGER if acc.is_blank else "#94a3b8")
        field("Hash LM present", "OUI" if acc.has_lm else "non",
              WARN if acc.has_lm else "#94a3b8")
        pwn = (f"{finding.pwned_count:,}".replace(",", " ")
               if finding.pwned_count else "non compromis")
        field("Occurrences HIBP", pwn,
              DANGER if finding.pwned_count else OK)

        # membres du groupe de reutilisation
        ctk.CTkFrame(wrap, height=1, fg_color="#334155").pack(
            fill="x", pady=(10, 6))
        members = []
        if self._report and not acc.is_blank:
            for g in self._report.reuse_groups():
                if g and g[0].account.nt_hash == acc.nt_hash:
                    members = [m.account.name for m in g]
                    break
        if members:
            ctk.CTkLabel(
                wrap, text=f"Mot de passe partage avec {len(members) - 1} "
                           f"autre(s) compte(s) :",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=WARN).pack(anchor="w")
            box = ctk.CTkTextbox(wrap, height=110, width=420,
                                 font=ctk.CTkFont(family="Consolas", size=11))
            box.pack(fill="x", pady=(4, 4))
            box.insert("end", "\n".join(sorted(members)))
            box.configure(state="disabled")
        else:
            ctk.CTkLabel(wrap, text="Mot de passe non reutilise.",
                         font=ctk.CTkFont(size=12),
                         text_color="#94a3b8").pack(anchor="w")

        ctk.CTkButton(wrap, text="Fermer", width=110, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, command=win.destroy).pack(
            anchor="e", pady=(12, 0))

        win.update_idletasks()
        ww = wrap.winfo_reqwidth() + 48
        hh = wrap.winfo_reqheight() + 40
        x = self.winfo_rootx() + max(0, (self.winfo_width() - ww) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - hh) // 2)
        win.geometry(f"{ww}x{hh}+{x}+{y}")
        win.after(120, lambda: self._fade_window(win, 0.0))

    def _report_text(self, report: AnalysisReport) -> str:
        lines = []
        lines.append("=" * 78)
        lines.append(f"  RAPPORT D'ANALYSE NTDS / HIBP  -  mode {report.mode}")
        lines.append("=" * 78)
        lines.append(f"  Comptes analyses .............. {report.total_accounts}")
        lines.append(f"  Compromis (presents dans HIBP)  {report.pwned_accounts}")
        lines.append(f"  Sans mot de passe ............. {report.blank_accounts}")
        lines.append(f"  Avec hash LM (faible) ......... {report.lm_accounts}")
        lines.append(f"  Mots de passe reutilises ...... {report.reused_groups} groupe(s)")
        lines.append("")
        at_risk = sorted(report.at_risk,
                         key=lambda f: (-f.pwned_count, -f.reuse_count))
        if not at_risk:
            lines.append("  Aucun compte a risque detecte. ")
        else:
            lines.append(f"  COMPTES A RISQUE ({len(at_risk)}) :")
            lines.append("-" * 78)
            lines.append(f"  {'Compte':<38} {'HIBP':>10} {'Reutil.':>8}  Etat")
            lines.append("-" * 78)
            for f in at_risk:
                flags = []
                if f.account.is_blank:
                    flags.append("VIDE")
                if f.pwned_count > 0 and not f.account.is_blank:
                    flags.append("COMPROMIS")
                if f.account.has_lm:
                    flags.append("LM")
                if f.reuse_count > 1:
                    flags.append(f"x{f.reuse_count}")
                name = f.account.name[:37]
                pw = f"{f.pwned_count:,}" if f.pwned_count else "-"
                reuse = str(f.reuse_count) if f.reuse_count > 1 else "-"
                lines.append(f"  {name:<38} {pw:>10} {reuse:>8}  "
                             f"{', '.join(flags)}")
        lines.append("")
        lines.append("=" * 78)
        lines.append("  RAPPEL : supprimez ntds.dit et SYSTEM avec sdelete.")
        lines.append("  " + sdelete_command(
            [self.sel_ntds.get(), self.sel_system.get()]))
        lines.append("=" * 78)
        return "\n".join(lines)

    # --------------------------------------------------------- export --- #
    def _export(self):
        if not self._report:
            return
        path = filedialog.asksaveasfilename(
            title="Exporter le rapport", defaultextension=".html",
            filetypes=[("Rapport HTML", "*.html"), ("JSON", "*.json"),
                       ("CSV", "*.csv"), ("Texte", "*.txt")],
            initialfile="rapport_ntds_hibp.html")
        if not path:
            return
        low = path.lower()
        try:
            if low.endswith(".html") or low.endswith(".htm"):
                to_html(self._report, path)
            elif low.endswith(".json"):
                to_json(self._report, path)
            elif low.endswith(".csv"):
                to_csv(self._report, path)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self._report_text(self._report))
            self._toast(f"Rapport exporte : {os.path.basename(path)}", "ok")
            if low.endswith((".html", ".htm")):
                try:
                    webbrowser.open("file:///" + path.replace("\\", "/"))
                except Exception:
                    pass
        except Exception as exc:        # noqa
            self._toast(f"Echec de l'export : {exc}", "error")

    # ------------------------------------------------------- sdelete --- #
    def _secure_delete(self):
        files = [p for p in (self.sel_ntds.get(), self.sel_system.get())
                 if p and os.path.isfile(p)]
        if not files:
            messagebox.showwarning("sdelete", "Aucun fichier a supprimer.")
            return
        if not messagebox.askyesno(
                "Suppression securisee",
                "Cette operation efface DEFINITIVEMENT (7 passes) :\n\n"
                + "\n".join(files) + "\n\nConfirmer ?"):
            return
        # sdelete peut etre long : on l'execute dans un thread pour ne pas
        # geler la GUI ; le resultat revient via la file d'attente.
        self.btn_sdelete.configure(state="disabled")
        self._set_status("Suppression securisee en cours (sdelete)...")

        def _work():
            res = secure_delete(files, passes=7)
            self._queue.put(("sdelete", res))

        threading.Thread(target=_work, daemon=True).start()

    def _on_sdelete_done(self, ok: bool, msg: str):
        self.btn_sdelete.configure(state="normal")
        if ok:
            self._toast(msg, "ok")
            self._set_status("Fichiers supprimes de facon securisee.")
            # rafraichir les champs si les fichiers ont disparu
            if not os.path.isfile(self.sel_ntds.get()):
                self.sel_ntds.set("")
            if not os.path.isfile(self.sel_system.get()):
                self.sel_system.set("")
        else:
            # un echec necessite souvent une action manuelle (commande a
            # copier) : on garde une boite de dialogue lisible.
            messagebox.showwarning("sdelete", msg)
            self._set_status("Suppression securisee : echec ou action manuelle requise.")

    # ---------------------------------------------------------- toasts -- #
    def _toast(self, message: str, kind: str = "ok", duration: int = 3200):
        """Notification ephemere glissant depuis le coin bas-droit, avec fondu."""
        colors = {"ok": ("#064e3b", "#6ee7b7"),
                  "error": ("#7f1d1d", "#fecaca"),
                  "info": ("#1e3a8a", "#bfdbfe")}
        bg, fg = colors.get(kind, colors["info"])
        tw = tk.Toplevel(self)
        tw.wm_overrideredirect(True)
        try:
            tw.attributes("-alpha", 0.0)
            tw.attributes("-topmost", True)
        except Exception:
            pass
        tw.configure(bg=bg)
        frame = tk.Frame(tw, bg=bg)
        frame.pack(padx=1, pady=1)
        tk.Label(frame, text=message, bg=bg, fg=fg, justify="left",
                 wraplength=320, font=("Segoe UI", 10, "bold"),
                 padx=16, pady=12).pack()
        tw.update_idletasks()
        w = tw.winfo_width()
        h = tw.winfo_height()
        # position finale : coin bas-droit de la fenetre principale
        fx = self.winfo_rootx() + self.winfo_width() - w - 24
        fy0 = self.winfo_rooty() + self.winfo_height() - h - 24
        state = {"alpha": 0.0, "off": 24.0, "phase": "in", "elapsed": 0}

        def step():
            if not tw.winfo_exists():
                return
            if state["phase"] == "in":
                state["alpha"] = min(0.96, state["alpha"] + 0.12)
                state["off"] = max(0.0, state["off"] - 3.0)   # glisse vers le haut
                if state["alpha"] >= 0.96 and state["off"] <= 0.0:
                    state["phase"] = "hold"
            elif state["phase"] == "hold":
                state["elapsed"] += self.FRAME_MS
                if state["elapsed"] >= duration:
                    state["phase"] = "out"
            else:  # out
                state["alpha"] -= 0.10
                state["off"] += 3.0
                if state["alpha"] <= 0.0:
                    try:
                        tw.destroy()
                    except Exception:
                        pass
                    return
            try:
                tw.attributes("-alpha", max(0.0, state["alpha"]))
                tw.wm_geometry(f"+{fx}+{int(fy0 + state['off'])}")
            except Exception:
                pass
            tw.after(self.FRAME_MS, step)

        step()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
