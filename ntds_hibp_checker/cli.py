"""
Interface en ligne de commande (CLI) du NTDS HIBP Checker.

Permet d'executer l'analyse sans interface graphique, utile pour les
environnements sans affichage (serveur, CI) ou l'automatisation.

Usage :
  python app.py --ntds ntds.dit --system SYSTEM [options]
  NTDS-HIBP-Checker.exe --ntds ntds.dit --system SYSTEM [options]
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

from . import __app_name__, __version__, __author__, __url__
from .analyzer import Analyzer, AnalysisReport, Phase, Progress, AccountStatus
from .downloader import download_hibp_ntlm, TOTAL_PREFIXES
from .report import to_json, to_csv, to_html, reuse_distribution
from .security import SECURITY_WARNINGS, sdelete_command


# ---- couleurs ANSI (desactivees si le terminal ne les supporte pas) -------- #
def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(kernel32.GetStdHandle(-11), ctypes.byref(mode))
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), mode.value | 0x0004)
            return True
        except Exception:
            return os.environ.get("TERM") is not None
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = _supports_color()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def red(t): return _c("91", t)
def yellow(t): return _c("93", t)
def green(t): return _c("92", t)
def cyan(t): return _c("96", t)
def bold(t): return _c("1", t)
def dim(t): return _c("90", t)


# ---- auto-detection (reutilise la logique de gui.py sans les deps GUI) ----- #
def _autodetect(filename_options, subdirs=("", "Active Directory", "registry")):
    wanted = [f.lower() for f in filename_options]
    for base in (os.getcwd(),):
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
    return None


# ---- point d'entree CLI --------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=__app_name__,
        description=f"{__app_name__} v{__version__} - {__author__}\n"
                    f"Analyse ntds.dit et compare les hash NT a HaveIBeenPwned.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Exemples :\n"
               f"  python app.py --ntds ntds.dit --system SYSTEM\n"
               f"  python app.py --ntds ntds.dit --system SYSTEM --format html --output rapport.html\n"
               f"  python app.py --ntds ntds.dit --system SYSTEM --mode local --hibp-file pwnedpasswords_ntlm.txt\n"
               f"  python app.py --download-hibp pwnedpasswords_ntlm.txt\n"
               f"\n{__author__} - {__url__}",
    )
    p.add_argument("--download-hibp", metavar="FILE",
                   help="Telecharger la base HIBP NTLM complete dans FILE "
                        "(plusieurs dizaines de Go, 1h+). "
                        "Ignore les options d'analyse.")
    p.add_argument("--ntds", metavar="FILE",
                   help="Chemin vers le fichier ntds.dit "
                        "(auto-detecte dans le dossier courant)")
    p.add_argument("--system", metavar="FILE",
                   help="Chemin vers la ruche SYSTEM "
                        "(auto-detecte dans le dossier courant)")
    p.add_argument("--mode", choices=["online", "local"], default="online",
                   help="Mode de verification HIBP (defaut : online)")
    p.add_argument("--hibp-file", metavar="FILE",
                   help="Fichier HIBP NTLM local (requis si --mode local)")
    p.add_argument("--include-machine", action="store_true", default=False,
                   help="Inclure les comptes machine ($) dans la verification HIBP")
    p.add_argument("--no-cache", action="store_true", default=False,
                   help="Desactiver le cache persistant SQLite")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="Chemin du fichier de rapport a generer")
    p.add_argument("--format", "-f", choices=["json", "csv", "html", "txt"],
                   default=None,
                   help="Format du rapport (deduit de l'extension de --output, "
                        "ou txt par defaut)")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Mode silencieux : uniquement le resume final")
    p.add_argument("--version", "-V", action="version",
                   version=f"{__app_name__} v{__version__}")
    return p


def _resolve_format(args) -> Optional[str]:
    if args.format:
        return args.format
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        mapping = {".json": "json", ".csv": "csv", ".html": "html",
                   ".htm": "html", ".txt": "txt"}
        return mapping.get(ext, "txt")
    return None


def _print_progress(p: Progress, quiet: bool):
    if quiet:
        return
    if p.phase == Phase.EXTRACTION:
        print(f"\r  {dim('[extraction]')} {p.message}", end="", flush=True)
    elif p.phase == Phase.HIBP:
        pct = f"{p.current}/{p.total}" if p.total else str(p.current)
        bar = ""
        if p.total > 0:
            filled = int(30 * p.current / p.total)
            bar = f" [{'#' * filled}{'.' * (30 - filled)}]"
            pct += f" ({100 * p.current / p.total:.0f}%)"
        print(f"\r  {dim('[hibp]')} {pct}{bar}  ", end="", flush=True)
    elif p.phase == Phase.DONE:
        print(f"\r  {green('Analyse terminee.')}" + " " * 40)


def _print_report(report: AnalysisReport, quiet: bool):
    w = 72
    print()
    print(bold("=" * w))
    print(bold(f"  RAPPORT D'ANALYSE NTDS / HIBP  -  mode {report.mode}"))
    print(bold("=" * w))
    print()

    # -- resume chiffre -- #
    def stat(label, value, color_fn=None):
        v = str(value)
        if color_fn:
            v = color_fn(v)
        print(f"  {label:<40} {v}")

    stat("Comptes analyses", report.total_accounts)
    stat("Compromis (presents dans HIBP)",
         report.pwned_accounts, red if report.pwned_accounts else None)
    stat("Sans mot de passe",
         report.blank_accounts, yellow if report.blank_accounts else None)
    stat("Avec hash LM (faible)",
         report.lm_accounts, yellow if report.lm_accounts else None)
    stat(f"Mots de passe reutilises",
         f"{report.reused_groups} groupe(s)",
         yellow if report.reused_groups else None)
    stat("Comptes machine",
         f"{report.machine_accounts}" +
         (" (exclus de HIBP)" if report.machine_skipped else ""))
    print()

    # -- groupes de reutilisation de mots de passe -- #
    groups = report.reuse_groups()
    if groups:
        print(bold("-" * w))
        print(bold(yellow(
            f"  MOTS DE PASSE IDENTIQUES ({len(groups)} groupe(s))")))
        print(bold("-" * w))
        for i, g in enumerate(groups, 1):
            names = [f.account.name for f in g]
            pwned = g[0].pwned_count if g else 0
            hibp_tag = red(f" [HIBP: {pwned:,}x]") if pwned else ""
            print(f"\n  {yellow(f'Groupe {i}')} - "
                  f"{bold(str(len(g)))} comptes partagent le meme mot de passe"
                  f"{hibp_tag}")
            for name in sorted(names):
                enabled = ""
                for f in g:
                    if f.account.name == name:
                        if not f.account.enabled:
                            enabled = dim(" (desactive)")
                        break
                print(f"    - {name}{enabled}")
        print()

    # -- comptes a risque -- #
    at_risk = sorted(report.at_risk,
                     key=lambda f: (-f.pwned_count, -f.reuse_count))
    if at_risk and not quiet:
        print(bold("-" * w))
        print(bold(red(f"  COMPTES A RISQUE ({len(at_risk)})")))
        print(bold("-" * w))
        print(f"  {'Compte':<38} {'HIBP':>10} {'Reutil.':>8}  Etat")
        print(f"  {'-'*37}  {'-'*10} {'-'*8}  {'-'*14}")
        for f in at_risk:
            flags = []
            if f.account.is_blank:
                flags.append(yellow("VIDE"))
            if f.pwned_count > 0 and not f.account.is_blank:
                flags.append(red("COMPROMIS"))
            if f.account.has_lm:
                flags.append(yellow("LM"))
            if f.reuse_count > 1:
                flags.append(cyan(f"x{f.reuse_count}"))
            name = f.account.name[:37]
            pw = f"{f.pwned_count:,}" if f.pwned_count else "-"
            reuse = str(f.reuse_count) if f.reuse_count > 1 else "-"
            print(f"  {name:<38} {pw:>10} {reuse:>8}  "
                  f"{', '.join(flags)}")
        print()

    if not at_risk:
        print(f"  {green('Aucun compte a risque detecte.')}")
        print()

    # -- rappel securite -- #
    print(bold("=" * w))
    print(yellow("  RAPPEL : supprimez ntds.dit et SYSTEM avec sdelete apres"))
    print(yellow("  l'analyse, et forcez la reinitialisation des mots de passe"))
    print(yellow("  compromis (+ krbtgt deux fois)."))
    print(bold("=" * w))


def _export_report(report: AnalysisReport, path: str, fmt: str):
    if fmt == "json":
        to_json(report, path)
    elif fmt == "csv":
        to_csv(report, path)
    elif fmt == "html":
        to_html(report, path)
    else:
        lines = _report_text_plain(report)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(lines)


def _report_text_plain(report: AnalysisReport) -> str:
    """Genere un rapport texte brut (sans codes ANSI)."""
    lines = []
    w = 72
    lines.append("=" * w)
    lines.append(f"  RAPPORT D'ANALYSE NTDS / HIBP  -  mode {report.mode}")
    lines.append(f"  {__app_name__} v{__version__} - {__author__}")
    lines.append(f"  Genere le {time.strftime('%d/%m/%Y a %H:%M')}")
    lines.append("=" * w)
    lines.append(f"  Comptes analyses .............. {report.total_accounts}")
    lines.append(f"  Compromis (presents dans HIBP)  {report.pwned_accounts}")
    lines.append(f"  Sans mot de passe ............. {report.blank_accounts}")
    lines.append(f"  Avec hash LM (faible) ......... {report.lm_accounts}")
    lines.append(f"  Mots de passe reutilises ...... {report.reused_groups} groupe(s)")
    lines.append(f"  Comptes machine ............... {report.machine_accounts}"
                 f"{' (exclus de HIBP)' if report.machine_skipped else ''}")
    lines.append("")

    groups = report.reuse_groups()
    if groups:
        lines.append("-" * w)
        lines.append(f"  MOTS DE PASSE IDENTIQUES ({len(groups)} groupe(s))")
        lines.append("-" * w)
        for i, g in enumerate(groups, 1):
            names = sorted(f.account.name for f in g)
            pwned = g[0].pwned_count if g else 0
            hibp_tag = f" [HIBP: {pwned:,}x]" if pwned else ""
            lines.append(f"\n  Groupe {i} - {len(g)} comptes{hibp_tag}")
            for name in names:
                lines.append(f"    - {name}")
        lines.append("")

    at_risk = sorted(report.at_risk,
                     key=lambda f: (-f.pwned_count, -f.reuse_count))
    if at_risk:
        lines.append("-" * w)
        lines.append(f"  COMPTES A RISQUE ({len(at_risk)})")
        lines.append("-" * w)
        lines.append(f"  {'Compte':<38} {'HIBP':>10} {'Reutil.':>8}  Etat")
        lines.append(f"  {'-'*37}  {'-'*10} {'-'*8}  {'-'*14}")
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
    else:
        lines.append("  Aucun compte a risque detecte.")
    lines.append("")
    lines.append("=" * w)
    lines.append("  RAPPEL : supprimez ntds.dit et SYSTEM avec sdelete.")
    lines.append("=" * w)
    return "\n".join(lines)


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}min"
    if m:
        return f"{m}min{s:02d}s"
    return f"{s}s"


def _fmt_size(nbytes: float) -> str:
    if nbytes >= 1 << 30:
        return f"{nbytes / (1 << 30):.1f} Go"
    if nbytes >= 1 << 20:
        return f"{nbytes / (1 << 20):.1f} Mo"
    return f"{nbytes / (1 << 10):.0f} Ko"


def _run_download(args):
    out_path = args.download_hibp
    print()
    print(bold(f"  {__app_name__} v{__version__} - Telechargement base HIBP"))
    print(dim(f"  {__author__} - {__url__}"))
    print()
    print(f"  Destination : {out_path}")
    print(f"  Plages API  : {TOTAL_PREFIXES:,} prefixes a telecharger")
    print()
    print(yellow("  [!] Le fichier final pese plusieurs dizaines de Go."))
    print(yellow("      Le telechargement peut durer 1 a plusieurs heures."))
    print(yellow("      Ctrl+C pour annuler (le fichier .part est conserve)."))
    print()

    t0 = time.time()
    last_print = [0.0]

    def on_progress(done: int, total: int):
        now = time.time()
        if now - last_print[0] < 0.5 and done < total:
            return
        last_print[0] = now

        elapsed = now - t0
        pct = 100 * done / total if total else 0
        filled = int(40 * done / total) if total else 0
        bar = f"[{'#' * filled}{'.' * (40 - filled)}]"

        eta_txt = ""
        speed_txt = ""
        size_txt = ""
        if done > 0 and elapsed > 2:
            rate = done / elapsed
            remaining = (total - done) / rate if rate > 0 else 0
            eta_txt = f"  ETA {_fmt_duration(remaining)}"
            speed_txt = f"  {rate:.0f} plages/s"
            # estimation taille : ~540 octets par plage en moyenne
            est_size = done * 540
            size_txt = f"  ~{_fmt_size(est_size)}"

        print(f"\r  {bar} {pct:5.1f}%  {done:>10,}/{total:,}"
              f"{speed_txt}{size_txt}{eta_txt}    ",
              end="", flush=True)

    try:
        download_hibp_ntlm(out_path, on_progress=on_progress)
    except KeyboardInterrupt:
        elapsed = time.time() - t0
        print(f"\n\n  {yellow('Telechargement interrompu.')} "
              f"({_fmt_duration(elapsed)})")
        print(f"  Le fichier partiel est conserve : {out_path}.part")
        sys.exit(130)
    except Exception as exc:
        print(f"\n\n  {red(f'Erreur : {exc}')}")
        sys.exit(1)

    elapsed = time.time() - t0
    try:
        size = os.path.getsize(out_path)
    except OSError:
        size = 0
    print(f"\n\n  {green('Telechargement termine.')}")
    print(f"  Fichier : {out_path} ({_fmt_size(size)})")
    print(f"  Duree   : {_fmt_duration(elapsed)}")
    print()
    print(f"  Utilisez ensuite :")
    print(dim(f"    --mode local --hibp-file \"{out_path}\""))
    sys.exit(0)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # mode telechargement : prioritaire, ignore les options d'analyse
    if args.download_hibp:
        _run_download(args)
        return

    # auto-detection
    ntds = args.ntds or _autodetect(["ntds.dit"])
    system = args.system or _autodetect(["SYSTEM"])

    if not ntds:
        parser.error("Fichier ntds.dit non specifie et non trouve dans le "
                     "dossier courant. Utilisez --ntds.")
    if not system:
        parser.error("Ruche SYSTEM non specifiee et non trouvee dans le "
                     "dossier courant. Utilisez --system.")
    if not os.path.isfile(ntds):
        parser.error(f"Fichier ntds.dit introuvable : {ntds}")
    if not os.path.isfile(system):
        parser.error(f"Ruche SYSTEM introuvable : {system}")
    if args.mode == "local" and not args.hibp_file:
        parser.error("Mode local : specifiez le fichier HIBP NTLM avec "
                     "--hibp-file.")
    if args.mode == "local" and args.hibp_file \
            and not os.path.isfile(args.hibp_file):
        parser.error(f"Fichier HIBP introuvable : {args.hibp_file}")

    # banniere
    if not args.quiet:
        print()
        print(bold(f"  {__app_name__} v{__version__}"))
        print(dim(f"  {__author__} - {__url__}"))
        print()
        print(f"  ntds.dit : {ntds}")
        print(f"  SYSTEM   : {system}")
        print(f"  Mode     : {args.mode}")
        if args.mode == "local":
            print(f"  HIBP     : {args.hibp_file}")
        print()

    # avertissement securite
    if not args.quiet and args.mode == "online":
        print(yellow("  [!] Mode en ligne : les 5 premiers caracteres de chaque"))
        print(yellow("      hash NT seront envoyes a l'API HIBP (k-anonymity)."))
        print(yellow("      Le hash complet ne quitte jamais le poste."))
        print()

    # callbacks de progression
    t0 = time.time()

    def on_progress(p: Progress):
        _print_progress(p, args.quiet)

    def on_log(msg: str):
        if not args.quiet:
            print(f"\r  {dim('[log]')} {msg}" + " " * 20)

    # analyse
    analyzer = Analyzer(
        ntds_path=ntds,
        system_path=system,
        use_online=(args.mode == "online"),
        local_hibp_file=args.hibp_file or None,
        ignore_machine=not args.include_machine,
        use_cache=not args.no_cache,
        on_progress=on_progress,
        on_log=on_log,
    )

    try:
        report = analyzer.run()
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Analyse interrompue par l utilisateur.')}")
        sys.exit(130)
    except Exception as exc:
        print(f"\n\n  {red(f'Erreur : {exc}')}")
        sys.exit(1)

    elapsed = time.time() - t0
    if not args.quiet:
        print(dim(f"\n  Analyse terminee en {elapsed:.1f}s"))

    # affichage du rapport
    _print_report(report, args.quiet)

    # export
    fmt = _resolve_format(args)
    if args.output and fmt:
        try:
            _export_report(report, args.output, fmt)
            print(f"\n  {green(f'Rapport exporte : {args.output}')} "
                  f"({os.path.getsize(args.output):,} octets)")
        except Exception as exc:
            print(f"\n  {red(f'Echec de l export : {exc}')}")
            sys.exit(1)

    # code de sortie
    if report.pwned_accounts > 0 or report.blank_accounts > 0:
        sys.exit(2)
    sys.exit(0)
