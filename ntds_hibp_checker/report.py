"""
Generation des rapports d'analyse : CSV, JSON et HTML (mise en page soignee,
camembert SVG embarque). Aussi : calcul de la distribution de reutilisation
des mots de passe, partagee par le camembert de l'interface.

Auteur : Ayi NEDJIMI Consultants - https://ayinedjimi-consultants.fr
"""

from __future__ import annotations

import csv
import html
import json
import math
import time
from typing import List

from . import __app_name__, __author__, __url__, __version__

# Palette utilisee pour le camembert (interface + HTML).
PALETTE = ["#ef4444", "#f59e0b", "#3b82f6", "#8b5cf6", "#ec4899",
           "#14b8a6", "#84cc16", "#f97316", "#06b6d4", "#a855f7"]
UNIQUE_COLOR = "#334155"      # part "mots de passe uniques"


def reuse_distribution(report, top: int = 8) -> List[dict]:
    """Repartition des comptes par mot de passe partage, pour le camembert.

    Chaque segment = un groupe de comptes partageant un meme hash NT, plus un
    segment agregé 'autres groupes' et un segment 'mots de passe uniques'.
    """
    groups = report.reuse_groups()           # listes triees par taille desc.
    segments: List[dict] = []
    for i, g in enumerate(groups[:top]):
        sample = g[0].account.name
        segments.append({
            "label": f"{len(g)} comptes - ex. {sample}",
            "count": len(g),
            "color": PALETTE[i % len(PALETTE)],
            "reuse": True,
        })
    if len(groups) > top:
        extra = sum(len(g) for g in groups[top:])
        segments.append({
            "label": f"{len(groups) - top} autres groupes",
            "count": extra,
            "color": "#64748b",
            "reuse": True,
        })
    reused_accounts = sum(len(g) for g in groups)
    nonblank = sum(1 for f in report.findings if not f.account.is_blank)
    uniques = max(0, nonblank - reused_accounts)
    if uniques > 0:
        segments.append({
            "label": "Mots de passe uniques",
            "count": uniques,
            "color": UNIQUE_COLOR,
            "reuse": False,
        })
    return segments


# --------------------------------------------------------------------------- #
#  Camembert SVG (utilise dans l'export HTML)
# --------------------------------------------------------------------------- #
def svg_pie(segments: List[dict], size: int = 260, donut: float = 0.58) -> str:
    total = sum(s["count"] for s in segments)
    cx = cy = size / 2
    r = size / 2 - 6
    if total <= 0:
        return (f'<svg viewBox="0 0 {size} {size}" width="{size}" '
                f'height="{size}"><circle cx="{cx}" cy="{cy}" r="{r}" '
                f'fill="{UNIQUE_COLOR}"/></svg>')
    parts = []
    angle = -90.0
    for s in segments:
        frac = s["count"] / total
        if frac >= 0.9999:                # un seul segment : cercle plein
            parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" '
                         f'fill="{s["color"]}"/>')
            break
        a0 = math.radians(angle)
        angle2 = angle + frac * 360.0
        a1 = math.radians(angle2)
        x0, y0 = cx + r * math.cos(a0), cy + r * math.sin(a0)
        x1, y1 = cx + r * math.cos(a1), cy + r * math.sin(a1)
        large = 1 if frac > 0.5 else 0
        parts.append(
            f'<path d="M{cx:.1f},{cy:.1f} L{x0:.1f},{y0:.1f} '
            f'A{r:.1f},{r:.1f} 0 {large} 1 {x1:.1f},{y1:.1f} Z" '
            f'fill="{s["color"]}"/>')
        angle = angle2
    inner = ""
    if donut:
        inner = (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r * donut:.1f}" '
                 f'fill="#0b1220"/>')
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'{"".join(parts)}{inner}</svg>')


# --------------------------------------------------------------------------- #
#  Donnees serialisables
# --------------------------------------------------------------------------- #
def report_to_dict(report) -> dict:
    return {
        "application": __app_name__,
        "version": __version__,
        "author": __author__,
        "url": __url__,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": report.mode,
        "summary": {
            "total_accounts": report.total_accounts,
            "pwned_accounts": report.pwned_accounts,
            "blank_accounts": report.blank_accounts,
            "lm_accounts": report.lm_accounts,
            "reused_groups": report.reused_groups,
            "machine_accounts": report.machine_accounts,
            "machine_skipped": report.machine_skipped,
        },
        "accounts": [
            {
                "name": f.account.name,
                "rid": f.account.rid,
                "enabled": f.account.enabled,
                "blank_password": f.account.is_blank,
                "has_lm_hash": f.account.has_lm,
                "hibp_count": f.pwned_count,
                "reuse_count": f.reuse_count,
                "at_risk": f.is_at_risk,
            }
            for f in report.findings
        ],
        "reuse_groups": [
            {
                "shared_by": len(g),
                "accounts": [f.account.name for f in g],
            }
            for g in report.reuse_groups()
        ],
    }


# --------------------------------------------------------------------------- #
#  Exports
# --------------------------------------------------------------------------- #
def to_json(report, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report_to_dict(report), fh, ensure_ascii=False, indent=2)


def to_csv(report, path: str):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["compte", "rid", "active", "hibp_count", "reutilisations",
                    "sans_mdp", "hash_lm", "a_risque"])
        for f in report.findings:
            w.writerow([
                f.account.name, f.account.rid,
                "oui" if f.account.enabled else "non",
                f.pwned_count, f.reuse_count,
                "oui" if f.account.is_blank else "non",
                "oui" if f.account.has_lm else "non",
                "oui" if f.is_at_risk else "non",
            ])


def _esc(s) -> str:
    return html.escape(str(s))


def to_html(report, path: str):
    segments = reuse_distribution(report)
    pie = svg_pie(segments)

    legend_rows = "".join(
        f'<li><span class="dot" style="background:{s["color"]}"></span>'
        f'<span class="lbl">{_esc(s["label"])}</span>'
        f'<span class="cnt">{s["count"]}</span></li>'
        for s in segments)

    at_risk = sorted(report.at_risk,
                     key=lambda f: (-f.pwned_count, -f.reuse_count))
    risk_rows = ""
    for f in at_risk:
        flags = []
        if f.account.is_blank:
            flags.append('<span class="tag blank">VIDE</span>')
        if f.pwned_count > 0 and not f.account.is_blank:
            flags.append('<span class="tag pwned">COMPROMIS</span>')
        if f.account.has_lm:
            flags.append('<span class="tag lm">LM</span>')
        if f.reuse_count > 1:
            flags.append(f'<span class="tag reuse">x{f.reuse_count}</span>')
        risk_rows += (
            f"<tr><td>{_esc(f.account.name)}</td>"
            f"<td class='num'>{f.pwned_count:,}</td>"
            f"<td class='num'>{f.reuse_count if f.reuse_count > 1 else '-'}</td>"
            f"<td>{''.join(flags)}</td></tr>")
    if not risk_rows:
        risk_rows = ("<tr><td colspan='4' class='ok'>Aucun compte a risque "
                     "detecte.</td></tr>")

    reuse_rows = ""
    for g in report.reuse_groups():
        names = ", ".join(_esc(x.account.name) for x in g)
        reuse_rows += (f"<tr><td class='num'>{len(g)}</td>"
                       f"<td>{names}</td></tr>")
    if not reuse_rows:
        reuse_rows = ("<tr><td colspan='2' class='ok'>Aucun mot de passe "
                      "reutilise.</td></tr>")

    cards = [
        ("Comptes", report.total_accounts, "#cbd5e1"),
        ("Compromis HIBP", report.pwned_accounts, "#ef4444"),
        ("Sans mot de passe", report.blank_accounts, "#f59e0b"),
        ("Hash LM", report.lm_accounts, "#f59e0b"),
        ("Mots de passe reutilises", report.reused_groups, "#f59e0b"),
        ("Comptes machine", report.machine_accounts, "#64748b"),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="val" style="color:{c}">{v}</div>'
        f'<div class="cap">{_esc(lbl)}</div></div>'
        for lbl, v, c in cards)

    machine_note = ("<p class='note'>Les comptes machine (...$) ont ete exclus "
                    "de la comparaison HIBP.</p>"
                    if report.machine_skipped else "")

    doc = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport NTDS / HIBP - {_esc(__author__)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family:'Segoe UI',system-ui,sans-serif;
         background:#0b1220; color:#e2e8f0; }}
  header {{ background:linear-gradient(135deg,#1e293b,#0f172a);
           padding:28px 40px; border-bottom:1px solid #1e293b; }}
  header h1 {{ margin:0; font-size:26px; letter-spacing:1px; }}
  header .sub {{ color:#94a3b8; margin-top:6px; }}
  header a {{ color:#60a5fa; text-decoration:none; }}
  main {{ max-width:1080px; margin:0 auto; padding:28px 40px 60px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:14px; margin:18px 0 28px; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
          padding:18px; text-align:center; }}
  .card .val {{ font-size:30px; font-weight:700; }}
  .card .cap {{ color:#94a3b8; font-size:12px; margin-top:4px; }}
  .panel {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
           padding:22px; margin:18px 0; }}
  h2 {{ font-size:16px; margin:0 0 14px; color:#e2e8f0; }}
  .pie-wrap {{ display:flex; gap:28px; align-items:center; flex-wrap:wrap; }}
  ul.legend {{ list-style:none; margin:0; padding:0; flex:1; min-width:260px; }}
  ul.legend li {{ display:flex; align-items:center; gap:10px; padding:5px 0;
                 border-bottom:1px solid #1f2937; }}
  .dot {{ width:13px; height:13px; border-radius:3px; flex:none; }}
  .legend .lbl {{ flex:1; font-size:13px; color:#cbd5e1; }}
  .legend .cnt {{ font-weight:700; color:#e2e8f0; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937; }}
  th {{ color:#94a3b8; font-weight:600; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.ok {{ color:#22c55e; }}
  .tag {{ display:inline-block; padding:2px 8px; border-radius:6px;
         font-size:11px; font-weight:700; margin-right:5px; }}
  .tag.pwned {{ background:#7f1d1d; color:#fecaca; }}
  .tag.blank {{ background:#78350f; color:#fed7aa; }}
  .tag.lm    {{ background:#78350f; color:#fde68a; }}
  .tag.reuse {{ background:#1e3a8a; color:#bfdbfe; }}
  .note {{ color:#94a3b8; font-size:12px; }}
  footer {{ color:#64748b; font-size:12px; text-align:center; padding:24px; }}
  .warn {{ background:#422006; border:1px solid #a16207; color:#fde68a;
          border-radius:10px; padding:14px 18px; margin:18px 0; font-size:13px; }}
</style></head>
<body>
<header>
  <h1>NTDS &nbsp;HIBP&nbsp; CHECKER</h1>
  <div class="sub">Rapport d'analyse - mode {_esc(report.mode)} -
    genere le {time.strftime('%d/%m/%Y a %H:%M')}</div>
  <div class="sub"><a href="{__url__}">{_esc(__author__)} - {__url__}</a></div>
</header>
<main>
  <div class="cards">{cards_html}</div>
  {machine_note}

  <div class="panel">
    <h2>Reutilisation des mots de passe</h2>
    <div class="pie-wrap">
      <div>{pie}</div>
      <ul class="legend">{legend_rows}</ul>
    </div>
  </div>

  <div class="panel">
    <h2>Comptes a risque ({len(at_risk)})</h2>
    <table><thead><tr><th>Compte</th><th class="num">HIBP</th>
      <th class="num">Reutil.</th><th>Etat</th></tr></thead>
      <tbody>{risk_rows}</tbody></table>
  </div>

  <div class="panel">
    <h2>Groupes de comptes a mot de passe identique</h2>
    <table><thead><tr><th class="num">Comptes</th><th>Membres</th></tr></thead>
      <tbody>{reuse_rows}</tbody></table>
  </div>

  <div class="warn">Rappel de securite : supprimez ntds.dit et SYSTEM avec
    sdelete apres l'analyse, et reinitialisez les mots de passe compromis
    (ainsi que le compte krbtgt deux fois) si la base a pu etre exposee.</div>
</main>
<footer>{_esc(__app_name__)} v{__version__} - {_esc(__author__)} - {__url__}</footer>
</body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
