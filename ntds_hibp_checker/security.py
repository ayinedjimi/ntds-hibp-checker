"""
Avertissements de securite et suppression securisee (sdelete).

Les fichiers ntds.dit et SYSTEM contiennent l'integralite des secrets du
domaine Active Directory. Leur manipulation impose des precautions strictes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List


def _app_dir() -> str:
    """Dossier de l'executable (mode PyInstaller) ou du module."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


SECURITY_WARNINGS: List[str] = [
    "Le fichier ntds.dit contient les hash de TOUS les comptes du domaine "
    "(utilisateurs, ordinateurs, comptes de service, krbtgt).",
    "La ruche SYSTEM contient la boot key permettant de dechiffrer ntds.dit. "
    "ntds.dit + SYSTEM = compromission totale du domaine.",
    "Realisez cette analyse sur un poste DEDIE et ISOLE (air-gapped de "
    "preference), jamais sur un controleur de domaine de production.",
    "En mode ONLINE, seuls les 5 premiers caracteres du hash sont envoyes a "
    "HIBP (k-anonymity) : le hash complet ne quitte jamais le poste. "
    "Pour une isolation totale, utilisez le mode fichier LOCAL.",
    "Ne stockez JAMAIS les hash extraits en clair sur disque. Cette "
    "application les garde uniquement en memoire.",
    "Apres l'analyse, SUPPRIMEZ DE FACON SECURISEE les fichiers ntds.dit, "
    "SYSTEM et tout export intermediaire avec sdelete (effacement DoD).",
    "Forcez la reinitialisation des mots de passe compromis et du compte "
    "krbtgt (deux fois) si le ntds.dit a pu etre expose.",
]


def sdelete_command(paths: List[str], passes: int = 7) -> str:
    """Renvoie la commande sdelete recommandee (a executer manuellement)."""
    quoted = " ".join(f'"{p}"' for p in paths)
    return f"sdelete64.exe -p {passes} -nobanner {quoted}"


def find_sdelete() -> str | None:
    """Cherche sdelete dans le PATH ou a cote de l'executable."""
    for name in ("sdelete64.exe", "sdelete.exe", "sdelete64", "sdelete"):
        found = shutil.which(name)
        if found:
            return found
    # a cote de l'exe / du script / dossier courant
    for base in (_app_dir(), os.getcwd()):
        for name in ("sdelete64.exe", "sdelete.exe"):
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def secure_delete(paths: List[str], passes: int = 7) -> tuple[bool, str]:
    """Tente une suppression securisee via sdelete.

    :return: (succes, message). N'effectue rien si sdelete est introuvable.
    """
    exe = find_sdelete()
    existing = [p for p in paths if os.path.isfile(p)]
    if not existing:
        return False, "Aucun des fichiers indiques n'existe."
    if not exe:
        return False, (
            "sdelete introuvable. Telechargez Sysinternals SDelete puis "
            "executez manuellement :\n" + sdelete_command(existing, passes))
    try:
        # -p passes, accepte EULA silencieusement, sans banniere
        cmd = [exe, "-accepteula", "-nobanner", "-p", str(passes), *existing]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode == 0:
            return True, f"Suppression securisee reussie ({len(existing)} "\
                         f"fichier(s), {passes} passes)."
        return False, f"sdelete a echoue (code {proc.returncode}) :\n{proc.stderr}"
    except subprocess.TimeoutExpired:
        return False, ("sdelete n'a pas termine dans le delai imparti (1h). "
                       "L'effacement est peut-etre encore en cours ; verifiez "
                       "manuellement.")
    except Exception as exc:
        return False, f"Erreur lors de l'appel a sdelete : {exc}"
