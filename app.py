"""
Point d'entree du NTDS HIBP Checker.

Sans arguments : lance l'interface graphique.
Avec arguments (--ntds, --system, etc.) : mode ligne de commande.

Auteur : Ayi NEDJIMI Consultants - https://ayinedjimi-consultants.fr
"""

import sys


def _has_cli_args() -> bool:
    """Detecte si l'utilisateur a passe des arguments CLI."""
    if len(sys.argv) <= 1:
        return False
    cli_flags = {"--ntds", "--system", "--mode", "--hibp-file", "--output",
                 "-o", "--format", "-f", "--quiet", "-q", "--version", "-V",
                 "--help", "-h", "--include-machine", "--no-cache",
                 "--download-hibp"}
    return any(arg in cli_flags or arg.startswith("--ntds=")
               or arg.startswith("--system=") or arg.startswith("--output=")
               or arg.startswith("--hibp-file=") or arg.startswith("--format=")
               or arg.startswith("--download-hibp=")
               for arg in sys.argv[1:])


if __name__ == "__main__":
    if _has_cli_args():
        from ntds_hibp_checker.cli import main
        main()
    else:
        from ntds_hibp_checker.gui import main
        main()
