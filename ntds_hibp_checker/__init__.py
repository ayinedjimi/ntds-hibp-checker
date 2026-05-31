"""
NTDS / HIBP Checker
Analyse d'un fichier ntds.dit et comparaison des hash NT avec la base
HaveIBeenPwned (Pwned Passwords - NTLM).

Auteur : Ayi NEDJIMI Consultants - https://ayinedjimi-consultants.fr
"""

__app_name__ = "NTDS HIBP Checker"
__version__ = "1.0.0"
__author__ = "Ayi NEDJIMI Consultants"
__url__ = "https://ayinedjimi-consultants.fr"

# Hash NT d'un mot de passe vide (compte sans mot de passe).
EMPTY_NT_HASH = "31D6CFE0D16AE931B73C59D7E0C089C0"
# Partie LM "vide" (LM hashes desactives).
EMPTY_LM_HASH = "AAD3B435B51404EEAAD3B435B51404EE"
