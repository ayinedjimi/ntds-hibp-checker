"""
Extraction des hash NT depuis un fichier ntds.dit hors-ligne.

S'appuie sur impacket (secretsdump). Le decryptage de la base NTDS necessite
la cle de boot (SYSKEY) stockee dans la ruche de registre SYSTEM.

Fichiers necessaires :
  - ntds.dit  : la base de donnees Active Directory (table ESE)
  - SYSTEM    : ruche de registre contenant la boot key

Ces deux fichiers s'obtiennent par exemple via :
  ntdsutil "activate instance ntds" "ifm" "create full C:\\export" quit quit
ce qui produit  Active Directory\\ntds.dit  et  registry\\SYSTEM.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from impacket.examples.secretsdump import LocalOperations, NTDSHashes

from . import EMPTY_LM_HASH, EMPTY_NT_HASH


@dataclass
class Account:
    """Un compte extrait du ntds.dit."""
    name: str            # domaine\\utilisateur
    rid: str
    lm_hash: str         # majuscules
    nt_hash: str         # majuscules
    enabled: bool = True

    @property
    def is_blank(self) -> bool:
        return self.nt_hash == EMPTY_NT_HASH

    @property
    def has_lm(self) -> bool:
        return bool(self.lm_hash) and self.lm_hash != EMPTY_LM_HASH


@dataclass
class ExtractionResult:
    accounts: list[Account] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class CancelledError(BaseException):
    """Levee lorsque l'utilisateur annule l'analyse.

    Herite de BaseException (et non Exception) a dessein : impacket entoure le
    traitement de chaque enregistrement d'un `except Exception`. Une exception
    derivee d'Exception serait donc avalee et l'annulation ignoree pendant la
    phase d'extraction. BaseException traverse ces `except Exception`.
    """


def _parse_secret(secret: str) -> Optional[Account]:
    """Transforme une ligne 'domaine\\user:rid:lm:nt:::' en Account."""
    # Format impacket : user:rid:lmhash:nthash:::
    parts = secret.split(":")
    if len(parts) < 4:
        return None
    name = parts[0]
    rid = parts[1]
    lm_hash = parts[2].upper()
    nt_hash = parts[3].upper()
    # printUserStatus ajoute en fin un token "(status=Enabled|Disabled)".
    # On lit la valeur du DERNIER token "status=" (et non une sous-chaine
    # globale, pour ne pas etre trompe par un nom de compte particulier).
    enabled = True
    tail = secret.rsplit("status=", 1)
    if len(tail) == 2:
        enabled = not tail[1].lstrip().startswith("Disabled")
    return Account(name=name, rid=rid, lm_hash=lm_hash, nt_hash=nt_hash,
                   enabled=enabled)


def extract_hashes(
    ntds_path: str,
    system_hive_path: str,
    on_account: Optional[Callable[[Account], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> ExtractionResult:
    """
    Extrait l'ensemble des hash NT du ntds.dit.

    :param on_account: callback appele pour chaque compte trouve (progression).
    :param should_cancel: callback renvoyant True pour interrompre l'extraction.
    """
    if not os.path.isfile(ntds_path):
        raise FileNotFoundError(f"ntds.dit introuvable : {ntds_path}")
    if not os.path.isfile(system_hive_path):
        raise FileNotFoundError(f"Ruche SYSTEM introuvable : {system_hive_path}")

    result = ExtractionResult()

    local_ops = LocalOperations(system_hive_path)
    boot_key = local_ops.getBootKey()
    if not boot_key:
        raise ValueError(
            "Impossible d'extraire la boot key (SYSKEY) depuis la ruche SYSTEM. "
            "Verifiez que le fichier SYSTEM correspond bien au ntds.dit fourni."
        )

    def _callback(secret_type, secret):
        if should_cancel and should_cancel():
            raise CancelledError()
        if secret_type != NTDSHashes.SECRET_TYPE.NTDS:
            return
        acc = _parse_secret(secret)
        if acc is None:
            return
        result.accounts.append(acc)
        if on_account:
            on_account(acc)

    ntds = NTDSHashes(
        ntdsFile=ntds_path,
        bootKey=boot_key,
        isRemote=False,
        history=False,
        noLMHash=False,          # on veut detecter la presence de hash LM
        useVSSMethod=True,       # parsing local de la base ESE
        justNTLM=True,           # uniquement les hash NTLM (pas kerberos/cleartext)
        pwdLastSet=False,
        printUserStatus=True,    # recupere Enabled/Disabled
        perSecretCallback=_callback,
    )

    try:
        ntds.dump()
    except CancelledError:
        raise
    finally:
        try:
            ntds.finish()
        except Exception:
            pass

    return result
