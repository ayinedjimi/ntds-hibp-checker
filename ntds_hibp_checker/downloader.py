"""
Telechargement local de la base HaveIBeenPwned (Pwned Passwords - NTLM),
au format directement exploitable par le mode local (LocalNtlmChecker) :
fichier texte 'HASH:COUNT' trie par hash.

Il n'existe pas d'URL de telechargement direct d'un fichier unique : on agrege
les 1 048 576 plages de l'API k-anonymity (range/{prefixe}?mode=ntlm). Chaque
reponse est deja triee par suffixe ; en parcourant les prefixes dans l'ordre
croissant, le fichier produit est donc globalement trie par hash.

ATTENTION : le fichier final pese plusieurs dizaines de Go et le telechargement
peut durer une a plusieurs heures selon la connexion.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, Optional

import requests
from requests.adapters import HTTPAdapter

from .hibp import (BACKOFF_CAP, HIBP_RANGE_URL, MAX_ATTEMPTS, USER_AGENT,
                   retry_after_seconds)

TOTAL_PREFIXES = 1 << 20            # 16^5 = 1 048 576
DEFAULT_DL_WORKERS = 16            # bulk : l'API range est servie par CDN
DEFAULT_BATCH = 512                # prefixes traites (et ecrits) par lot


def _make_session(workers: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})  # pas de Add-Padding ici
    adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers,
                          max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _interruptible_sleep(seconds: float, should_cancel) -> None:
    """Attend par petits pas en surveillant l'annulation (arret reactif)."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if should_cancel and should_cancel():
            return
        time.sleep(min(0.1, end - time.monotonic()))


def _fetch(session: requests.Session, prefix: str, timeout: int = 20,
           should_cancel=None) -> str:
    from .extractor import CancelledError
    url = HIBP_RANGE_URL.format(prefix=prefix)
    for attempt in range(MAX_ATTEMPTS):
        if should_cancel and should_cancel():
            raise CancelledError()
        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException:
            _interruptible_sleep(min(BACKOFF_CAP, 0.5 * (2 ** attempt)),
                                 should_cancel)
            continue
        if resp.status_code == 429:
            wait = retry_after_seconds(resp.headers.get("Retry-After"))
            if wait is None:
                wait = min(BACKOFF_CAP, 0.5 * (2 ** attempt))
            _interruptible_sleep(min(BACKOFF_CAP, wait), should_cancel)
            continue
        if resp.status_code != 200:
            raise RuntimeError(f"HIBP a renvoye HTTP {resp.status_code} "
                               f"pour le prefixe {prefix}")
        return resp.text
    raise RuntimeError(f"Echec du telechargement du prefixe {prefix}")


def download_hibp_ntlm(
    out_path: str,
    on_progress: Optional[Callable[[int, int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    workers: int = DEFAULT_DL_WORKERS,
    batch: int = DEFAULT_BATCH,
) -> str:
    """Telecharge l'integralite de la base NTLM dans out_path.

    Ecrit d'abord dans un fichier '.part' renomme seulement en cas de succes
    complet (pas de fichier partiel pris pour une base valide).
    """
    from .extractor import CancelledError

    session = _make_session(workers)
    tmp = out_path + ".part"
    done = 0
    # fenetre courte (et non un gros lot) : l'annulation est verifiee tres
    # souvent et les requetes en vol sont peu nombreuses -> arret reactif.
    window = max(8, workers * 2)
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh, \
                ThreadPoolExecutor(max_workers=workers) as ex:
            i = 0
            while i < TOTAL_PREFIXES:
                if should_cancel and should_cancel():
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise CancelledError()
                chunk = [f"{j:05X}"
                         for j in range(i, min(i + window, TOTAL_PREFIXES))]
                try:
                    # ex.map conserve l'ordre des prefixes -> sortie triee.
                    # partial() lie explicitement les arguments (plus clair
                    # qu'une lambda fermant sur des variables externes).
                    fetch = partial(_fetch, session, timeout=20,
                                    should_cancel=should_cancel)
                    texts = list(ex.map(fetch, chunk))
                except CancelledError:
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise
                for prefix, text in zip(chunk, texts):
                    for line in text.splitlines():
                        if ":" not in line:
                            continue
                        suffix, count = line.split(":", 1)
                        fh.write(f"{prefix}{suffix.strip()}:"
                                 f"{count.strip()}\n")
                i += len(chunk)
                done = i
                if on_progress:
                    on_progress(done, TOTAL_PREFIXES)
    finally:
        session.close()
    os.replace(tmp, out_path)
    return out_path
