"""
Comparaison des hash NT avec la base HaveIBeenPwned (Pwned Passwords - NTLM).

Deux modes :
  - ONLINE  : API k-anonymity de HIBP. On n'envoie QUE les 5 premiers
              caracteres hexa du hash NT ; le serveur renvoie tous les suffixes
              connus pour ce prefixe. Le hash complet ne quitte jamais le poste.
  - LOCAL   : fichier 'pwnedpasswords' NTLM telecharge (trie par hash).
              Recommande en environnement air-gapped / hors-ligne.
              Telechargement : https://haveibeenpwned.com/Passwords
              (choisir le format "NTLM (ordered by hash)").

Le hash NT d'Active Directory EST le hash NTLM utilise par HIBP.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Optional

import requests
from requests.adapters import HTTPAdapter

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}?mode=ntlm"
USER_AGENT = "NTDS-HIBP-Checker (Ayi NEDJIMI Consultants)"

# Concurrence volontairement moderee : l'API range est servie par CDN mais on
# evite de la marteler. En cas de 429, on respecte Retry-After + backoff.
DEFAULT_WORKERS = 8
MAX_ATTEMPTS = 6
BACKOFF_CAP = 10.0          # secondes


class HibpError(Exception):
    pass


def retry_after_seconds(value) -> Optional[float]:
    """Interprete un en-tete Retry-After : nombre (entier OU decimal) de
    secondes, ou date HTTP. Renvoie None si non interpretable."""
    if not value:
        return None
    try:
        return max(0.0, float(value))      # gere "3" comme "3.5"
    except (TypeError, ValueError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Mode ONLINE (k-anonymity)
# --------------------------------------------------------------------------- #
class OnlineNtlmChecker:
    """Verifie des hash NT via l'API k-anonymity de HIBP.

    On regroupe les requetes par prefixe (5 hex) : une requete par prefixe
    unique suffit. Les prefixes sont recuperes en parallele (pool borne) avec
    gestion du rate-limiting (HTTP 429 -> Retry-After + backoff exponentiel)
    pour ne pas se faire bloquer.
    """

    def __init__(self, timeout: int = 20, workers: int = DEFAULT_WORKERS,
                 disk_cache=None):
        self.timeout = timeout
        self.workers = max(1, workers)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT,
                                      "Add-Padding": "true"})
        # pool de connexions dimensionne pour la concurrence
        adapter = HTTPAdapter(pool_connections=self.workers,
                              pool_maxsize=self.workers, max_retries=0)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._cache: Dict[str, Dict[str, int]] = {}
        self._cache_lock = threading.Lock()
        # cache persistant optionnel (sqlite) : reponses publiques HIBP reutilisees
        # d'une analyse a l'autre. None par defaut -> cache memoire seul.
        self._disk_cache = disk_cache
        # cooldown global partage : si l'API renvoie 429, tous les threads
        # patientent jusqu'a cette echeance (anti-blocage cooperatif).
        self._cooldown_until = 0.0
        self._cooldown_lock = threading.Lock()

    # -- gestion cooperative du rate-limiting -- #
    def _respect_cooldown(self):
        with self._cooldown_lock:
            wait = self._cooldown_until - time.monotonic()
        if wait > 0:
            time.sleep(min(wait, BACKOFF_CAP))

    def _trigger_cooldown(self, seconds: float):
        until = time.monotonic() + seconds
        with self._cooldown_lock:
            if until > self._cooldown_until:
                self._cooldown_until = until

    def _parse_body(self, text: str) -> Dict[str, int]:
        mapping: Dict[str, int] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            suffix, count = line.split(":", 1)
            try:
                c = int(count.strip())
            except ValueError:
                continue
            if c > 0:               # avec Add-Padding, les factices ont c == 0
                mapping[suffix.strip().upper()] = c
        return mapping

    def _fetch_prefix(self, prefix: str) -> Dict[str, int]:
        # 1) cache memoire (le plus rapide)
        with self._cache_lock:
            if prefix in self._cache:
                return self._cache[prefix]
        # 2) cache disque persistant (si actif)
        if self._disk_cache is not None:
            cached = self._disk_cache.get(prefix)
            if cached is not None:
                with self._cache_lock:
                    self._cache[prefix] = cached
                return cached
        url = HIBP_RANGE_URL.format(prefix=prefix)
        last_exc = None
        for attempt in range(MAX_ATTEMPTS):
            self._respect_cooldown()
            try:
                resp = self._session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(min(BACKOFF_CAP, 0.5 * (2 ** attempt)))
                continue
            if resp.status_code == 429:
                # rate limited : Retry-After (entier/decimal/date) sinon backoff
                wait = retry_after_seconds(resp.headers.get("Retry-After"))
                if wait is None:
                    wait = min(BACKOFF_CAP, 0.5 * (2 ** attempt))
                self._trigger_cooldown(wait)
                time.sleep(min(BACKOFF_CAP, wait))
                continue
            if resp.status_code != 200:
                raise HibpError(
                    f"HIBP a renvoye le code {resp.status_code} pour {prefix}")
            mapping = self._parse_body(resp.text)
            with self._cache_lock:
                self._cache[prefix] = mapping
            if self._disk_cache is not None:
                try:
                    self._disk_cache.set(prefix, mapping)
                except Exception:
                    pass            # un echec de cache ne doit jamais bloquer
            return mapping
        raise HibpError(
            f"Impossible d'interroger HIBP pour le prefixe {prefix} "
            f"apres {MAX_ATTEMPTS} tentatives" +
            (f" : {last_exc}" if last_exc else ""))

    def lookup(self, nt_hash: str) -> int:
        """Renvoie le nombre d'occurrences dans HIBP (0 si non compromis)."""
        nt_hash = nt_hash.upper()
        prefix, suffix = nt_hash[:5], nt_hash[5:]
        return self._fetch_prefix(prefix).get(suffix, 0)

    def check_many(self, unique_hashes, on_progress=None,
                   should_cancel=None) -> Dict[str, int]:
        """Recupere en parallele tous les prefixes uniques puis resout les
        comptes depuis le cache. La progression est rapportee par prefixe."""
        from .extractor import CancelledError
        prefixes = sorted({h.upper()[:5] for h in unique_hashes})
        total = len(prefixes)
        done = 0
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self._fetch_prefix, p): p for p in prefixes}
            try:
                for fut in as_completed(futures):
                    if should_cancel and should_cancel():
                        ex.shutdown(wait=False, cancel_futures=True)
                        raise CancelledError()
                    fut.result()        # peuple le cache (ou propage l'erreur)
                    with lock:
                        done += 1
                    if on_progress:
                        on_progress(done, total)
            except CancelledError:
                raise
            except Exception:
                ex.shutdown(wait=False, cancel_futures=True)
                raise
        results: Dict[str, int] = {}
        for h in unique_hashes:
            hu = h.upper()
            results[hu] = self._cache.get(hu[:5], {}).get(hu[5:], 0)
        return results

    def close(self):
        try:
            self._session.close()
        except Exception:
            pass
        if self._disk_cache is not None:
            self._disk_cache.close()


# --------------------------------------------------------------------------- #
#  Mode LOCAL (recherche dichotomique sur fichier trie par hash)
# --------------------------------------------------------------------------- #
class LocalNtlmChecker:
    """Recherche dichotomique dans le fichier NTLM HIBP (trie par hash).

    Le fichier fait ~30 Go : aucune lecture integrale, seulement des seek().
    """

    def __init__(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Fichier HIBP introuvable : {file_path}")
        self.file_path = file_path
        self._fh = open(file_path, "rb")
        self._fh.seek(0, os.SEEK_END)
        self._size = self._fh.tell()
        # mmap : seek/readline servis par le cache de pages de l'OS (plus
        # rapide que les seek() fichier). Repli sur le fichier si indisponible.
        self._mm = None
        if self._size > 0:
            try:
                import mmap
                self._mm = mmap.mmap(self._fh.fileno(), 0,
                                     access=mmap.ACCESS_READ)
            except Exception:
                self._mm = None
        self._reader = self._mm if self._mm is not None else self._fh

    def close(self):
        for obj in (self._mm, self._fh):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass

    @staticmethod
    def _count(line: bytes) -> int:
        parts = line.split(b":", 1)
        if len(parts) < 2:
            return 1
        try:
            return int(parts[1].strip())
        except ValueError:
            return 1

    def lookup(self, nt_hash: str) -> int:
        """Recherche dichotomique sur fichier trie par hash.

        Idiome standard : on se positionne au milieu, on jette la ligne
        partielle, puis on lit une ligne complete. L'intervalle [lo, hi) se
        reduit strictement a chaque iteration -> terminaison garantie, quel
        que soit le type de fin de ligne (LF ou CRLF).
        """
        target = nt_hash.upper().encode("ascii")
        r = self._reader
        lo, hi = 0, self._size
        while lo < hi:
            mid = (lo + hi) // 2
            r.seek(mid)
            if mid > 0:
                r.readline()                 # jette la ligne partielle
            line = r.readline()
            if not line:                     # au-dela de la derniere ligne
                hi = mid
                continue
            hash_part = line.split(b":", 1)[0].strip().upper()
            if hash_part == target:
                return self._count(line)
            if hash_part < target:
                lo = mid + 1
            else:
                hi = mid
        return 0


# --------------------------------------------------------------------------- #
#  Verification en lot, avec progression et regroupement par hash unique
# --------------------------------------------------------------------------- #
def check_hashes(
    nt_hashes: list[str],
    checker,
    on_progress: Optional[Callable[[int, int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, int]:
    """Verifie une liste de hash NT (peut contenir des doublons).

    On ne teste chaque hash unique qu'une seule fois.
    :return: dict {nt_hash_majuscule: count_hibp}
    """
    unique = sorted({h.upper() for h in nt_hashes})
    # Mode online : recuperation parallele des prefixes (beaucoup plus rapide).
    if isinstance(checker, OnlineNtlmChecker):
        return checker.check_many(unique, on_progress=on_progress,
                                  should_cancel=should_cancel)
    # Mode local : dichotomie sequentielle (I/O disque, deja rapide).
    total = len(unique)
    results: Dict[str, int] = {}
    for i, h in enumerate(unique, 1):
        if should_cancel and should_cancel():
            from .extractor import CancelledError
            raise CancelledError()
        results[h] = checker.lookup(h)
        if on_progress:
            on_progress(i, total)
    return results
