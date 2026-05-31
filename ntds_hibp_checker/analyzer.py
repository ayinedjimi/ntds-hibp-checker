"""
Orchestration de l'analyse : extraction -> verification HIBP -> rapport.

Conçu pour tourner dans un thread de travail et notifier la GUI via callbacks.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from itertools import count
from typing import Callable, Dict, List, Optional

from .extractor import Account, extract_hashes
from .hibp import (LocalNtlmChecker, OnlineNtlmChecker, check_hashes)


class Phase(Enum):
    EXTRACTION = "extraction"
    HIBP = "hibp"
    DONE = "done"


class AccountStatus(Enum):
    OK = "ok"
    PWNED = "pwned"
    BLANK = "blank"
    LM_PRESENT = "lm"


@dataclass
class AccountFinding:
    account: Account
    pwned_count: int = 0          # occurrences dans HIBP
    reuse_count: int = 1          # nombre de comptes partageant ce hash NT

    @property
    def statuses(self) -> List[AccountStatus]:
        s: List[AccountStatus] = []
        if self.account.is_blank:
            s.append(AccountStatus.BLANK)
        if self.pwned_count > 0 and not self.account.is_blank:
            s.append(AccountStatus.PWNED)
        if self.account.has_lm:
            s.append(AccountStatus.LM_PRESENT)
        if not s:
            s.append(AccountStatus.OK)
        return s

    @property
    def is_at_risk(self) -> bool:
        return self.account.is_blank or self.pwned_count > 0 \
            or self.account.has_lm


@dataclass
class AnalysisReport:
    findings: List[AccountFinding] = field(default_factory=list)
    total_accounts: int = 0
    pwned_accounts: int = 0
    blank_accounts: int = 0
    lm_accounts: int = 0
    reused_groups: int = 0        # nb de mots de passe partages par >1 compte
    machine_accounts: int = 0     # comptes ordinateurs/service (...$)
    machine_skipped: bool = False  # comptes machine exclus de la verif HIBP
    mode: str = ""

    @property
    def at_risk(self) -> List[AccountFinding]:
        return [f for f in self.findings if f.is_at_risk]

    def reuse_groups(self) -> List[List[AccountFinding]]:
        """Groupes de comptes (>1) partageant un meme hash NT non vide,
        tries du plus grand au plus petit. Pour le camembert et les exports."""
        by_hash: Dict[str, List[AccountFinding]] = defaultdict(list)
        for f in self.findings:
            if not f.account.is_blank:
                by_hash[f.account.nt_hash].append(f)
        groups = [g for g in by_hash.values() if len(g) > 1]
        groups.sort(key=len, reverse=True)
        return groups


@dataclass
class Progress:
    phase: Phase
    current: int = 0
    total: int = 0
    message: str = ""


class Analyzer:
    def __init__(
        self,
        ntds_path: str,
        system_path: str,
        use_online: bool = True,
        local_hibp_file: Optional[str] = None,
        ignore_machine: bool = True,
        use_cache: bool = True,
        on_progress: Optional[Callable[[Progress], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ):
        self.ntds_path = ntds_path
        self.system_path = system_path
        self.use_online = use_online
        self.local_hibp_file = local_hibp_file
        self.ignore_machine = ignore_machine
        self.use_cache = use_cache
        self.on_progress = on_progress or (lambda p: None)
        self.on_log = on_log or (lambda m: None)
        self._cancel = False

    @staticmethod
    def _is_machine(acc: Account) -> bool:
        # samAccountName des comptes ordinateurs/service se termine par '$'
        return bool(acc.name) and acc.name.rstrip().endswith("$")

    def cancel(self):
        self._cancel = True

    def _should_cancel(self) -> bool:
        return self._cancel

    def run(self) -> AnalysisReport:
        # ---- Phase 1 : extraction --------------------------------------- #
        self.on_log("Extraction des hash depuis ntds.dit...")
        self.on_progress(Progress(Phase.EXTRACTION, 0, 0,
                                  "Lecture de la base NTDS..."))
        # itertools.count.__next__ est atomique (thread-safe) et evite le
        # motif dict mutable partage dans la closure.
        counter = count(1)

        def _on_account(acc: Account):
            n = next(counter)
            if n % 25 == 0 or n == 1:
                self.on_progress(Progress(
                    Phase.EXTRACTION, n, 0, f"{n} comptes extraits..."))

        result = extract_hashes(
            self.ntds_path, self.system_path,
            on_account=_on_account, should_cancel=self._should_cancel)

        accounts = result.accounts
        self.on_log(f"{len(accounts)} comptes extraits.")

        # ---- Reutilisation de mot de passe ------------------------------ #
        hash_to_accounts: Dict[str, List[Account]] = defaultdict(list)
        for acc in accounts:
            if not acc.is_blank:
                hash_to_accounts[acc.nt_hash].append(acc)
        reused_groups = sum(1 for v in hash_to_accounts.values() if len(v) > 1)

        # ---- Phase 2 : verification HIBP -------------------------------- #
        checker = None
        try:
            if self.use_online:
                self.on_log("Verification via l'API HIBP (k-anonymity)...")
                disk_cache = None
                if self.use_cache:
                    try:
                        from .cache import PrefixCache
                        disk_cache = PrefixCache()
                    except Exception:
                        disk_cache = None      # cache optionnel, jamais bloquant
                checker = OnlineNtlmChecker(disk_cache=disk_cache)
            else:
                self.on_log(f"Verification via le fichier local : "
                            f"{self.local_hibp_file}")
                checker = LocalNtlmChecker(self.local_hibp_file)

            # on ignore le hash vide (mot de passe vide) et, en option, les
            # comptes machine (...$) dont le mot de passe est aleatoire et
            # jamais present dans HIBP -> reduit fortement le volume de lookups
            def _skip_for_hibp(a: Account) -> bool:
                return a.is_blank or (self.ignore_machine and self._is_machine(a))

            to_check = [a.nt_hash for a in accounts if not _skip_for_hibp(a)]

            def _on_hibp_progress(cur: int, total: int):
                self.on_progress(Progress(
                    Phase.HIBP, cur, total,
                    f"Comparaison HIBP : {cur}/{total}"))

            pwned_map = check_hashes(
                to_check, checker,
                on_progress=_on_hibp_progress,
                should_cancel=self._should_cancel)
        finally:
            if checker is not None and hasattr(checker, "close"):
                checker.close()

        # ---- Construction du rapport ------------------------------------ #
        report = AnalysisReport(total_accounts=len(accounts),
                                reused_groups=reused_groups,
                                machine_skipped=self.ignore_machine,
                                mode="online" if self.use_online else "local")
        for acc in accounts:
            reuse = len(hash_to_accounts.get(acc.nt_hash, [acc])) \
                if not acc.is_blank else 1
            pwned = 0 if acc.is_blank else pwned_map.get(acc.nt_hash, 0)
            finding = AccountFinding(account=acc, pwned_count=pwned,
                                     reuse_count=reuse)
            report.findings.append(finding)
            if acc.is_blank:
                report.blank_accounts += 1
            if pwned > 0 and not acc.is_blank:
                report.pwned_accounts += 1
            if acc.has_lm:
                report.lm_accounts += 1
            if self._is_machine(acc):
                report.machine_accounts += 1

        self.on_progress(Progress(Phase.DONE, 1, 1, "Analyse terminee."))
        self.on_log("Analyse terminee.")
        return report
