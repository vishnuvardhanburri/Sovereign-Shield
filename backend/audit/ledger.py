"""
Sovereign Shield v2 — Immutable Audit Ledger
Append-only audit log with SHA-256 hash chaining for tamper detection.

Every event recorded = {timestamp, user, action, data_hash, prompt_hash, policy_triggered, prev_hash, entry_hash}
The chain is broken if any entry is modified, giving cryptographic proof of integrity.
"""
import os
import json
import hashlib
import shutil
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from .hash_chain import HashChain
try:
    from config import security_settings
except ImportError:
    from ..config import security_settings

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
AUDIT_DIR = os.path.join(BASE_DIR, "logs", "audit")
AUDIT_LEDGER_FILE = os.path.join(AUDIT_DIR, "audit_ledger.jsonl")

_lock = threading.RLock()


class AuditLedger:
    """
    Append-only audit ledger with SHA-256 hash chaining.
    Each entry contains: timestamp, actor, action, payload hash, previous entry hash, and self hash.
    Tamper detection: verify_chain() returns False if any entry has been modified.
    """

    def __init__(self, ledger_path: str = AUDIT_LEDGER_FILE):
        self.ledger_path = ledger_path
        self.chain = HashChain()
        self._entries_cache_stat: Optional[tuple[int, int]] = None
        self._entries_cache: Optional[List[Dict[str, Any]]] = None
        self._verify_cache_stat: Optional[tuple[int, int]] = None
        self._verify_cache: Optional[Dict[str, Any]] = None
        self._summary_cache: Dict[tuple[Optional[str], Optional[tuple[int, int]]], Dict[str, Any]] = {}
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)

    def _ledger_stat(self) -> Optional[tuple[int, int]]:
        if not os.path.exists(self.ledger_path):
            return None
        stat = os.stat(self.ledger_path)
        return (stat.st_mtime_ns, stat.st_size)

    def _read_entries_chronological(self) -> List[Dict[str, Any]]:
        """Return cached parsed ledger entries in append order."""
        stat = self._ledger_stat()
        if stat is None:
            return []

        with _lock:
            if self._entries_cache_stat == stat and self._entries_cache is not None:
                return list(self._entries_cache)

            entries: List[Dict[str, Any]] = []
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))

            self._entries_cache_stat = stat
            self._entries_cache = entries
            self._verify_cache_stat = None
            self._verify_cache = None
            self._summary_cache.clear()
            return list(entries)

    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """Compute SHA-256 of the entry excluding derived signature fields."""
        payload = {k: v for k, v in entry.items() if k not in {"entry_hash", "signature"}}
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        salt = security_settings()["ledger_master_salt"]
        return hashlib.sha256(f"{salt}:{canonical}".encode()).hexdigest()

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _get_last_hash(self) -> str:
        """Read the hash of the last entry in the ledger."""
        if not os.path.exists(self.ledger_path):
            return "GENESIS"
        try:
            with open(self.ledger_path, "r") as f:
                lines = f.readlines()
            if not lines:
                return "GENESIS"
            last = json.loads(lines[-1].strip())
            return last.get("entry_hash", "UNKNOWN")
        except Exception:
            return "CORRUPTED"

    def log(
        self,
        action: str,
        user_id: str,
        user_role: str,
        department: Optional[str] = None,
        tenant_id: str = "default",
        prompt_text: Optional[str] = None,
        document_name: Optional[str] = None,
        redactions_applied: Optional[List[str]] = None,
        policy_triggered: Optional[str] = None,
        model_queried: Optional[str] = None,
        risk_score: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Append an immutable audit entry to the ledger.
        Returns the entry_hash for reference.
        """
        with _lock:
            prev_hash = self._get_last_hash()
            actor_hash = hashlib.sha256(f"{tenant_id}:{user_id}:{user_role}".encode()).hexdigest()

            entry: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor_hash": actor_hash,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "user_role": user_role,
                "department": department or "UNKNOWN",
                "action": action,
                "document": document_name,
                "prompt_hash": hashlib.sha256(prompt_text.encode()).hexdigest() if prompt_text else None,
                "redactions_applied": redactions_applied or [],
                "policy_triggered": policy_triggered,
                "model_queried": model_queried,
                "risk_score": risk_score,
                "prev_hash": prev_hash,
                "metadata": metadata or {},
            }

            signature = self._compute_entry_hash(entry)
            entry["signature"] = signature
            entry["entry_hash"] = signature

            with open(self.ledger_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

            self._entries_cache_stat = None
            self._entries_cache = None
            self._verify_cache_stat = None
            self._verify_cache = None
            self._summary_cache.clear()
            return entry["entry_hash"]

    def get_entries(
        self,
        limit: int = 100,
        user_id: Optional[str] = None,
        department: Optional[str] = None,
        tenant_id: Optional[str] = None,
        action_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Read audit entries with optional filters. Returns newest-first."""
        try:
            source_entries = self._read_entries_chronological()

            entries = []
            for entry in reversed(source_entries):
                # Apply filters
                if user_id and entry.get("user_id") != user_id:
                    continue
                if department and entry.get("department") != department:
                    continue
                if tenant_id and entry.get("tenant_id") != tenant_id:
                    continue
                if action_filter and action_filter.upper() not in entry.get("action", "").upper():
                    continue

                entries.append(entry)
                if len(entries) >= limit:
                    break
            return entries
        except Exception:
            return []

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire audit chain.
        Returns: {valid: bool, total_entries: int, corrupted_at: str | None}
        """
        stat = self._ledger_stat()
        if stat is None:
            return {"valid": True, "total_entries": 0, "corrupted_at": None}

        try:
            with _lock:
                if self._verify_cache_stat == stat and self._verify_cache is not None:
                    return dict(self._verify_cache)

            entries = self._read_entries_chronological()

            prev_hash = "GENESIS"
            for i, entry in enumerate(entries):
                # 1. Check prev_hash linkage
                if entry.get("prev_hash") != prev_hash:
                    result = {
                        "valid": False,
                        "total_entries": len(entries),
                        "corrupted_at": f"Entry {i+1} — prev_hash mismatch (chain broken)"
                    }
                    with _lock:
                        self._verify_cache_stat = stat
                        self._verify_cache = result
                    return result

                # 2. Re-compute entry hash and compare
                stored_hash = entry.get("entry_hash", "")
                stored_signature = entry.get("signature", stored_hash)
                computed_hash = self._compute_entry_hash(entry)
                if computed_hash != stored_hash or stored_signature != stored_hash:
                    result = {
                        "valid": False,
                        "total_entries": len(entries),
                        "corrupted_at": f"Entry {i+1} @ {entry.get('timestamp')} — content tampered"
                    }
                    with _lock:
                        self._verify_cache_stat = stat
                        self._verify_cache = result
                    return result

                prev_hash = stored_hash

            result = {"valid": True, "total_entries": len(entries), "corrupted_at": None}
            with _lock:
                self._verify_cache_stat = stat
                self._verify_cache = result
            return dict(result)

        except Exception as e:
            return {"valid": False, "total_entries": 0, "corrupted_at": f"Parse error: {e}"}

    def reseal_corrupted_chain(
        self,
        triggered_by: str = "SYSTEM",
        user_role: str = "SUPER_ADMIN",
        tenant_id: str = "default",
        archive_dir: Optional[str] = None,
        reason: str = "LEDGER_CHAIN_RESEAL",
    ) -> Dict[str, Any]:
        """
        Archive a corrupted active ledger, emit an incident report, and start a fresh chain.

        This preserves the previous ledger bytes for forensic review instead of rewriting
        history with the current salt.
        """
        with _lock:
            chain_status_before = self.verify_chain()
            if chain_status_before.get("valid"):
                return {
                    "resealed": False,
                    "reason": "ledger already valid",
                    "chain_status_before": chain_status_before,
                    "chain_status_after": chain_status_before,
                }

            os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
            archive_root = archive_dir or os.path.join(os.path.dirname(self.ledger_path), "archived")
            os.makedirs(archive_root, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

            previous_last_hash = self._get_last_hash()
            archived_ledger_path = os.path.join(archive_root, f"audit_ledger_corrupted_{timestamp}.jsonl")
            if os.path.exists(self.ledger_path):
                shutil.copy2(self.ledger_path, archived_ledger_path)
                with open(self.ledger_path, "w", encoding="utf-8") as handle:
                    handle.write("")
            else:
                open(self.ledger_path, "a", encoding="utf-8").close()

            incident_report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "triggered_by": triggered_by,
                "user_role": user_role,
                "tenant_id": tenant_id,
                "previous_ledger_path": self.ledger_path,
                "archived_ledger_path": archived_ledger_path,
                "archived_ledger_sha256": self._sha256_file(archived_ledger_path) if os.path.exists(archived_ledger_path) else None,
                "previous_last_hash": previous_last_hash,
                "chain_status_before": chain_status_before,
                "active_salt_fingerprint": hashlib.sha256(security_settings()["ledger_master_salt"].encode()).hexdigest()[:16],
            }
            incident_report_path = os.path.join(archive_root, f"ledger_incident_{timestamp}.json")
            with open(incident_report_path, "w", encoding="utf-8") as handle:
                json.dump(incident_report, handle, indent=2)

            self.log(
                action="LEDGER_RESEALED",
                user_id=triggered_by,
                user_role=user_role,
                department="SECURITY",
                tenant_id=tenant_id,
                policy_triggered="LEDGER_RESEAL",
                risk_score=9.9,
                metadata={
                    "reason": reason,
                    "archived_ledger_path": archived_ledger_path,
                    "incident_report_path": incident_report_path,
                    "chain_status_before": chain_status_before,
                    "previous_last_hash": previous_last_hash,
                },
            )

            chain_status_after = self.verify_chain()
            return {
                "resealed": True,
                "reason": reason,
                "archived_ledger_path": archived_ledger_path,
                "incident_report_path": incident_report_path,
                "chain_status_before": chain_status_before,
                "chain_status_after": chain_status_after,
            }

    def log_llm_request(
        self,
        actor: str,
        policy_triggered: Optional[str],
        prompt_text: str,
        sensitivity_score: float,
        model_queried: Optional[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Minimal Obsidian ledger entry for governed LLM traffic.

        Required audit fields are timestamp, actor_hash, policy_triggered, and
        signature. Additional fields remain hash chained for investigation.
        """
        return self.log(
            action="LLM_GATEWAY_REQUEST",
            user_id=actor,
            user_role="SERVICE_ACTOR",
            prompt_text=prompt_text,
            policy_triggered=policy_triggered,
            model_queried=model_queried,
            risk_score=sensitivity_score,
            metadata=metadata or {},
        )

    def get_summary_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Return aggregate stats for the compliance dashboard."""
        stat = self._ledger_stat()
        cache_key = (tenant_id, stat)
        with _lock:
            cached = self._summary_cache.get(cache_key)
            if cached is not None:
                return dict(cached)

        entries = self.get_entries(limit=100000, tenant_id=tenant_id)
        actions = {}
        risk_scores = []
        redaction_totals = 0

        for e in entries:
            action = e.get("action", "UNKNOWN")
            actions[action] = actions.get(action, 0) + 1
            if e.get("risk_score") is not None:
                risk_scores.append(e["risk_score"])
            redaction_totals += len(e.get("redactions_applied", []))

        result = {
            "total_events": len(entries),
            "action_breakdown": actions,
            "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
            "total_redactions": redaction_totals,
            "high_risk_events": sum(1 for s in risk_scores if s > 7.0),
        }
        with _lock:
            self._summary_cache[cache_key] = dict(result)
        return result


# Singleton
audit_ledger = AuditLedger()
