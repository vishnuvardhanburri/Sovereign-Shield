"""
Sovereign Shield Enterprise — Self-Diagnostic Bootstrapper

Runs startup diagnostics before the gateway is considered buyer-ready:
Ollama/model health, Obsidian ledger integrity, and scanner pattern accuracy.
"""
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .audit.ledger import audit_ledger
    from .compliance.india_patterns import IndiaPIIScanner
    from .security_scanner import EnterpriseScanner
except ImportError:
    from audit.ledger import audit_ledger
    from compliance.india_patterns import IndiaPIIScanner
    from security_scanner import EnterpriseScanner


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    ok: bool
    severity: str
    detail: str
    metadata: Dict[str, Any]


class SentinelCheck:
    REQUIRED_LABELS = {
        "Aadhaar Number",
        "PAN Card",
        "IFSC Code",
        "Indian Mobile",
        "UPI ID",
        "GST Number",
        "Credit Card",
        "PII (SSN)",
    }

    TEST_PII = (
        "Patient SSN 123-45-6789, Aadhaar 2345 6789 0123, PAN ABCDE1234F, "
        "IFSC HDFC0001234, mobile +919876543210, UPI buyer@oksbi, "
        "GST 27ABCDE1234F1Z5, card 4532015112830366."
    )

    def __init__(
        self,
        enterprise_scanner: Optional[EnterpriseScanner] = None,
        india_scanner: Optional[IndiaPIIScanner] = None,
        ollama_base_url: Optional[str] = None,
        model_name: Optional[str] = None,
    ):
        self.enterprise_scanner = enterprise_scanner or EnterpriseScanner()
        self.india_scanner = india_scanner or IndiaPIIScanner()
        self.ollama_base_url = (ollama_base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.allowed_ollama_hosts = {
            host.strip().lower()
            for host in os.getenv("OLLAMA_ALLOWED_HOSTS", "localhost,127.0.0.1,::1,ollama").split(",")
            if host.strip()
        }
        self.model_name = model_name or os.getenv("OLLAMA_MODEL", "llama3.1")
        self.generate_probe_enabled = os.getenv(
            "OLLAMA_DIAGNOSTIC_GENERATE_ENABLED",
            "false",
        ).strip().lower() in {"1", "true", "yes", "on"}

    def run_all(self) -> Dict[str, Any]:
        checks = [
            self.check_ollama_health(),
            self.check_ledger_integrity(),
            self.check_pattern_accuracy(),
        ]
        ready = all(check.ok or check.severity != "critical" for check in checks)
        return {
            "ready": ready,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "checks": [asdict(check) for check in checks],
            "certificate": self._certificate(checks),
        }

    def check_ollama_health(self) -> DiagnosticCheck:
        try:
            tags = self._get_json("/api/tags", timeout=2.5)
            models = [model.get("name", "") for model in tags.get("models", [])]
            model_present = any(name.startswith(self.model_name) for name in models)
            if not model_present:
                return DiagnosticCheck(
                    "Local Model Health",
                    False,
                    "critical",
                    f"Ollama is reachable, but model '{self.model_name}' is not pulled.",
                    {"ollama_base_url": self.ollama_base_url, "models": models},
                )

            if not self.generate_probe_enabled:
                return DiagnosticCheck(
                    "Local Model Health",
                    True,
                    "warning",
                    "Ollama is reachable and the configured model is installed; generation probe is disabled by default.",
                    {
                        "ollama_base_url": self.ollama_base_url,
                        "model": self.model_name,
                        "probe_enabled": False,
                    },
                )

            responsive = self._generate_probe()
            return DiagnosticCheck(
                "Local Model Health",
                responsive,
                "critical",
                "Ollama model responded to diagnostic probe." if responsive else "Ollama model did not respond to probe.",
                {"ollama_base_url": self.ollama_base_url, "model": self.model_name, "probe_enabled": True},
            )
        except Exception as exc:
            return DiagnosticCheck(
                "Local Model Health",
                False,
                "critical",
                f"Ollama unavailable: {exc}",
                {"ollama_base_url": self.ollama_base_url, "model": self.model_name},
            )

    def check_ledger_integrity(self) -> DiagnosticCheck:
        result = audit_ledger.verify_chain()
        return DiagnosticCheck(
            "Obsidian Ledger Integrity",
            bool(result.get("valid")),
            "critical",
            "Ledger hash chain verified." if result.get("valid") else str(result.get("corrupted_at")),
            result,
        )

    def check_pattern_accuracy(self) -> DiagnosticCheck:
        findings = self.enterprise_scanner.scan_content(self.TEST_PII) + self.india_scanner.scan(self.TEST_PII)
        labels = {str(f.get("label")) for f in findings}
        missing = sorted(self.REQUIRED_LABELS - labels)
        return DiagnosticCheck(
            "Pattern Accuracy",
            not missing,
            "critical",
            "Hidden PII fixture detected at 100% required coverage." if not missing else f"Missing labels: {', '.join(missing)}",
            {"required": sorted(self.REQUIRED_LABELS), "detected": sorted(labels), "missing": missing},
        )

    def _get_json(self, path: str, timeout: float) -> Dict[str, Any]:
        url = self._validated_ollama_url(path)
        # URL is constrained by _validated_ollama_url before the request.
        with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310
            import json
            return json.loads(response.read().decode("utf-8"))

    def _generate_probe(self) -> bool:
        import json

        payload = json.dumps({
            "model": self.model_name,
            "prompt": "Reply with exactly: SENTINEL_OK",
            "stream": False,
            "options": {"num_predict": 8},
        }).encode("utf-8")
        request = urllib.request.Request(
            self._validated_ollama_url("/api/generate"),
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # URL is constrained by _validated_ollama_url before the request.
            with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310
                body = json.loads(response.read().decode("utf-8"))
            return "SENTINEL" in str(body.get("response", "")).upper()
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return False

    def _validated_ollama_url(self, path: str) -> str:
        if not path.startswith("/") or ".." in path:
            raise ValueError("Invalid Ollama diagnostic path")
        parsed = urllib.parse.urlparse(self.ollama_base_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host:
            raise ValueError("OLLAMA_BASE_URL must be http(s) with a hostname")
        if host not in self.allowed_ollama_hosts:
            raise ValueError(f"Ollama host '{host}' is not in OLLAMA_ALLOWED_HOSTS")
        return urllib.parse.urljoin(f"{self.ollama_base_url}/", path.lstrip("/"))

    @staticmethod
    def _certificate(checks: List[DiagnosticCheck]) -> str:
        import hashlib
        import json

        payload = json.dumps([asdict(check) for check in checks], sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(payload.encode()).hexdigest()
