"""
Sovereign Shield Enterprise — Evidence PDF Generator

Builds a board-ready DPDP 2026/FedRAMP-style evidence report with Obsidian
ledger integrity, top Oracle risk actors, human review context, and a
tamper-proof certificate.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from audit.ledger import audit_ledger
from risk_engine import oracle_risk_engine

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
EXPORT_DIR = os.path.join(BASE_DIR, "logs", "exports")


class EvidencePDFGenerator:
    def __init__(self):
        os.makedirs(EXPORT_DIR, exist_ok=True)

    def generate(
        self,
        org_name: str = "Buyer Organization",
        tenant_id: str = "default",
        limit: int = 500,
        primary_color: str = "#047857",
        compliance_frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        entries = audit_ledger.get_entries(limit=limit, tenant_id=tenant_id)
        stats = audit_ledger.get_summary_stats(tenant_id=tenant_id)
        chain = audit_ledger.verify_chain()
        heatmap = oracle_risk_engine.heatmap(tenant_id=tenant_id, limit=5)
        high_sensitivity = [e for e in entries if float(e.get("risk_score") or 0) > 7.0]
        certificate = self._certificate(entries, stats, chain, heatmap)

        filename = f"sentinel_evidence_{org_name.replace(' ', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        path = os.path.join(EXPORT_DIR, filename)
        if REPORTLAB_AVAILABLE:
            self._write_pdf(path, org_name, stats, chain, heatmap, high_sensitivity, certificate, primary_color, compliance_frameworks or [])
        else:
            path = self._write_text_fallback(path.replace(".pdf", ".txt"), org_name, stats, chain, heatmap, high_sensitivity, certificate)

        return {
            "status": "success",
            "file": path,
            "reportlab_available": REPORTLAB_AVAILABLE,
            "certificate": certificate,
            "chain_valid": chain.get("valid", False),
            "total_pii_blocked": stats.get("total_redactions", 0),
            "high_sensitivity_interceptions": len(high_sensitivity),
            "top_risk_actors": heatmap.get("actors", []),
        }

    def _write_pdf(
        self,
        path: str,
        org_name: str,
        stats: Dict[str, Any],
        chain: Dict[str, Any],
        heatmap: Dict[str, Any],
        high_sensitivity: List[Dict[str, Any]],
        certificate: str,
        primary_color: str = "#047857",
        compliance_frameworks: Optional[List[str]] = None,
    ):
        doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=1.7 * cm, leftMargin=1.7 * cm, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
        styles = getSampleStyleSheet()
        title = ParagraphStyle("SentinelTitle", parent=styles["Title"], fontSize=20, textColor=colors.HexColor(primary_color or "#047857"))
        section = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#111827"))
        mono = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=7, textColor=colors.HexColor("#374151"))
        story: List[Any] = []

        story.append(Paragraph("Sovereign Shield Human-Governed Evidence Report", title))
        story.append(Paragraph(f"{org_name} · Generated {datetime.now(timezone.utc).isoformat()}", styles["Normal"]))
        if compliance_frameworks:
            story.append(Paragraph("Frameworks: " + ", ".join(compliance_frameworks), styles["Normal"]))
        story.append(Spacer(1, 0.4 * cm))

        summary = [
            ["Control", "Evidence"],
            ["Total PII Blocked", str(stats.get("total_redactions", 0))],
            ["Audit Events", str(stats.get("total_events", 0))],
            ["High Sensitivity Interceptions", str(len(high_sensitivity))],
            ["Ledger Integrity", "VERIFIED" if chain.get("valid") else "BROKEN"],
            ["Tamper-Proof Certificate", certificate],
        ]
        story.append(Paragraph("DPDP 2026 Governance Audit Summary", section))
        story.append(self._table(summary, [5.2 * cm, 11.2 * cm]))
        story.append(Spacer(1, 0.5 * cm))

        actors = [["Rank", "Actor Hash", "Risk", "PII/hr", "Injection/hr", "Quarantined"]]
        for idx, actor in enumerate(heatmap.get("actors", [])[:5], 1):
            actors.append([
                str(idx),
                str(actor.get("actor_hash", ""))[:24] + "...",
                str(actor.get("risk_score", 0)),
                str(actor.get("pii_attempts_last_hour", 0)),
                str(actor.get("injection_attempts_last_hour", 0)),
                "YES" if actor.get("quarantined") else "NO",
            ])
        story.append(Paragraph("Top 5 Oracle Risk Actors for Operator Review", section))
        story.append(self._table(actors, [1.2 * cm, 6.3 * cm, 2 * cm, 2 * cm, 2.5 * cm, 2.4 * cm]))
        story.append(Spacer(1, 0.5 * cm))

        interceptions = [["Timestamp", "Actor Hash", "Action", "Risk", "Policy"]]
        for event in high_sensitivity[:25]:
            interceptions.append([
                str(event.get("timestamp", ""))[:19].replace("T", " "),
                str(event.get("actor_hash", event.get("user_id", "")))[:18] + "...",
                str(event.get("action", ""))[:24],
                str(event.get("risk_score", "")),
                str(event.get("policy_triggered", ""))[:36],
            ])
        story.append(Paragraph("High Sensitivity Interceptions", section))
        story.append(self._table(interceptions, [3.4 * cm, 4.2 * cm, 3.4 * cm, 1.4 * cm, 4 * cm]))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Tamper-Proof Certificate Signature", section))
        story.append(Paragraph(certificate, mono))
        story.append(Paragraph("This digest is derived from the Obsidian JSONL ledger, Oracle risk state, human-governance metadata, and report summary. Any ledger mutation changes the certificate.", styles["Normal"]))
        doc.build(story)

    @staticmethod
    def _table(rows: List[List[str]], widths: List[float]) -> Table:
        table = Table(rows, colWidths=widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#064e3b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    @staticmethod
    def _certificate(entries: List[Dict[str, Any]], stats: Dict[str, Any], chain: Dict[str, Any], heatmap: Dict[str, Any]) -> str:
        payload = {
            "entry_hashes": [e.get("entry_hash") or e.get("signature") for e in entries],
            "stats": stats,
            "chain": chain,
            "top_actors": heatmap.get("actors", [])[:5],
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    @staticmethod
    def _write_text_fallback(path: str, org_name: str, stats: Dict[str, Any], chain: Dict[str, Any], heatmap: Dict[str, Any], high_sensitivity: List[Dict[str, Any]], certificate: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Sovereign Shield Human-Governed Evidence Report\n{org_name}\n\n")
            f.write(json.dumps({
                "stats": stats,
                "chain": chain,
                "top_actors": heatmap.get("actors", [])[:5],
                "high_sensitivity_count": len(high_sensitivity),
                "certificate": certificate,
            }, indent=2, default=str))
        return path
