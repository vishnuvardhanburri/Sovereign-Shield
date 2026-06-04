"""
Sovereign Shield v2 — PDF Report Generator
Generates board-ready compliance, governance, and HIPAA BAA summaries.
Wraps AuditExporter with compliance scoring and executive summary.
"""
import os
from datetime import datetime
from typing import Optional, Dict, Any

from audit.export_engine import AuditExporter
from audit.ledger import audit_ledger
from compliance.dpdp_engine import DPDPEngine
from reporting.compliance_scorer import ComplianceScorer

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
EXPORT_DIR = os.path.join(BASE_DIR, "logs", "exports")


class PDFGenerator:
    """
    High-level PDF report generator for board presentations, governance review, and regulator audits.
    Combines AuditExporter + ComplianceScorer into a single call.
    """

    def __init__(self):
        self.exporter = AuditExporter()
        self.scorer = ComplianceScorer()
        self.dpdp = DPDPEngine()

    def generate_compliance_report(
        self,
        org_name: str = "Your Organization",
        tenant_id: Optional[str] = "default",
        limit: int = 500,
        mfa_enabled_pct: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Generate a full compliance PDF report.
        Returns: {pdf_path, csv_path, scores, chain_status}
        """
        # 1. Gather data
        entries = audit_ledger.get_entries(limit=limit, tenant_id=tenant_id or "default")
        stats = audit_ledger.get_summary_stats(tenant_id=tenant_id)
        chain = audit_ledger.verify_chain()
        chain_valid = chain.get("valid", False)
        dpdp_score = self.dpdp.get_compliance_score()

        # 2. Score
        from policy.policy_engine import policy_engine
        active_policies = policy_engine.list_policies().get("total_rules", 0)

        scores = self.scorer.score(
            audit_stats=stats,
            dpdp_score=dpdp_score,
            chain_integrity=chain_valid,
            active_policies=active_policies,
            open_incidents=dpdp_score.get("open_incidents", 0),
            mfa_enabled_pct=mfa_enabled_pct,
        )

        # 3. Generate PDF
        filename = f"sentinel_compliance_{org_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        pdf_path = self.exporter.to_pdf(
            entries=entries,
            org_name=org_name,
            stats=stats,
            chain_valid=chain_valid,
            filename=filename,
        )

        # 4. Generate CSV backup
        csv_filename = filename.replace(".pdf", ".csv")
        csv_path = self.exporter.to_csv(entries=entries, filename=csv_filename)

        return {
            "pdf_path": pdf_path,
            "csv_path": csv_path,
            "scores": scores,
            "chain_status": chain,
            "total_entries": stats.get("total_events", 0),
            "generated_at": datetime.now().isoformat(),
        }
