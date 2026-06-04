#!/usr/bin/env python3
"""Generate buyer architecture and handoff PDF."""
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "logs" / "handoff"
OUT.mkdir(parents=True, exist_ok=True)


def main() -> int:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:
        path = OUT / "sovereign_shield_architecture_handoff.pdf"
        write_minimal_pdf(path)
        print(f"{path} (minimal PDF fallback; ReportLab unavailable: {exc})")
        return 0

    path = OUT / "sovereign_shield_architecture_handoff.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=letter, title="Sovereign Shield Architecture Handoff")
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("Sovereign Shield Enterprise Handoff", styles["Title"]))
    story.append(Paragraph("Xavira Tech Labs", styles["Heading2"]))
    story.append(Paragraph(f"Generated {datetime.now(timezone.utc).isoformat()}", styles["Normal"]))
    story.append(Spacer(1, 16))
    story.append(Paragraph("Security Flow", styles["Heading2"]))
    flow = [
        ["1", "Enterprise app or dashboard submits prompt"],
        ["2", "Zero-Trust API Shield applies mTLS, rate, body, cost, and path controls"],
        ["3", "Identity Masking Proxy pseudonymizes PII and India DPDP identifiers"],
        ["4", "Prompt Injection Shield and Semantic DLP score adversarial and sensitive context"],
        ["5", "Model Router forces high-sensitivity prompts to local Ollama"],
        ["6", "Obsidian Ledger writes salted hash-chained evidence"],
        ["7", "Oracle Risk Engine updates actor score and queues quarantine context for operator review"],
        ["8", "Enterprise command center exports reports, anchors ledger, and packages handoff evidence"],
    ]
    table = Table(flow, colWidths=[30, 470])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#10b981")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#064e3b")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))
    story.append(Paragraph("Operational Guarantees", styles["Heading2"]))
    guarantees = [
        "Fail-closed secret loading and no wildcard CORS.",
        "No hardcoded demo admin credentials.",
        "Local-first Vault AI; cloud providers are optional and policy-governed.",
        "Critical actions are human-directed, RBAC-protected, and audit-backed.",
        "Tamper-evident JSONL audit ledger with certificate signatures.",
        "Buyer-owned encrypted backup option through BACKUP_ENCRYPTION_PASSPHRASE.",
        "Deployment Doctor, production readiness certificate, SBOM, security scan, and handoff ZIP commands.",
    ]
    for item in guarantees:
        story.append(Paragraph(f"• {item}", styles["Normal"]))
    story.append(Spacer(1, 16))
    story.append(Paragraph("Known Production Assumptions", styles["Heading2"]))
    assumptions = [
        "Ollama must be installed and the configured local model pulled.",
        "mTLS requires Nginx or Envoy to terminate TLS and forward verified certificate headers.",
        "Redis is optional for local demos but recommended for distributed risk state.",
        "Off-box ledger anchoring should point to buyer-controlled immutable storage.",
    ]
    for item in assumptions:
        story.append(Paragraph(f"• {item}", styles["Normal"]))
    doc.build(story)
    print(path)
    return 0


def write_minimal_pdf(path: Path):
    lines = [
        "Sovereign Shield Enterprise Handoff",
        "Xavira Tech Labs",
        f"Generated {datetime.now(timezone.utc).isoformat()}",
        "",
        "Security Flow",
        "1. Enterprise app or dashboard submits prompt",
        "2. Zero-Trust API Shield applies mTLS, rate, body, cost, and path controls",
        "3. Identity Masking Proxy pseudonymizes PII and India DPDP identifiers",
        "4. Prompt Injection Shield and Semantic DLP score sensitive context",
        "5. Model Router forces high-sensitivity prompts to local Ollama",
        "6. Obsidian Ledger writes salted hash-chained evidence",
        "7. Oracle Risk Engine updates actor score and queues quarantine context for operator review",
        "8. Enterprise command center exports reports, anchors ledger, and packages evidence",
        "",
        "Known Production Assumptions",
        "- Ollama must be installed and local model pulled.",
        "- mTLS requires Nginx or Envoy forwarding verified cert headers.",
        "- Redis is recommended for distributed risk state.",
        "- Off-box ledger anchoring should use buyer-controlled immutable storage.",
    ]
    escaped = [line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for line in lines]
    text = "BT /F1 12 Tf 50 750 Td 16 TL " + " T* ".join(f"({line}) Tj" for line in escaped) + " ET"
    stream = text.encode("utf-8")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        f"5 0 obj << /Length {len(stream)} >> stream\n".encode("utf-8") + stream + b"\nendstream endobj\n",
    ]
    content = b"%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(content))
        content += obj
    xref_at = len(content)
    content += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode("utf-8")
    for offset in offsets[1:]:
        content += f"{offset:010d} 00000 n \n".encode("utf-8")
    content += f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("utf-8")
    path.write_bytes(content)


if __name__ == "__main__":
    raise SystemExit(main())
