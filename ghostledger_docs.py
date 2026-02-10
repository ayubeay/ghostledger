#!/usr/bin/env python3
"""
GhostLedger Document Generator
================================
Generates professional payment inquiry and coordination letters
from live claim data. All templates are informational only —
no legal threats, no impersonation, no coercion.

Templates:
  1. Initial Payment Inquiry (Day 1-3)
  2. Follow-Up Request (Day 5-10)
  3. Compliance Reference (Day 10-21)

Usage:
    from ghostledger_docs import generate_letter
    pdf_bytes = generate_letter(claim_data, template="initial")

Version: 2.0 — February 2026
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)


# ── Brand Colors ──
COPPER      = HexColor("#8B5E3C")
COPPER_LIGHT = HexColor("#c9956b")
DARK_BG     = HexColor("#0a0e14")
TEXT_DARK   = HexColor("#1a1a1a")
TEXT_MED    = HexColor("#4a4a4a")
TEXT_LIGHT  = HexColor("#6e7681")
BORDER      = HexColor("#d0d7de")
WHITE       = HexColor("#ffffff")
RED_ACCENT  = HexColor("#da3633")


def _build_styles():
    """Create custom paragraph styles for GhostLedger letters."""
    base = getSampleStyleSheet()

    styles = {
        "brand": ParagraphStyle(
            "brand",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            textColor=COPPER,
            leading=22,
            spaceAfter=6,
        ),
        "tagline": ParagraphStyle(
            "tagline",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=TEXT_LIGHT,
            leading=10,
            spaceBefore=0,
            spaceAfter=16,
        ),
        "subject": ParagraphStyle(
            "subject",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=TEXT_DARK,
            spaceAfter=12,
            spaceBefore=12,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            textColor=TEXT_DARK,
            leading=16,
            spaceAfter=10,
            alignment=TA_JUSTIFY,
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=TEXT_DARK,
            leading=16,
            spaceAfter=10,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            textColor=TEXT_DARK,
            leading=16,
            leftIndent=24,
            spaceAfter=4,
            bulletIndent=12,
        ),
        "closing": ParagraphStyle(
            "closing",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            textColor=TEXT_DARK,
            leading=16,
            spaceAfter=4,
        ),
        "signature": ParagraphStyle(
            "signature",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=COPPER,
            spaceAfter=2,
        ),
        "footer": ParagraphStyle(
            "footer",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=TEXT_LIGHT,
            alignment=TA_CENTER,
        ),
        "meta_label": ParagraphStyle(
            "meta_label",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=TEXT_LIGHT,
        ),
        "meta_value": ParagraphStyle(
            "meta_value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=TEXT_DARK,
        ),
        "warning": ParagraphStyle(
            "warning",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=RED_ACCENT,
            spaceBefore=8,
            spaceAfter=8,
        ),
    }
    return styles


def _add_header(story, styles):
    """Add GhostLedger letterhead."""
    story.append(Paragraph("GhostLedger", styles["brand"]))
    story.append(Paragraph(
        "Recovery Coordination (Non-Legal)  |  No Recovery, No Fee  |  ghostledger.io",
        styles["tagline"],
    ))
    story.append(HRFlowable(
        width="100%", thickness=1.5, color=COPPER, spaceAfter=16,
    ))


def _add_case_meta(story, styles, claim: Dict):
    """Add case metadata table (claim ID, date, respondent, amount)."""
    claim_id = claim.get("claim_id", "N/A")
    filed_at = claim.get("filed_at", "")
    try:
        filed_date = datetime.fromisoformat(filed_at.replace("Z", "")).strftime("%B %d, %Y")
    except (ValueError, TypeError, AttributeError):
        filed_date = datetime.utcnow().strftime("%B %d, %Y")

    respondent = claim.get("respondent_entity", "Unknown Platform")
    amount = claim.get("amount_claimed_usd", 0)
    claimant = claim.get("claimant_name", "")

    meta_data = [
        [
            Paragraph("Case Reference", styles["meta_label"]),
            Paragraph(claim_id, styles["meta_value"]),
            Paragraph("Date", styles["meta_label"]),
            Paragraph(filed_date, styles["meta_value"]),
        ],
        [
            Paragraph("Respondent", styles["meta_label"]),
            Paragraph(respondent, styles["meta_value"]),
            Paragraph("Amount in Dispute", styles["meta_label"]),
            Paragraph(f"${amount:,.2f} USD", styles["meta_value"]),
        ],
        [
            Paragraph("Claimant", styles["meta_label"]),
            Paragraph(claimant, styles["meta_value"]),
            Paragraph("Status", styles["meta_label"]),
            Paragraph((claim.get("status", "filed")).replace("_", " ").title(), styles["meta_value"]),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[1.2 * inch, 2.3 * inch, 1.2 * inch, 2.3 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f6f8fa")),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))


def _add_footer(story, styles, claim: Dict):
    """Add footer with disclaimer."""
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8))
    story.append(Paragraph(
        "This communication is sent on behalf of the claimant for the purpose of payment status inquiry. "
        "GhostLedger coordinates recovery efforts and does not provide legal advice or legal representation. "
        "This is not a legal demand. No government filing or legal action is implied or threatened.",
        styles["footer"],
    ))
    story.append(Paragraph(
        f"Case Ref: {claim.get('claim_id', 'N/A')} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["footer"],
    ))


def _build_initial_notice(claim: Dict) -> list:
    """Template 1: Initial Payment Inquiry (Day 1-3).
    Neutral tone, no threats, no legal claims. Asks for information only."""
    styles = _build_styles()
    story = []

    _add_header(story, styles)
    _add_case_meta(story, styles, claim)

    respondent = claim.get("respondent_entity", "the platform")
    amount = claim.get("amount_claimed_usd", 0)
    claimant = claim.get("claimant_name", "the claimant")
    description = claim.get("description", "")
    support_status = (claim.get("contacted_support", "no_not_yet")).replace("_", " ")

    story.append(Paragraph(
        f"Subject: Account Payment Status Inquiry — {claim.get('claim_id', 'N/A')}",
        styles["subject"],
    ))

    story.append(Paragraph("Hello,", styles["body"]))

    story.append(Paragraph(
        f"I am following up regarding an unpaid or withheld balance of "
        f"<b>${amount:,.2f} USD</b> associated with <b>{claimant}</b>'s account "
        f"on the <b>{respondent}</b> platform.",
        styles["body"],
    ))

    if description:
        story.append(Paragraph(
            f"Relevant documentation has been provided for reference. "
            f"The claimant reports the following: <i>{description}</i>",
            styles["body"],
        ))

    story.append(Paragraph(
        f"Support contact status: <b>{support_status}</b>.",
        styles["body"],
    ))

    story.append(Paragraph(
        "At your convenience, please confirm:",
        styles["body"],
    ))

    items = [
        "The current status of the payment or balance in question",
        "Any reason provided for delay or rejection, if applicable",
        "An estimated timeline for next steps",
        "Any additional documentation required from the claimant",
    ]
    for item in items:
        story.append(Paragraph(f"&bull;  {item}", styles["bullet"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Thank you for your time and attention. Our goal is to resolve this inquiry "
        "through standard support channels.",
        styles["body"],
    ))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Best regards,", styles["closing"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("GhostLedger \u2014 Recovery Coordination (Non-Legal)", styles["signature"]))
    story.append(Paragraph(
        f"On behalf of {claimant}",
        styles["closing"],
    ))

    _add_footer(story, styles, claim)
    return story


def _build_second_escalation(claim: Dict) -> list:
    """Template 2: Follow-Up Request (Day 5-10).

    Rules:
      MAY: reference prior contact, ask for escalation to senior support,
           ask for a ticket or reference number.
      MUST NOT: mention regulators, use 'demand', use 'failure to respond',
                imply consequences.
      Tone: 'following up' — not 'pressing'.
    """
    styles = _build_styles()
    story = []

    _add_header(story, styles)
    _add_case_meta(story, styles, claim)

    respondent = claim.get("respondent_entity", "the platform")
    amount = claim.get("amount_claimed_usd", 0)
    claimant = claim.get("claimant_name", "the claimant")
    claim_id = claim.get("claim_id", "N/A")

    filed_str = claim.get("filed_at", "")
    try:
        filed = datetime.fromisoformat(filed_str.replace("Z", "").replace("+00:00", ""))
        days_open = (datetime.utcnow() - filed).days
    except (ValueError, TypeError, AttributeError):
        days_open = 7

    story.append(Paragraph(
        f"Subject: Follow-Up \u2014 Payment Status Inquiry \u2014 Ref: {claim_id}",
        styles["subject"],
    ))

    story.append(Paragraph("Hello,", styles["body"]))

    story.append(Paragraph(
        f"I am following up on a previous inquiry (reference: <b>{claim_id}</b>) "
        f"regarding an unpaid balance of <b>${amount:,.2f} USD</b> associated with "
        f"<b>{claimant}</b>'s account on <b>{respondent}</b>.",
        styles["body"],
    ))

    story.append(Paragraph(
        f"This inquiry was first submitted <b>{days_open} days ago</b>, and we have not yet "
        f"received a substantive update. We understand that reviews can take time and appreciate "
        f"your team's attention to this matter.",
        styles["body"],
    ))

    story.append(Paragraph(
        "To help move this forward, we respectfully ask:",
        styles["body"],
    ))

    items = [
        "Could this inquiry be routed to a senior support or payments team member?",
        "Is there a ticket or reference number we can use for future follow-ups?",
        "Is any additional documentation needed from the claimant?",
    ]
    for item in items:
        story.append(Paragraph(f"&bull;  {item}", styles["bullet"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "We remain committed to resolving this through your standard support channels "
        "and appreciate any update you can provide at your earliest convenience.",
        styles["body"],
    ))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Best regards,", styles["closing"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("GhostLedger \u2014 Recovery Coordination (Non-Legal)", styles["signature"]))
    story.append(Paragraph(f"On behalf of {claimant}", styles["closing"]))

    _add_footer(story, styles, claim)
    return story


def _build_compliance_escalation(claim: Dict) -> list:
    """Template 3: Compliance Reference (Day 10-21).

    Rules:
      MAY: reference publicly stated platform policies, reference consumer
           protection frameworks in general terms, ask how the platform
           aligns with its own published procedures.
      MUST NEVER: say 'we will report', say 'we are filing', say 'required
                  by law', imply government action is imminent, list agencies
                  as a threat, use 'demand', 'final opportunity', or
                  'proceedings will be initiated'.
      Tone: informational and professional — never threatening.
    """
    styles = _build_styles()
    story = []

    _add_header(story, styles)
    _add_case_meta(story, styles, claim)

    respondent = claim.get("respondent_entity", "the platform")
    amount = claim.get("amount_claimed_usd", 0)
    claimant = claim.get("claimant_name", "the claimant")
    claim_id = claim.get("claim_id", "N/A")

    filed_str = claim.get("filed_at", "")
    try:
        filed = datetime.fromisoformat(filed_str.replace("Z", "").replace("+00:00", ""))
        filed_date = filed.strftime("%B %d, %Y")
        days_open = (datetime.utcnow() - filed).days
    except (ValueError, TypeError, AttributeError):
        filed_date = "the date of initial contact"
        days_open = 14

    story.append(Paragraph(
        f"Subject: Payment Status Follow-Up \u2014 Compliance Reference \u2014 Ref: {claim_id}",
        styles["subject"],
    ))

    story.append(Paragraph("Hello,", styles["body"]))

    story.append(Paragraph(
        f"I am writing as a continued follow-up regarding a payment inquiry involving "
        f"<b>${amount:,.2f} USD</b> associated with <b>{claimant}</b>'s account on "
        f"<b>{respondent}</b>, first submitted on <b>{filed_date}</b>.",
        styles["body"],
    ))

    story.append(Paragraph(
        f"This inquiry has been open for <b>{days_open} days</b>. We have previously "
        f"communicated through your standard support channels and have not yet received "
        f"a substantive resolution or update.",
        styles["body"],
    ))

    story.append(Paragraph(
        "For your reference, the following consumer protection frameworks may be "
        "applicable to disputes of this nature. We share these solely for informational "
        "purposes and transparency:",
        styles["body"],
    ))

    frameworks = [
        "Consumer Financial Protection Bureau (CFPB) \u2014 consumer complaint processes",
        "Federal Trade Commission (FTC) \u2014 unfair or deceptive practices guidance",
        "State consumer protection statutes and agencies",
        "Platform-published terms of service and payment policies",
    ]
    for fw in frameworks:
        story.append(Paragraph(f"&bull;  {fw}", styles["bullet"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "We are seeking clarity on how this situation aligns with "
        f"<b>{respondent}</b>'s published policies and the consumer protection "
        "processes referenced above. We are not filing or threatening any action \u2014 "
        "our goal remains to resolve this through direct communication.",
        styles["body"],
    ))

    story.append(Paragraph(
        "If there is additional context, documentation, or a specific team member "
        "we should direct this inquiry to, we welcome that guidance.",
        styles["body"],
    ))

    # Classification info if available (internal routing context, not a threat)
    cc = claim.get("classification", {})
    if cc.get("value_band"):
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"<b>Internal Routing Note:</b> {cc.get('dispute_type', 'N/A').replace('_', ' ').title()} | "
            f"Value Band: {cc.get('value_band', 'N/A').replace('_', ' ').title()} | "
            f"Initial Assessment: {cc.get('recovery_path', 'N/A').replace('_', ' ').title()}",
            styles["meta_label"],
        ))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Best regards,", styles["closing"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("GhostLedger \u2014 Recovery Coordination (Non-Legal)", styles["signature"]))
    story.append(Paragraph(f"On behalf of {claimant}", styles["closing"]))

    _add_footer(story, styles, claim)
    return story


# ── Template Registry ──
TEMPLATES = {
    "initial": {
        "name": "Initial Payment Inquiry",
        "day_range": "Day 1-3",
        "builder": _build_initial_notice,
    },
    "second": {
        "name": "Follow-Up Request",
        "day_range": "Day 5-10",
        "builder": _build_second_escalation,
    },
    "compliance": {
        "name": "Compliance Reference",
        "day_range": "Day 10-21",
        "builder": _build_compliance_escalation,
    },
}


def generate_letter(
    claim: Dict[str, Any],
    template: str = "initial",
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a payment inquiry letter PDF from claim data.

    All templates are informational only — no legal threats,
    no impersonation, no coercion.

    Args:
        claim: Full claim data dict (from the API).
        template: One of "initial", "second", "compliance".
        output_path: If provided, also writes to this file path.

    Returns:
        PDF as bytes (can be streamed directly in an HTTP response).
    """
    if template not in TEMPLATES:
        raise ValueError(f"Unknown template: {template}. Must be one of: {list(TEMPLATES.keys())}")

    builder = TEMPLATES[template]["builder"]

    # Build PDF in memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=f"GhostLedger - {TEMPLATES[template]['name']}",
        author="GhostLedger — Recovery Coordination (Non-Legal)",
    )

    story = builder(claim)
    doc.build(story)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    # Optionally write to disk
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


def list_templates() -> list:
    """Return available templates with metadata."""
    return [
        {
            "key": key,
            "name": info["name"],
            "day_range": info["day_range"],
        }
        for key, info in TEMPLATES.items()
    ]


if __name__ == "__main__":
    # Quick test: generate all 3 templates with sample data
    sample_claim = {
        "claim_id": "clm_test123456",
        "claimant_name": "Jane Doe",
        "claimant_email": "jane@example.com",
        "respondent_entity": "Shiftsmart",
        "amount_claimed_usd": 2450.00,
        "description": "Completed 2 weeks of shifts but payout has been withheld for over 30 days. Support says 'under review' with no timeline.",
        "contacted_support": "yes_no_resolution",
        "status": "escalated",
        "harm_type": "payout_withholding",
        "filed_at": "2026-01-15T10:00:00",
        "classification": {
            "value_band": "small",
            "dispute_type": "gig_worker_dispute",
            "complexity_score": 3,
            "recovery_path": "platform_escalation",
            "requires_human_triage": False,
        },
    }

    for tpl in ["initial", "second", "compliance"]:
        path = f"/tmp/ghostledger_{tpl}.pdf"
        generate_letter(sample_claim, template=tpl, output_path=path)
        print(f"Generated: {path}")
