"""
PDF Verification Report Generator.

Generates professional, auditor-friendly PDF reports for verified submissions.
Uses reportlab (pure Python, no system dependencies).
"""
import io
import logging
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import HorizontalBarChart

from core.database import (
    SessionLocal, RawSubmission, CleanedData,
    VerificationResult, BlockchainStamp, DataQuarantine,
)

logger = logging.getLogger("REPORT_GEN")

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#1e293b")
DARK_GRAY = colors.HexColor("#334155")
MED_GRAY = colors.HexColor("#64748b")
LIGHT_GRAY = colors.HexColor("#f1f5f9")
WHITE = colors.white

VERDICT_COLORS = {
    "GOLD": colors.HexColor("#15803d"),
    "VERIFIED": colors.HexColor("#16a34a"),
    "QUARANTINE": colors.HexColor("#d97706"),
    "REJECTED": colors.HexColor("#dc2626"),
}

SCORE_GREEN = colors.HexColor("#16a34a")
SCORE_AMBER = colors.HexColor("#d97706")
SCORE_RED = colors.HexColor("#dc2626")


def _score_color(score: float) -> colors.HexColor:
    if score >= 0.7:
        return SCORE_GREEN
    if score >= 0.4:
        return SCORE_AMBER
    return SCORE_RED


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=18, textColor=WHITE,
        alignment=TA_LEFT, spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"],
        fontName="Helvetica", fontSize=10, textColor=colors.HexColor("#94a3b8"),
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=13, textColor=NAVY,
        spaceBefore=6 * mm, spaceAfter=3 * mm,
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9, textColor=DARK_GRAY,
        leading=13,
    ))
    styles.add(ParagraphStyle(
        "SmallGray", parent=styles["Normal"],
        fontName="Helvetica", fontSize=8, textColor=MED_GRAY,
    ))
    styles.add(ParagraphStyle(
        "VerdictLarge", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=22, textColor=WHITE,
        alignment=TA_CENTER, leading=28,
    ))
    styles.add(ParagraphStyle(
        "VerdictSub", parent=styles["Normal"],
        fontName="Helvetica", fontSize=11, textColor=WHITE,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "CellText", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9, textColor=DARK_GRAY,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        "CellBold", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=9, textColor=DARK_GRAY,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        "FooterStyle", parent=styles["Normal"],
        fontName="Helvetica", fontSize=7, textColor=MED_GRAY,
        alignment=TA_CENTER,
    ))
    return styles


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def _load_report_data(submission_id: str) -> dict:
    """Load all DB records needed for the report. Returns dict or raises."""
    db = SessionLocal()
    try:
        raw = db.query(RawSubmission).filter(
            RawSubmission.id == submission_id
        ).first()
        if not raw:
            return {}

        verification = db.query(VerificationResult).filter(
            VerificationResult.submission_id == submission_id
        ).order_by(VerificationResult.created_at.desc()).first()

        cleaned = db.query(CleanedData).filter(
            CleanedData.submission_id == submission_id
        ).first()

        stamp = None
        quarantine = None
        if verification:
            stamp = db.query(BlockchainStamp).filter(
                BlockchainStamp.verification_result_id == verification.id
            ).first()
            quarantine = db.query(DataQuarantine).filter(
                DataQuarantine.verification_result_id == verification.id
            ).first()

        return {
            "raw": raw,
            "verification": verification,
            "cleaned": cleaned,
            "stamp": stamp,
            "quarantine": quarantine,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------
def _std_table_style(has_header: bool = True):
    """Standard table style with alternating rows."""
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY if has_header else LIGHT_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE if has_header else DARK_GRAY),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 1), (-1, -1), DARK_GRAY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    return cmds


def _alt_row_bg(start_row: int, end_row: int):
    """Returns table style commands for alternating row backgrounds."""
    cmds = []
    for i in range(start_row, end_row + 1):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), LIGHT_GRAY))
    return cmds


def _score_text(score, styles):
    """Return a colored score paragraph."""
    c = _score_color(score)
    return Paragraph(
        f'<font color="{c.hexval()}">{score:.3f}</font>',
        styles["CellText"],
    )


def _status_text(passed: bool, styles):
    if passed:
        return Paragraph(
            '<font color="#16a34a">PASS</font>', styles["CellBold"]
        )
    return Paragraph(
        '<font color="#dc2626">FAIL</font>', styles["CellBold"]
    )


# ---------------------------------------------------------------------------
# Score bar drawing
# ---------------------------------------------------------------------------
def _score_bar(score: float, width=120, height=12):
    """Small inline colored score bar."""
    d = Drawing(width, height)
    # Background
    d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#e2e8f0"),
               strokeColor=None))
    # Filled portion
    fill_w = max(1, score * width)
    d.add(Rect(0, 0, fill_w, height, fillColor=_score_color(score),
               strokeColor=None))
    # Score text
    d.add(String(width + 4, 1, f"{score:.2f}",
                 fontName="Helvetica", fontSize=8, fillColor=DARK_GRAY))
    return d


# ---------------------------------------------------------------------------
# Page template callbacks
# ---------------------------------------------------------------------------
def _header_footer(canvas, doc, proof_hash: str = ""):
    """Draw header bar and footer on every page."""
    width, height = A4
    # Header bar
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 22 * mm, width, 22 * mm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(15 * mm, height - 14 * mm, "THE LAST BASTION")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.drawString(15 * mm, height - 19 * mm, "Independent Verification Platform")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        width - 15 * mm, height - 14 * mm,
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    )
    canvas.restoreState()

    # Footer
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MED_GRAY)
    canvas.drawString(15 * mm, 10 * mm,
                      "The Last Bastion — Independent Verification Platform")
    canvas.drawCentredString(width / 2, 10 * mm,
                             f"Page {doc.page}")
    if proof_hash:
        canvas.drawRightString(
            width - 15 * mm, 10 * mm,
            f"Verify: GET /m2m/verify/{proof_hash[:16]}...",
        )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
async def generate_verification_report(submission_id: str) -> bytes:
    """Generate a professional PDF verification report. Returns PDF bytes."""
    data = _load_report_data(submission_id)
    if not data:
        raise ValueError(f"Submission {submission_id} not found")

    raw = data["raw"]
    vr = data["verification"]
    cleaned = data["cleaned"]
    stamp = data["stamp"]
    quarantine = data["quarantine"]

    styles = _build_styles()
    buf = io.BytesIO()

    proof_hash = vr.proof_hash if vr else ""

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=28 * mm,  # space for header
        bottomMargin=18 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
    )

    elements = []

    # -----------------------------------------------------------------------
    # PAGE 1: Executive Summary
    # -----------------------------------------------------------------------
    report_id = f"RPT-{submission_id[:8]}"
    elements.append(Paragraph(
        f"Verification Report &nbsp; <font size=10 color='#94a3b8'>{report_id}</font>",
        styles["SectionHeader"],
    ))

    # Verdict banner
    verdict = vr.verdict if vr else "PENDING"
    score = vr.composite_score if vr else 0.0
    vc = VERDICT_COLORS.get(verdict, MED_GRAY)

    verdict_data = [[
        Paragraph(
            f'<font color="white" size="20"><b>{verdict}</b></font>'
            f'<br/><font color="white" size="11">'
            f'Composite Score: {score:.3f} / 1.000</font>',
            styles["VerdictSub"],
        )
    ]]
    verdict_table = Table(verdict_data, colWidths=[doc.width])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), vc),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 4 * mm))

    # Submission details table (2-column key-value)
    elements.append(Paragraph("Submission Details", styles["SectionHeader"]))

    blockchain_status = "Not anchored"
    if stamp:
        if stamp.tx_hash:
            blockchain_status = f"Anchored (tx: {stamp.tx_hash[:16]}...)"
        elif stamp.anchor_approved:
            blockchain_status = "Approved, pending anchor"
        else:
            blockchain_status = "Pending human approval"

    details_data = [
        ["Submission ID", raw.id, "Data Hash", (raw.data_hash or "—")[:24] + "..."],
        ["Source Agent", raw.source_agent_id or "—", "Document Format", raw.format or "—"],
        ["File Size", f"{raw.raw_size_bytes or 0:,} bytes", "Submitted", _fmt_dt(raw.created_at)],
        ["Proof Hash", (proof_hash or "—")[:24] + "...", "Blockchain", blockchain_status],
    ]
    col_w = doc.width / 4
    det_table = Table(details_data, colWidths=[col_w * 0.8, col_w * 1.2, col_w * 0.8, col_w * 1.2])
    det_style = _std_table_style(has_header=False)
    # Bold label columns
    det_style.extend([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
        ("BACKGROUND", (2, 0), (2, -1), LIGHT_GRAY),
    ])
    det_table.setStyle(TableStyle(det_style))
    elements.append(det_table)
    elements.append(Spacer(1, 4 * mm))

    # Pillar scores table
    elements.append(Paragraph("Verification Pillar Scores", styles["SectionHeader"]))

    layer_scores = (vr.layer_scores if vr else {}) or {}
    details_json = (vr.details if vr else {}) or {}

    pillar_rows = [["Layer", "Score", "Status", "Notes"]]

    # Gates
    gate1 = layer_scores.get("schema_gatekeeper", layer_scores.get("gate_1", {}))
    gate1_score = _extract_score(gate1)
    gate1_veto = _extract_flag(gate1, "veto")
    pillar_rows.append([
        "Gate 1: Schema Gatekeeper", f"{gate1_score:.3f}",
        "VETO" if gate1_veto else ("PASS" if gate1_score >= 0.5 else "FAIL"),
        "Veto active" if gate1_veto else "",
    ])

    gate2 = layer_scores.get("consistency_analyzer", layer_scores.get("gate_2", {}))
    gate2_score = _extract_score(gate2)
    pillar_rows.append([
        "Gate 2: Consistency Analyzer", f"{gate2_score:.3f}",
        "PASS" if gate2_score >= 0.5 else "FAIL", "",
    ])

    # Pillars
    p1 = layer_scores.get("forensic_integrity", layer_scores.get("pillar_1", {}))
    p1_score = _extract_score(p1)
    p1_weight = _extract_weight(p1, 0.35)
    pillar_rows.append([
        "Pillar 1: Forensic Integrity", f"{p1_score:.3f}",
        "PASS" if p1_score >= 0.5 else "FAIL", f"Weight: {p1_weight:.2f}",
    ])

    p2 = layer_scores.get("logic_triangulation", layer_scores.get("pillar_2", {}))
    p2_score = _extract_score(p2)
    p2_veto = _extract_flag(p2, "veto")
    p2_weight = _extract_weight(p2, 0.45)
    pillar_rows.append([
        "Pillar 2: Logic Triangulation", f"{p2_score:.3f}",
        "VETO" if p2_veto else ("PASS" if p2_score >= 0.5 else "FAIL"),
        f"Weight: {p2_weight:.2f}" + (" | Veto active" if p2_veto else ""),
    ])

    p3 = layer_scores.get("attestation", layer_scores.get("pillar_3", {}))
    p3_score = _extract_score(p3)
    if p3_score > 0:
        p3_weight = _extract_weight(p3, 0.20)
        pillar_rows.append([
            "Pillar 3: Attestation", f"{p3_score:.3f}",
            "PASS" if p3_score >= 0.5 else "FAIL", f"Weight: {p3_weight:.2f}",
        ])

    adv = layer_scores.get("adversarial_challenge", layer_scores.get("adversarial", {}))
    adv_penalty = _extract_score(adv, key="penalty")
    if adv_penalty == 0:
        adv_penalty = _extract_score(adv)
    pillar_rows.append([
        "Adversarial Challenge", f"{adv_penalty:.3f}",
        "Penalty" if adv_penalty > 0 else "No penalty",
        f"Score reduced by {adv_penalty:.3f}",
    ])

    pillar_table = Table(pillar_rows, colWidths=[
        doc.width * 0.35, doc.width * 0.12, doc.width * 0.13, doc.width * 0.40,
    ])
    p_style = _std_table_style(has_header=True)
    p_style.extend(_alt_row_bg(1, len(pillar_rows) - 1))
    pillar_table.setStyle(TableStyle(p_style))
    elements.append(pillar_table)
    elements.append(Spacer(1, 4 * mm))

    # Composite score formula
    elements.append(Paragraph("Composite Score Calculation", styles["SectionHeader"]))
    formula = (
        "Weighted formula: "
        f"(Forensic × {p1_weight:.2f}) + (Triangulation × {p2_weight:.2f})"
    )
    if p3_score > 0:
        formula += f" + (Attestation × {_extract_weight(p3, 0.20):.2f})"
    formula += " − Adversarial Penalty"
    elements.append(Paragraph(formula, styles["BodyText2"]))
    elements.append(Paragraph(
        f"<b>Result: {score:.3f}</b> → <b>{verdict}</b>",
        styles["BodyText2"],
    ))

    # -----------------------------------------------------------------------
    # PAGE 2: Detailed Analysis
    # -----------------------------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("Detailed Layer Analysis", styles["SectionHeader"]))

    # Extract per-layer results from details JSON
    layer_results = _extract_layer_details(details_json, layer_scores)
    if layer_results:
        lr_rows = [["Layer", "Score", "Status", "Key Findings"]]
        for lr in layer_results:
            findings = lr.get("findings", "")
            if len(findings) > 120:
                findings = findings[:117] + "..."
            lr_rows.append([
                lr["name"],
                f"{lr['score']:.3f}",
                lr["status"],
                Paragraph(findings, styles["CellText"]),
            ])

        lr_table = Table(lr_rows, colWidths=[
            doc.width * 0.28, doc.width * 0.10, doc.width * 0.10, doc.width * 0.52,
        ])
        lr_style = _std_table_style(has_header=True)
        lr_style.extend(_alt_row_bg(1, len(lr_rows) - 1))
        lr_table.setStyle(TableStyle(lr_style))
        elements.append(lr_table)
    else:
        elements.append(Paragraph(
            "No detailed layer breakdown available for this submission.",
            styles["BodyText2"],
        ))

    elements.append(Spacer(1, 4 * mm))

    # Warnings & Anomalies
    warnings = _collect_warnings(details_json, layer_scores)
    if warnings:
        elements.append(Paragraph("Warnings &amp; Anomalies", styles["SectionHeader"]))
        for w in warnings[:20]:  # cap at 20
            bullet_color = "#d97706" if w["level"] == "warning" else "#dc2626"
            elements.append(Paragraph(
                f'<font color="{bullet_color}">\u25cf</font> '
                f'<b>{w["source"]}</b>: {w["text"]}',
                styles["BodyText2"],
            ))
        elements.append(Spacer(1, 3 * mm))

    # Evidence chain
    evidence = _extract_evidence(details_json)
    if evidence:
        elements.append(Paragraph("Evidence Chain", styles["SectionHeader"]))
        ev_rows = [["#", "Source", "Field", "Result", "Confidence"]]
        for i, ev in enumerate(evidence[:15], 1):
            ev_rows.append([
                str(i),
                ev.get("source", "—"),
                ev.get("field", "—"),
                ev.get("result", "—"),
                f"{ev.get('confidence', 0):.2f}",
            ])
        ev_table = Table(ev_rows, colWidths=[
            doc.width * 0.06, doc.width * 0.22, doc.width * 0.22,
            doc.width * 0.35, doc.width * 0.15,
        ])
        ev_style = _std_table_style(has_header=True)
        ev_style.extend(_alt_row_bg(1, len(ev_rows) - 1))
        ev_table.setStyle(TableStyle(ev_style))
        elements.append(ev_table)

    # -----------------------------------------------------------------------
    # PAGE 3: Cryptographic Proof & Audit Trail
    # -----------------------------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("Cryptographic Proof &amp; Audit Trail", styles["SectionHeader"]))

    # Proof ledger record
    elements.append(Paragraph("Proof Ledger Record", styles["SectionHeader"]))
    proof_data = [
        ["Field", "Value"],
        ["Proof Hash", proof_hash or "—"],
        ["Data Hash", raw.data_hash or "—"],
        ["Submission ID", raw.id],
        ["Verdict", verdict],
        ["Composite Score", f"{score:.3f}"],
        ["Recorded At", _fmt_dt(vr.created_at) if vr else "—"],
    ]
    proof_table = Table(proof_data, colWidths=[doc.width * 0.30, doc.width * 0.70])
    pr_style = _std_table_style(has_header=True)
    pr_style.extend(_alt_row_bg(1, len(proof_data) - 1))
    proof_table.setStyle(TableStyle(pr_style))
    elements.append(proof_table)
    elements.append(Spacer(1, 2 * mm))

    elements.append(Paragraph(
        "This record is part of a tamper-evident Merkle chain. "
        "Modifying any record invalidates all subsequent records in the chain. "
        "The proof hash is a SHA-256 digest of the verification payload.",
        styles["SmallGray"],
    ))
    elements.append(Spacer(1, 4 * mm))

    # Blockchain anchor
    elements.append(Paragraph("Blockchain Anchor", styles["SectionHeader"]))
    chain_name = stamp.chain if stamp else "polygon"
    tx_hash = stamp.tx_hash if stamp else None
    block_num = stamp.block_number if stamp else None

    bc_data = [
        ["Field", "Value"],
        ["Network", f"{chain_name.title()} (Amoy Testnet)"],
        ["Transaction Hash", tx_hash or "Not yet anchored"],
        ["Block Number", str(block_num) if block_num else "—"],
        ["Status", blockchain_status],
    ]
    if tx_hash:
        bc_data.append([
            "Verify URL",
            f"https://amoy.polygonscan.com/tx/{tx_hash}",
        ])

    bc_table = Table(bc_data, colWidths=[doc.width * 0.30, doc.width * 0.70])
    bc_style = _std_table_style(has_header=True)
    bc_style.extend(_alt_row_bg(1, len(bc_data) - 1))
    bc_table.setStyle(TableStyle(bc_style))
    elements.append(bc_table)
    elements.append(Spacer(1, 4 * mm))

    # Quarantine details (if applicable)
    if quarantine:
        elements.append(Paragraph("Quarantine Details", styles["SectionHeader"]))
        q_data = [
            ["Field", "Value"],
            ["Reason", quarantine.reason or "Score in uncertain range (0.40–0.70)"],
            ["Resolution Status", quarantine.resolution_status],
            ["Score", f"{quarantine.score:.3f}" if quarantine.score else "—"],
        ]
        if quarantine.resolved_by:
            q_data.append(["Resolved By", quarantine.resolved_by])
        if quarantine.resolved_at:
            q_data.append(["Resolved At", _fmt_dt(quarantine.resolved_at)])
        q_table = Table(q_data, colWidths=[doc.width * 0.30, doc.width * 0.70])
        q_style = _std_table_style(has_header=True)
        q_style.extend(_alt_row_bg(1, len(q_data) - 1))
        q_table.setStyle(TableStyle(q_style))
        elements.append(q_table)
        elements.append(Spacer(1, 4 * mm))

    # Verification methodology
    elements.append(Paragraph("Verification Methodology", styles["SectionHeader"]))
    elements.append(Paragraph(
        "This document was verified through The Last Bastion's 5-layer automated pipeline:",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 2 * mm))

    methodology = [
        ("Gate 1 — Schema Gatekeeper",
         "Structural validation, type checking, injection pattern detection. Has veto right."),
        ("Gate 2 — Consistency Analyzer",
         "Arithmetic checks, cross-field logic validation, statistical anomaly detection."),
        ("Pillar 1 — Forensic Integrity",
         "7 independent analyzers: ELA, noise, copy-move, lighting, metadata, file structure, PDF forensics."),
        ("Pillar 2 — Logic Triangulation",
         "Cross-reference verification, temporal consistency, domain-specific logic checks. Has veto right."),
        ("Pillar 3 — Attestation",
         "GPS plausibility, depth map analysis, device verification, anti-replay protection."),
        ("Final — Adversarial Challenge",
         "Devil's advocate analysis: contradiction hunting, boundary testing, pattern injection detection."),
    ]
    for name, desc in methodology:
        elements.append(Paragraph(
            f"<b>{name}</b>: {desc}", styles["BodyText2"],
        ))
        elements.append(Spacer(1, 1 * mm))

    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(
        "No human judgment was involved in scoring. "
        "Human oversight is required for blockchain anchoring.",
        styles["SmallGray"],
    ))

    # Build PDF
    doc.build(
        elements,
        onFirstPage=lambda c, d: _header_footer(c, d, proof_hash),
        onLaterPages=lambda c, d: _header_footer(c, d, proof_hash),
    )

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fmt_dt(dt) -> str:
    if not dt:
        return "—"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    return str(dt)


def _extract_score(layer_data, key="score") -> float:
    """Safely extract a score from various layer_scores formats."""
    if isinstance(layer_data, (int, float)):
        return float(layer_data)
    if isinstance(layer_data, dict):
        val = layer_data.get(key, layer_data.get("composite_score", 0))
        if isinstance(val, (int, float)):
            return float(val)
    return 0.0


def _extract_weight(layer_data, default: float = 0.0) -> float:
    if isinstance(layer_data, dict):
        return float(layer_data.get("weight", default))
    return default


def _extract_flag(layer_data, flag: str) -> bool:
    if isinstance(layer_data, dict):
        return bool(layer_data.get(flag, False))
    return False


def _extract_layer_details(details: dict, layer_scores: dict) -> list:
    """Extract per-layer detail rows from the verification details JSON."""
    results = []

    # Try to get layer results from details
    layers = details.get("layer_results", details.get("layers", []))
    if isinstance(layers, list):
        for layer in layers:
            if isinstance(layer, dict):
                name = layer.get("name", layer.get("layer", "Unknown"))
                score = float(layer.get("score", 0))
                passed = layer.get("passed", score >= 0.5)
                findings_list = layer.get("findings", layer.get("warnings", []))
                if isinstance(findings_list, list):
                    findings = "; ".join(str(f) for f in findings_list[:3])
                else:
                    findings = str(findings_list) if findings_list else ""
                results.append({
                    "name": name,
                    "score": score,
                    "status": "PASS" if passed else "FAIL",
                    "findings": findings or "No issues detected",
                })

    # If no structured layers, try to build from layer_scores
    if not results and isinstance(layer_scores, dict):
        layer_names = {
            "schema_gatekeeper": "Schema Gatekeeper",
            "gate_1": "Schema Gatekeeper",
            "consistency_analyzer": "Consistency Analyzer",
            "gate_2": "Consistency Analyzer",
            "forensic_integrity": "Forensic Integrity",
            "pillar_1": "Forensic Integrity",
            "logic_triangulation": "Logic Triangulation",
            "pillar_2": "Logic Triangulation",
            "attestation": "Attestation",
            "pillar_3": "Attestation",
            "adversarial_challenge": "Adversarial Challenge",
            "adversarial": "Adversarial Challenge",
        }
        seen = set()
        for key, display_name in layer_names.items():
            if key in layer_scores and display_name not in seen:
                seen.add(display_name)
                score = _extract_score(layer_scores[key])
                results.append({
                    "name": display_name,
                    "score": score,
                    "status": "PASS" if score >= 0.5 else "FAIL",
                    "findings": "",
                })

    return results


def _collect_warnings(details: dict, layer_scores: dict) -> list:
    """Collect warnings and anomalies from verification details."""
    warnings = []

    def _walk(obj, source=""):
        if isinstance(obj, dict):
            for key in ("warnings", "anomalies", "issues"):
                items = obj.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        level = "anomaly" if key == "anomalies" else "warning"
                        text = str(item) if not isinstance(item, dict) else (
                            item.get("message", item.get("description", str(item)))
                        )
                        warnings.append({
                            "level": level,
                            "source": source or key,
                            "text": text,
                        })
            for k, v in obj.items():
                if k not in ("warnings", "anomalies", "issues"):
                    _walk(v, source=k)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, source=source)

    _walk(details)
    _walk(layer_scores)
    return warnings


def _extract_evidence(details: dict) -> list:
    """Extract evidence chain entries from details."""
    evidence = details.get("evidence", details.get("evidence_chain", []))
    if isinstance(evidence, list):
        result = []
        for ev in evidence:
            if isinstance(ev, dict):
                result.append({
                    "source": ev.get("source", "—"),
                    "field": ev.get("field", ev.get("claim", "—")),
                    "result": ev.get("result", ev.get("confirms", "—")),
                    "confidence": float(ev.get("confidence", 0)),
                })
        return result
    return []
