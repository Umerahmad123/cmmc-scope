"""
Evidence Reporter — cmmc_scope/reporter.py

Transforms a list of Finding objects into immutable, auditor-ready evidence
packages.  Two output formats are supported:

  1. JSON  — machine-readable, suitable for CI/CD artifact archiving.
  2. PDF   — human-readable report generated with fpdf2, formatted for
             presentation to a C3PAO or internal compliance team.

Both formats embed an SHA-256 integrity hash of the Finding data so that
any post-generation tampering is detectable.

Design invariants:
  - This module writes files; it does not perform I/O against cloud APIs.
  - All PDF layout constants are defined at module level for easy tuning.
  - The JSON schema is versioned so consumers can adapt to future changes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from fpdf import FPDF, XPos, YPos

from cmmc_scope import __version__
from cmmc_scope.engine import ComplianceStatus, Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PDF layout constants
# ---------------------------------------------------------------------------

_PDF_MARGIN_MM = 15
_PDF_PAGE_WIDTH_MM = 210          # A4
_PDF_CONTENT_WIDTH_MM = _PDF_PAGE_WIDTH_MM - 2 * _PDF_MARGIN_MM

# Colour palette (R, G, B)
_COLOR_BLACK = (0, 0, 0)
_COLOR_WHITE = (255, 255, 255)
_COLOR_DARK_NAVY = (15, 32, 65)
_COLOR_LIGHT_GRAY = (240, 240, 242)
_COLOR_MID_GRAY = (120, 120, 128)
_COLOR_PASS_GREEN = (34, 139, 34)
_COLOR_FAIL_RED = (185, 28, 28)
_COLOR_ERROR_AMBER = (202, 138, 4)
_COLOR_ACCENT_BLUE = (37, 99, 210)

_STATUS_COLOR_MAP: dict[ComplianceStatus, tuple[int, int, int]] = {
    ComplianceStatus.PASS: _COLOR_PASS_GREEN,
    ComplianceStatus.FAIL: _COLOR_FAIL_RED,
    ComplianceStatus.ERROR: _COLOR_ERROR_AMBER,
    ComplianceStatus.NOT_APPLICABLE: _COLOR_MID_GRAY,
}


# ---------------------------------------------------------------------------
# Integrity hashing
# ---------------------------------------------------------------------------


def _compute_findings_hash(findings: Sequence[Finding]) -> str:
    """
    Produce a deterministic SHA-256 digest of the serialised findings list.

    The hash is included in both output artefacts so auditors can verify the
    evidence has not been modified after generation.
    """
    serialised = json.dumps(
        [asdict(f) for f in findings],
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(serialised).hexdigest()


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------


def generate_json_report(
    findings: Sequence[Finding],
    output_path: Path,
) -> Path:
    """
    Write an audit evidence package as a JSON file.

    The output is a self-contained object with a schema version, generation
    metadata, an integrity hash, and the full findings array.

    Args:
        findings:    The evaluated Finding objects from engine.py.
        output_path: Destination file path (will be created/overwritten).

    Returns:
        The resolved absolute path of the written file.
    """
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    integrity_hash = _compute_findings_hash(findings)

    summary_counts = {
        "PASS": sum(1 for f in findings if f.status == ComplianceStatus.PASS),
        "FAIL": sum(1 for f in findings if f.status == ComplianceStatus.FAIL),
        "ERROR": sum(1 for f in findings if f.status == ComplianceStatus.ERROR),
        "N/A": sum(1 for f in findings if f.status == ComplianceStatus.NOT_APPLICABLE),
    }

    payload = {
        "schema_version": "1.0",
        "tool": "CMMC-Scope",
        "tool_version": __version__,
        "generated_at_utc": generated_at,
        "integrity_sha256": integrity_hash,
        "summary": summary_counts,
        "findings": [asdict(f) for f in findings],
    }

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    logger.info("JSON evidence report written to: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# PDF reporter — internal helpers
# ---------------------------------------------------------------------------


class _CMMCReportPDF(FPDF):
    """
    Custom FPDF subclass that provides header/footer boilerplate and
    semantic drawing helpers used throughout the report layout.
    """

    def __init__(self, generated_at: str, integrity_hash: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.generated_at = generated_at
        self.integrity_hash = integrity_hash
        self.set_margins(_PDF_MARGIN_MM, _PDF_MARGIN_MM, _PDF_MARGIN_MM)
        self.set_auto_page_break(auto=True, margin=_PDF_MARGIN_MM + 8)

    # ── FPDF hooks ────────────────────────────────────────────────────────────

    def header(self) -> None:
        # Navy top bar
        self.set_fill_color(*_COLOR_DARK_NAVY)
        self.rect(0, 0, 210, 10, style="F")
        self.set_y(12)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*_COLOR_MID_GRAY)
        page_label = f"Page {self.page_no()} | Generated: {self.generated_at}"
        self.cell(0, 5, page_label, align="L")
        hash_label = f"SHA-256: {self.integrity_hash[:32]}…"
        self.cell(0, 5, hash_label, align="R")

    # ── Semantic helpers ──────────────────────────────────────────────────────

    def draw_cover_page(self, summary_counts: dict[str, int]) -> None:
        """Render the cover / title page."""
        self.add_page()

        # Hero bar
        self.set_fill_color(*_COLOR_DARK_NAVY)
        self.rect(0, 0, 210, 70, style="F")

        self.set_xy(_PDF_MARGIN_MM, 22)
        self.set_font("Helvetica", "B", 26)
        self.set_text_color(*_COLOR_WHITE)
        self.cell(0, 10, "CMMC-Scope", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font("Helvetica", "", 13)
        self.set_text_color(180, 200, 230)
        self.cell(
            0,
            7,
            "Automated CMMC Level 2 / NIST SP 800-171 Compliance Audit Report",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )

        self.set_y(80)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*_COLOR_BLACK)

        meta_lines = [
            ("Report generated (UTC)", self.generated_at),
            ("Tool version", __version__),
            ("Integrity (SHA-256)", self.integrity_hash),
        ]
        for label, value in meta_lines:
            self.set_font("Helvetica", "B", 9)
            self.cell(55, 6, label + ":", new_x=XPos.RIGHT)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*_COLOR_MID_GRAY)
            self.cell(0, 6, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(*_COLOR_BLACK)

        # Summary scorecard
        self.ln(10)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*_COLOR_DARK_NAVY)
        self.cell(0, 7, "AUDIT SUMMARY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_draw_color(*_COLOR_DARK_NAVY)
        self.set_line_width(0.4)
        self.line(_PDF_MARGIN_MM, self.get_y(), 210 - _PDF_MARGIN_MM, self.get_y())
        self.ln(4)

        box_w = 38
        box_h = 18
        labels_colors = [
            ("PASS", _COLOR_PASS_GREEN),
            ("FAIL", _COLOR_FAIL_RED),
            ("ERROR", _COLOR_ERROR_AMBER),
            ("N/A", _COLOR_MID_GRAY),
        ]
        start_x = _PDF_MARGIN_MM

        for key, color in labels_colors:
            count = summary_counts.get(key, 0)
            self.set_fill_color(*color)
            self.set_text_color(*_COLOR_WHITE)
            self.set_xy(start_x, self.get_y())
            self.set_font("Helvetica", "B", 18)
            self.cell(box_w, box_h, str(count), align="C", fill=True,
                      new_x=XPos.RIGHT)
            start_x += box_w + 4

        self.ln(box_h + 1)
        start_x = _PDF_MARGIN_MM
        self.set_text_color(*_COLOR_MID_GRAY)
        self.set_font("Helvetica", "", 8)

        for key, _ in labels_colors:
            self.set_x(start_x)
            self.cell(box_w, 5, key, align="C", new_x=XPos.RIGHT)
            start_x += box_w + 4

        self.set_text_color(*_COLOR_BLACK)

    def draw_finding_section(self, finding: Finding, index: int) -> None:
        """Render a single finding block onto the current/next page."""
        self.ln(6)

        # Section header
        status_color = _STATUS_COLOR_MAP.get(finding.status, _COLOR_BLACK)
        self.set_fill_color(*_COLOR_LIGHT_GRAY)
        self.rect(_PDF_MARGIN_MM, self.get_y(), _PDF_CONTENT_WIDTH_MM, 8, style="F")

        self.set_xy(_PDF_MARGIN_MM + 2, self.get_y() + 1)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*_COLOR_DARK_NAVY)
        id_label = f"[{index}]  {finding.cmmc_practice_id}  —  {finding.control_title}"
        self.cell(_PDF_CONTENT_WIDTH_MM - 25, 6, id_label, new_x=XPos.RIGHT)

        # Status badge
        self.set_fill_color(*status_color)
        self.set_text_color(*_COLOR_WHITE)
        self.set_font("Helvetica", "B", 8)
        self.cell(22, 6, finding.status.value, align="C", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(*_COLOR_BLACK)

        # Metadata row
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*_COLOR_MID_GRAY)
        self.set_x(_PDF_MARGIN_MM)
        self.cell(
            0,
            5,
            f"NIST 800-171: §{finding.nist_control_id}  |  "
            f"Family: {finding.control_family}  |  "
            f"Scope: {finding.resource_scope}  |  "
            f"Evaluated: {finding.evaluated_at}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.set_text_color(*_COLOR_BLACK)
        self.ln(1)

        # Summary
        self.set_font("Helvetica", "B", 9)
        self.set_x(_PDF_MARGIN_MM)
        self.cell(0, 5, "Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "", 9)
        self.set_x(_PDF_MARGIN_MM)
        self.multi_cell(_PDF_CONTENT_WIDTH_MM, 5, finding.summary)
        self.ln(2)

        # Evidence
        if finding.evidence:
            self.set_font("Helvetica", "B", 9)
            self.set_x(_PDF_MARGIN_MM)
            self.cell(0, 5, "Evidence", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("Courier", "", 7.5)
            self.set_fill_color(248, 248, 252)
            for line in finding.evidence:
                self.set_x(_PDF_MARGIN_MM + 2)
                self.multi_cell(
                    _PDF_CONTENT_WIDTH_MM - 2, 4.5, line, fill=True
                )
            self.ln(1)

        # Remediation
        if finding.remediation_items:
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*_COLOR_FAIL_RED)
            self.set_x(_PDF_MARGIN_MM)
            self.cell(0, 5, "Required Remediation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(*_COLOR_BLACK)
            self.set_font("Helvetica", "", 9)
            for i, item in enumerate(finding.remediation_items, start=1):
                self.set_x(_PDF_MARGIN_MM + 2)
                self.multi_cell(_PDF_CONTENT_WIDTH_MM - 2, 5, f"{i}. {item}")

        # Divider
        self.ln(2)
        self.set_draw_color(*_COLOR_LIGHT_GRAY)
        self.set_line_width(0.3)
        self.line(_PDF_MARGIN_MM, self.get_y(), 210 - _PDF_MARGIN_MM, self.get_y())


# ---------------------------------------------------------------------------
# PDF reporter — public API
# ---------------------------------------------------------------------------


def generate_pdf_report(
    findings: Sequence[Finding],
    output_path: Path,
) -> Path:
    """
    Write an audit evidence package as a formatted PDF document.

    The report includes a cover page with a summary scorecard, followed by
    one section per Finding containing evidence, status, and remediation
    guidance.

    Args:
        findings:    The evaluated Finding objects from engine.py.
        output_path: Destination file path (will be created/overwritten).

    Returns:
        The resolved absolute path of the written file.
    """
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    integrity_hash = _compute_findings_hash(findings)

    summary_counts = {
        "PASS": sum(1 for f in findings if f.status == ComplianceStatus.PASS),
        "FAIL": sum(1 for f in findings if f.status == ComplianceStatus.FAIL),
        "ERROR": sum(1 for f in findings if f.status == ComplianceStatus.ERROR),
        "N/A": sum(1 for f in findings if f.status == ComplianceStatus.NOT_APPLICABLE),
    }

    pdf = _CMMCReportPDF(generated_at=generated_at, integrity_hash=integrity_hash)
    pdf.draw_cover_page(summary_counts)

    # Findings pages
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*_COLOR_DARK_NAVY)
    pdf.set_y(14)
    pdf.cell(0, 8, "DETAILED FINDINGS", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*_COLOR_DARK_NAVY)
    pdf.set_line_width(0.5)
    pdf.line(_PDF_MARGIN_MM, pdf.get_y(), 210 - _PDF_MARGIN_MM, pdf.get_y())

    for idx, finding in enumerate(findings, start=1):
        pdf.draw_finding_section(finding, idx)

    pdf.output(str(output_path))
    logger.info("PDF evidence report written to: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------


def generate_all_reports(
    findings: Sequence[Finding],
    output_dir: Path,
    base_filename: str = "cmmc_scope_evidence",
) -> dict[str, Path]:
    """
    Generate both JSON and PDF evidence reports in a single call.

    Args:
        findings:      Evaluated Finding objects.
        output_dir:    Directory where both files will be written.
        base_filename: Stem for both output files (extensions appended).

    Returns:
        A dict mapping ``"json"`` and ``"pdf"`` to their written Paths.
    """
    output_dir = Path(output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{base_filename}_{timestamp}"

    return {
        "json": generate_json_report(findings, output_dir / f"{stem}.json"),
        "pdf": generate_pdf_report(findings, output_dir / f"{stem}.pdf"),
    }
