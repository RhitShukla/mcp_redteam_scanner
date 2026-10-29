"""
Markdown to DOCX Converter

Converts any .md file into a formatted .docx with:
  - Headings (H1-H6)
  - Bold, italic, inline code, strikethrough
  - Tables with styled headers and alternating rows
  - Fenced code blocks with monospace font and gray background
  - Bullet and numbered lists (nested)
  - Horizontal rules as page breaks
  - Block quotes

Usage:
    python md_to_docx.py report.md                     # → report.docx
    python md_to_docx.py report.md -o output/final.docx
    python md_to_docx.py report.md --title "My Report"
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import mistune
from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from lxml import etree


# ── DOCX Styling Helpers ──

SEVERITY_KEYWORDS = {
    "CRITICAL": RGBColor(0xCC, 0x00, 0x00),
    "HIGH": RGBColor(0xE0, 0x4F, 0x00),
    "MEDIUM": RGBColor(0xE8, 0x9C, 0x00),
    "LOW": RGBColor(0x33, 0x70, 0xCC),
    "PASS": RGBColor(0x22, 0x8B, 0x22),
}


def _set_cell_shading(cell, hex_color: str):
    tc_pr = cell._element.get_or_add_tcPr()
    sh = etree.SubElement(tc_pr, qn("w:shd"))
    sh.set(qn("w:fill"), hex_color)
    sh.set(qn("w:val"), "clear")


def _set_para_shading(para, hex_color: str):
    p_pr = para._element.get_or_add_pPr()
    sh = etree.SubElement(p_pr, qn("w:shd"))
    sh.set(qn("w:fill"), hex_color)
    sh.set(qn("w:val"), "clear")


# ── Markdown AST → DOCX Renderer ──

class DocxRenderer:
    """Walks mistune AST tokens and builds a python-docx Document."""

    def __init__(self, doc: Document, title: str | None = None):
        self.doc = doc
        self.title = title
        self._setup_styles()
        self._current_paragraph = None
        self._list_depth = 0
        self._list_counters: list[int] = []

    def _setup_styles(self):
        style = self.doc.styles["Normal"]
        style.font.name = "Calibri"
        style.font.size = Pt(10.5)
        style.paragraph_format.space_after = Pt(4)
        for lv in range(1, 7):
            try:
                h = self.doc.styles[f"Heading {lv}"]
                h.font.name = "Calibri"
                h.font.color.rgb = RGBColor(0x1B, 0x2A, 0x4A)
            except KeyError:
                pass
        for section in self.doc.sections:
            section.top_margin = Cm(2)
            section.bottom_margin = Cm(2)
            section.left_margin = Cm(2.5)
            section.right_margin = Cm(2.5)

    def render(self, tokens: list[dict]):
        for tok in tokens:
            self._render_token(tok)

    def _render_token(self, tok: dict):
        tp = tok.get("type", "")
        handler = getattr(self, f"_tok_{tp}", None)
        if handler:
            handler(tok)

    # ── Block-level tokens ──

    def _tok_heading(self, tok: dict):
        level = tok.get("attrs", {}).get("level", 1)
        text = self._extract_text(tok.get("children", []))
        self.doc.add_heading(text, level=min(level, 6))

    def _tok_paragraph(self, tok: dict):
        p = self.doc.add_paragraph()
        self._current_paragraph = p
        self._render_inline(tok.get("children", []), p)

    def _tok_code_block(self, tok: dict):
        raw = tok.get("raw", tok.get("text", ""))
        p = self.doc.add_paragraph()
        run = p.add_run(raw.rstrip("\n"))
        run.font.name = "Consolas"
        run.font.size = Pt(8.5)
        run.font.color.rgb = RGBColor(0x2D, 0x2D, 0x2D)
        _set_para_shading(p, "F5F5F5")
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(4)

    def _tok_thematic_break(self, tok: dict):
        self.doc.add_page_break()

    def _tok_table(self, tok: dict):
        head_children = []
        body_children = []
        for child in tok.get("children", []):
            if child.get("type") == "table_head":
                head_children = child.get("children", [])
            elif child.get("type") == "table_body":
                body_children = child.get("children", [])

        # Extract header texts
        headers: list[str] = []
        if head_children:
            row_tok = head_children[0] if head_children else {}
            for cell_tok in row_tok.get("children", []):
                headers.append(self._extract_text(cell_tok.get("children", [])))

        # Extract body rows
        rows: list[list[str]] = []
        for row_tok in body_children:
            row: list[str] = []
            for cell_tok in row_tok.get("children", []):
                row.append(self._extract_text(cell_tok.get("children", [])))
            rows.append(row)

        if not headers:
            return

        ncols = len(headers)
        table = self.doc.add_table(rows=1 + len(rows), cols=ncols)
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        # Header row
        for i, h in enumerate(headers):
            cell = table.rows[0].cells[i]
            cell.text = ""
            run = cell.paragraphs[0].add_run(h)
            run.bold = True
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            _set_cell_shading(cell, "1B2A4A")

        # Data rows
        for ri, row_data in enumerate(rows):
            for ci in range(ncols):
                val = row_data[ci] if ci < len(row_data) else ""
                cell = table.rows[ri + 1].cells[ci]
                cell.text = ""
                run = cell.paragraphs[0].add_run(val)
                run.font.size = Pt(9)
                # Color severity keywords
                upper = val.strip().upper()
                if upper in SEVERITY_KEYWORDS:
                    run.bold = True
                    run.font.color.rgb = SEVERITY_KEYWORDS[upper]
                # Alternating row shading
                if ri % 2 == 1:
                    _set_cell_shading(cell, "F2F6FC")

    def _tok_block_quote(self, tok: dict):
        for child in tok.get("children", []):
            if child.get("type") == "paragraph":
                p = self.doc.add_paragraph(style="Quote")
                self._render_inline(child.get("children", []), p)
            else:
                self._render_token(child)

    def _tok_list(self, tok: dict):
        ordered = tok.get("attrs", {}).get("ordered", False)
        self._list_depth += 1
        if ordered:
            self._list_counters.append(0)
        for child in tok.get("children", []):
            if child.get("type") == "list_item":
                self._tok_list_item(child, ordered)
        if ordered:
            self._list_counters.pop()
        self._list_depth -= 1

    def _tok_list_item(self, tok: dict, ordered: bool):
        children = tok.get("children", [])
        for child in children:
            if child.get("type") == "paragraph":
                indent = "  " * (self._list_depth - 1)
                if ordered:
                    self._list_counters[-1] += 1
                    prefix = f"{indent}{self._list_counters[-1]}. "
                else:
                    bullets = ["-", "-", "-"]
                    marker = bullets[min(self._list_depth - 1, 2)]
                    prefix = f"{indent}{marker} "
                text = self._extract_text(child.get("children", []))
                p = self.doc.add_paragraph()
                p.paragraph_format.left_indent = Cm(1.0 * self._list_depth)
                # Add prefix as bold
                run_prefix = p.add_run(prefix)
                run_prefix.font.size = Pt(10.5)
                # Render inline content
                self._render_inline(child.get("children", []), p)
            elif child.get("type") == "list":
                self._tok_list(child)

    def _tok_blank_line(self, tok: dict):
        pass  # skip

    # ── Inline rendering ──

    def _render_inline(self, children: list[dict], paragraph):
        for child in children:
            tp = child.get("type", "")
            if tp == "text":
                raw = child.get("raw", child.get("text", ""))
                paragraph.add_run(raw)
            elif tp == "codespan":
                raw = child.get("raw", child.get("text", ""))
                run = paragraph.add_run(raw)
                run.font.name = "Consolas"
                run.font.size = Pt(9)
                run.font.color.rgb = RGBColor(0x88, 0x00, 0x88)
            elif tp == "strong":
                text = self._extract_text(child.get("children", []))
                run = paragraph.add_run(text)
                run.bold = True
                # Color severity keywords in bold
                upper = text.strip().upper().rstrip(":")
                if upper in SEVERITY_KEYWORDS:
                    run.font.color.rgb = SEVERITY_KEYWORDS[upper]
            elif tp == "emphasis":
                text = self._extract_text(child.get("children", []))
                run = paragraph.add_run(text)
                run.italic = True
            elif tp == "strikethrough":
                text = self._extract_text(child.get("children", []))
                run = paragraph.add_run(text)
                run.font.strike = True
            elif tp == "link":
                text = self._extract_text(child.get("children", []))
                url = child.get("attrs", {}).get("url", "")
                run = paragraph.add_run(text)
                run.font.color.rgb = RGBColor(0x05, 0x63, 0xC1)
                run.font.underline = True
            elif tp == "softbreak":
                paragraph.add_run("\n")
            elif tp == "linebreak":
                paragraph.add_run("\n")
            else:
                # Fallback: extract any text content
                raw = child.get("raw", child.get("text", ""))
                if raw:
                    paragraph.add_run(raw)
                elif child.get("children"):
                    self._render_inline(child.get("children", []), paragraph)

    def _extract_text(self, children: list[dict]) -> str:
        """Recursively extract plain text from inline tokens."""
        parts: list[str] = []
        for child in children:
            tp = child.get("type", "")
            if tp == "text":
                parts.append(child.get("raw", child.get("text", "")))
            elif tp == "codespan":
                parts.append(child.get("raw", child.get("text", "")))
            elif tp in ("strong", "emphasis", "strikethrough", "link"):
                parts.append(self._extract_text(child.get("children", [])))
            elif tp == "softbreak":
                parts.append(" ")
            else:
                raw = child.get("raw", child.get("text", ""))
                if raw:
                    parts.append(raw)
                elif child.get("children"):
                    parts.append(self._extract_text(child.get("children", [])))
        return "".join(parts)


# ── Main Conversion ──

def convert(md_path: str, docx_path: str, title: str | None = None):
    """Convert a markdown file to DOCX."""
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Parse markdown to AST
    md = mistune.create_markdown(renderer=None)
    tokens = md(md_text)

    # Build DOCX
    doc = Document()
    renderer = DocxRenderer(doc, title=title)
    renderer.render(tokens)

    doc.save(docx_path)
    print(f"Converted: {md_path} -> {docx_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert a Markdown file to a formatted DOCX document.",
        epilog="Examples:\n"
        "  python md_to_docx.py report.md\n"
        "  python md_to_docx.py report.md -o output/report.docx\n"
        "  python md_to_docx.py report.md --title 'Security Report'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="Input markdown file (.md)")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output DOCX path (default: same name with .docx extension)",
    )
    parser.add_argument(
        "--title", default=None,
        help="Document title (default: extracted from first H1)",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: file not found: {args.input}")
        sys.exit(1)

    if not args.input.endswith(".md"):
        print(f"Warning: input file does not have .md extension: {args.input}")

    output = args.output or args.input.rsplit(".", 1)[0] + ".docx"

    # Ensure output directory exists
    out_dir = os.path.dirname(output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    convert(args.input, output, title=args.title)


if __name__ == "__main__":
    main()
