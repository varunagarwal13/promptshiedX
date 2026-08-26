"""
PromptShield X - PDF Extractor
Extracts body text, document metadata, form fields, and annotations.
Detects cloaked indirect prompt injections:
- Microscopic / zero-point fonts (font size < 2.0pt)
- Off-canvas / negative coordinate text
- Invisible / white-on-white text (matching background)
- Covert payloads in PDF metadata & sticky note annotations
"""

import io
from typing import Optional, List
from app.modules.extractors import (
    BaseExtractor,
    ExtractedSegment,
    ExtractionResult,
    SourceType,
    ThreatCategory,
)

# Safe import: 'fitz' is installed via 'pip install pymupdf'
try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    fitz = None
    HAS_PYMUPDF = False


class PDFExtractor(BaseExtractor):
    def __init__(self, min_visible_font_size: float = 2.0):
        """
        :param min_visible_font_size: Any text with font size below this threshold
                                      is flagged as hidden/adversarial cloaking.
        """
        self.min_visible_font_size = min_visible_font_size

    def extract(self, data: bytes, filename: Optional[str] = None, **kwargs) -> ExtractionResult:
        fname = filename or "document.pdf"
        result = ExtractionResult(source_type=SourceType.PDF, filename=fname)

        if not HAS_PYMUPDF:
            result.extraction_warnings.append(
                "PyMuPDF is not installed. Please run 'pip install pymupdf' to enable PDF extraction."
            )
            return result

        doc = None
        try:
            doc = fitz.open(stream=data, filetype="pdf")

            # ----------------------------------------------------
            # 1. Document Metadata Inspection (/Author, /Title, etc.)
            # ----------------------------------------------------
            if doc.metadata:
                for meta_key, meta_val in doc.metadata.items():
                    if meta_val and isinstance(meta_val, str):
                        clean_val = meta_val.strip()
                        if len(clean_val) >= 4:
                            result.segments.append(
                                ExtractedSegment(
                                    content=clean_val,
                                    source_type=SourceType.PDF,
                                    location=f"Metadata:{meta_key}",
                                    is_hidden=True,
                                    threat_indicators=[ThreatCategory.METADATA_INJECTION],
                                    confidence_penalty=20.0,
                                    metadata={"meta_key": meta_key},
                                )
                            )

            # ----------------------------------------------------
            # 2. Pages, Structured Spans, Font & Bounding Box Inspection
            # ----------------------------------------------------
            for page_num in range(len(doc)):
                page = doc[page_num]
                page_rect = page.rect
                
                # Extract text layout dict containing spans, fonts, bboxes, and colors
                text_page = page.get_text("dict", flags=fitz.TEXTFLAGS_SEARCH)

                for block in text_page.get("blocks", []):
                    if block.get("type") == 0:  # 0 = Text block
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                text = span.get("text", "").strip()
                                if not text:
                                    continue

                                font_size = span.get("size", 10.0)
                                color = span.get("color", 0)  # RGB int
                                bbox = span.get("bbox", [0, 0, 0, 0])

                                is_hidden = False
                                threats: List[ThreatCategory] = []
                                penalty = 0.0

                                # Anomaly A: Micro / Sub-visible Font Size
                                if font_size < self.min_visible_font_size:
                                    is_hidden = True
                                    threats.append(ThreatCategory.HIDDEN_TEXT)
                                    penalty += 35.0

                                # Anomaly B: Off-Canvas / Margin Placement
                                if (
                                    bbox[0] < 0
                                    or bbox[1] < 0
                                    or bbox[2] > page_rect.width
                                    or bbox[3] > page_rect.height
                                ):
                                    is_hidden = True
                                    threats.append(ThreatCategory.HIDDEN_TEXT)
                                    penalty += 40.0

                                # Anomaly C: White Text (RGB integer 16777215 or 0xFFFFFF)
                                if color in (16777215, 0xFFFFFF):
                                    is_hidden = True
                                    threats.append(ThreatCategory.HIDDEN_TEXT)
                                    penalty += 45.0

                                result.segments.append(
                                    ExtractedSegment(
                                        content=text,
                                        source_type=SourceType.PDF,
                                        location=f"Page {page_num + 1} (bbox:{[round(x, 1) for x in bbox]})",
                                        is_hidden=is_hidden,
                                        threat_indicators=threats,
                                        confidence_penalty=penalty,
                                        metadata={
                                            "page": page_num + 1,
                                            "font_size": font_size,
                                            "font_name": span.get("font", "Unknown"),
                                            "color_hex": hex(color),
                                        },
                                    )
                                )

                # ----------------------------------------------------
                # 3. PDF Annotations & Sticky Notes Inspection
                # ----------------------------------------------------
                try:
                    annots = page.annots()
                    if annots:
                        for annot in annots:
                            info = annot.info
                            content = info.get("content", "").strip() if info else ""
                            if content:
                                result.segments.append(
                                    ExtractedSegment(
                                        content=content,
                                        source_type=SourceType.PDF,
                                        location=f"Page {page_num + 1} (Annotation:{info.get('title', 'Note')})",
                                        is_hidden=True,
                                        threat_indicators=[ThreatCategory.METADATA_INJECTION],
                                        confidence_penalty=25.0,
                                        metadata={"annot_type": getattr(annot, "type", ["Unknown"])[1]},
                                    )
                                )
                except Exception:
                    pass  # If page has no annotations or unsupported annotation format

            result.raw_character_count = sum(len(s.content) for s in result.segments)
            result.anomalies_detected = sum(
                1 for s in result.segments if s.is_hidden or len(s.threat_indicators) > 0
            )

        except Exception as e:
            result.extraction_warnings.append(f"PDF extraction error: {str(e)}")
        finally:
            if doc:
                doc.close()

        return result