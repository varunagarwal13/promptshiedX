"""
PromptShield X - Extractor Package
Unified abstractions and data structures for multi-vector indirect prompt injection defense.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SourceType(str, Enum):
    PDF = "pdf"
    SPREADSHEET = "spreadsheet"
    IMAGE = "image"
    WEB = "web"
    CODE = "code"
    DOCUMENTATION = "documentation"


class ThreatCategory(str, Enum):
    HIDDEN_TEXT = "hidden_text"
    METADATA_INJECTION = "metadata_injection"
    FORMULA_INJECTION = "formula_injection"
    VISUAL_PROMPT_INJECTION = "visual_prompt_injection"
    DOM_CLOAKING = "dom_cloaking"
    TROJAN_SOURCE_UNICODE = "trojan_source_unicode"
    COMMENT_HIJACK = "comment_hijack"
    ZERO_WIDTH_OBSCURITY = "zero_width_obscurity"
    DIRECT_INJECTION = "direct_injection"


@dataclass
class ExtractedSegment:
    """Represents an atomic text segment extracted from any document or artifact."""
    content: str
    source_type: SourceType
    location: str  # e.g. "Page 3", "Sheet1!B14", "EXIF:UserComment", "DOM:div.hidden-prompt", "main.py:L42"
    is_hidden: bool = False
    threat_indicators: List[ThreatCategory] = field(default_factory=list)
    confidence_penalty: float = 0.0  # Boosts risk score if extractor finds structural anomalies
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "source_type": self.source_type.value,
            "location": self.location,
            "is_hidden": self.is_hidden,
            "threat_indicators": [t.value for t in self.threat_indicators],
            "confidence_penalty": self.confidence_penalty,
            "metadata": self.metadata,
        }


@dataclass
class ExtractionResult:
    """Consolidated result returned by any extractor."""
    source_type: SourceType
    filename: Optional[str]
    segments: List[ExtractedSegment] = field(default_factory=list)
    raw_character_count: int = 0
    anomalies_detected: int = 0
    extraction_warnings: List[str] = field(default_factory=list)


class BaseExtractor(ABC):
    """Abstract base class for all PromptShield X data extractors."""

    @abstractmethod
    def extract(self, data: bytes, filename: Optional[str] = None, **kwargs) -> ExtractionResult:
        """Extract content into structured segments and identify structural cloaking."""
        pass