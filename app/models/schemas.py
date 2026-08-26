"""
Pydantic Request & Response Schemas for PromptShield X.
Includes schemas for:
- Direct Prompt Injection (/analyze)
- RAG Chunk Protection (/analyze-rag)
- Multi-vector File, Web, & Code Protection (/analyze-file, /analyze-web, /analyze-code)
"""

from typing import Literal, Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ==========================================
# 1. Existing Core Schemas (Direct & RAG)
# ==========================================

class AnalyzeRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = None
    retrieved_chunks: Optional[list[str]] = None  # populated for /analyze-rag


class AnalyzeResponse(BaseModel):
    action: Literal["PASS", "REWRITE", "BLOCK"]
    risk_score: int  # 0-100, see config.yaml risk_scoring.thresholds
    category: Literal[
        "safe",
        "prompt_injection",
        "jailbreak",
        "prompt_extraction",
        "agent_manipulation",
    ]
    details: str
    rewritten_prompt: Optional[str] = None


class ChunkRiskResult(BaseModel):
    index: int
    chunk_preview: str
    risk_score: int
    category: Literal[
        "safe",
        "prompt_injection",
        "jailbreak",
        "prompt_extraction",
        "agent_manipulation",
    ]
    action: Literal["PASS", "REWRITE", "BLOCK"]
    pattern_matches: list[str]  # rule ids from pattern_scanner, e.g. ["ignore_instructions_v1"]
    classifier_confidence: float


class AnalyzeRagResponse(BaseModel):
    total_chunks: int
    overall_risk_score: int
    overall_action: Literal["PASS", "REWRITE", "BLOCK"]
    chunks: list[ChunkRiskResult]


# ==========================================
# 2. New Schemas for 5 Multi-Vector Extractors
# ==========================================

class SegmentRiskResult(BaseModel):
    """Evaluation result for an individual extracted element (e.g. PDF page/annotation, Excel cell, DOM node, Docstring)."""
    location: str
    content_preview: str
    source_type: str
    is_hidden: bool
    threat_indicators: List[str]
    risk_score: int
    category: Literal[
        "safe",
        "prompt_injection",
        "jailbreak",
        "prompt_extraction",
        "agent_manipulation",
    ]
    action: Literal["PASS", "REWRITE", "BLOCK"]
    pattern_matches: List[str]
    classifier_confidence: float
    structural_penalty: float = 0.0


class FileAnalyzeResponse(BaseModel):
    """Consolidated report for analyzed files (PDF, Excel, CSV, Image, Web, Code)."""
    filename: str
    source_type: str
    total_segments: int
    hidden_segments_count: int
    overall_risk_score: int
    overall_action: Literal["PASS", "REWRITE", "BLOCK"]
    overall_category: Literal[
        "safe",
        "prompt_injection",
        "jailbreak",
        "prompt_extraction",
        "agent_manipulation",
    ]
    is_safe: bool
    segments: List[SegmentRiskResult]
    sanitized_content: Optional[str] = None
    extraction_warnings: List[str] = Field(default_factory=list)


class WebAnalyzeRequest(BaseModel):
    """Direct URL or raw HTML payload for web scraping injection detection."""
    url: Optional[str] = None
    html_content: Optional[str] = None
    user_id: Optional[str] = None


class CodeAnalyzeRequest(BaseModel):
    """Direct code or docstring payload for repo/docstring injection detection."""
    code: str
    filename: Optional[str] = "snippet.py"
    user_id: Optional[str] = None