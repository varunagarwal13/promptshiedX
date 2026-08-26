"""
API routes for PromptShield X.

Pipeline:
1. Pre-Retrieval Extractor & Sanitizer (Features 1-5: PDF, Excel/CSV, Image, Web, Code)
2. Pattern Scanner (6.2)
3. Semantic Classifier (6.3)
4. Risk Engine (6.9)
5. Action Engine (6.10)
6. Audit Logging (6.12)
"""

import os
import sqlite3
from typing import Optional, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse

from app.models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeRagResponse,
    ChunkRiskResult,
    SegmentRiskResult,
    FileAnalyzeResponse,
    WebAnalyzeRequest,
    CodeAnalyzeRequest,
)

# Core PromptShield X Pipeline Imports
from app.modules.sanitizer import sanitize
from app.modules.pattern_scanner import scan_prompt
from app.modules.semantic_classifier import classify_prompt
from app.core.risk_engine import compute_risk_score
from app.core.action_engine import apply_action
from app.core.init_db import log_audit, DB_PATH

# 5 Multi-Vector Extractor Modules
from app.modules.extractors.pdf_extractor import PDFExtractor
from app.modules.extractors.spreadsheet_extractor import SpreadsheetExtractor
from app.modules.extractors.image_extractor import ImageExtractor
from app.modules.extractors.web_extractor import WebExtractor
from app.modules.extractors.code_extractor import CodeExtractor
from app.modules.extractors import ExtractedSegment, ExtractionResult, SourceType

router = APIRouter()

# Instantiate Extractors once
pdf_extractor = PDFExtractor()
spreadsheet_extractor = SpreadsheetExtractor()
image_extractor = ImageExtractor()
web_extractor = WebExtractor()
code_extractor = CodeExtractor()


# ==========================================
# Shared Pipeline Helper
# ==========================================

def _evaluate_single_segment(seg: ExtractedSegment) -> tuple[SegmentRiskResult, Optional[str]]:
    """
    Runs the standard PromptShield X pipeline on an extracted segment:
    Sanitizer -> Pattern Scanner -> Semantic Classifier -> Risk Engine (+ Structural Penalty) -> Action Engine
    """
    clean_text = sanitize(seg.content)
    
    # 1. Pattern Scanner
    pattern_result = scan_prompt(clean_text)
    
    # 2. Semantic Classifier
    classification = classify_prompt(clean_text)
    
    # 3. Base Risk Engine
    scored = compute_risk_score(pattern_result["severity"], classification)
    
    # 4. Integrate Extractor Structural Penalty (e.g. hidden white text, cloaked DOM, Trojan unicode)
    raw_risk = scored["risk_score"] + int(seg.confidence_penalty)
    final_risk_score = min(100, max(0, raw_risk))
    
    # Re-evaluate action if structural penalty escalated the risk category
    if final_risk_score >= 66:
        final_action = "BLOCK"
    elif final_risk_score >= 31:
        final_action = "REWRITE"
    else:
        final_action = scored["action"]
    
    # 5. Action Engine (Rewriting / Filtering)
    outcome = apply_action(final_action, clean_text, pattern_result["matches"])
    
    sanitized_piece = None
    if final_action == "PASS":
        sanitized_piece = seg.content
    elif final_action == "REWRITE":
        sanitized_piece = outcome["prompt"]
    # If BLOCK, sanitized_piece remains None (excluded from clean output)

    preview = (seg.content[:120] + "...") if len(seg.content) > 120 else seg.content

    result_model = SegmentRiskResult(
        location=seg.location,
        content_preview=preview,
        source_type=seg.source_type.value,
        is_hidden=seg.is_hidden,
        threat_indicators=[t.value for t in seg.threat_indicators],
        risk_score=final_risk_score,
        category=scored["category"],
        action=final_action,
        pattern_matches=[m["id"] for m in pattern_result["matches"]],
        classifier_confidence=classification["confidence"],
        structural_penalty=seg.confidence_penalty,
    )
    
    return result_model, sanitized_piece


# ==========================================
# 1. Existing Endpoints (Unchanged)
# ==========================================

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_prompt(payload: AnalyzeRequest):
    clean_prompt = sanitize(payload.prompt)

    pattern_result = scan_prompt(clean_prompt)
    classification = classify_prompt(clean_prompt)
    scored = compute_risk_score(pattern_result["severity"], classification)

    outcome = apply_action(scored["action"], clean_prompt, pattern_result["matches"])

    details = (
        f"pattern_matches={[m['id'] for m in pattern_result['matches']]}, "
        f"classifier_confidence={classification['confidence']}, "
        f"removed_fragments={outcome['removed_fragments']}"
    )

    try:
        log_audit(
            user_id=payload.user_id,
            prompt=payload.prompt,
            risk_score=scored["risk_score"],
            attack_category=scored["category"],
            action_taken=scored["action"],
            detection_evidence=details,
        )
    except Exception as e:
        print(f"Failed to log audit entry: {e}")

    return AnalyzeResponse(
        action=scored["action"],
        risk_score=scored["risk_score"],
        category=scored["category"],
        details=details,
        rewritten_prompt=outcome["prompt"] if scored["action"] == "REWRITE" else None,
    )


@router.post("/analyze-rag", response_model=AnalyzeRagResponse)
def analyze_rag_context(payload: AnalyzeRequest):
    chunks = payload.retrieved_chunks or []
    chunk_results: list[ChunkRiskResult] = []
    
    for i, chunk in enumerate(chunks):
        clean_chunk = sanitize(chunk)

        pattern_result = scan_prompt(clean_chunk)
        classification = classify_prompt(clean_chunk)
        scored = compute_risk_score(pattern_result["severity"], classification)

        chunk_results.append(
            ChunkRiskResult(
                index=i,
                chunk_preview=(clean_chunk[:120] + "...") if len(clean_chunk) > 120 else clean_chunk,
                risk_score=scored["risk_score"],
                category=scored["category"],
                action=scored["action"],
                pattern_matches=[m["id"] for m in pattern_result["matches"]],
                classifier_confidence=classification["confidence"],
            )
        )

    if chunk_results:
        riskiest = max(chunk_results, key=lambda c: c.risk_score)
        overall_risk_score = riskiest.risk_score
        overall_action = riskiest.action
    else:
        overall_risk_score = 0
        overall_action = "PASS"

    return AnalyzeRagResponse(
        total_chunks=len(chunk_results),
        overall_risk_score=overall_risk_score,
        overall_action=overall_action,
        chunks=chunk_results,
    )


# ==========================================
# 2. New Multi-Vector File & Artifact Endpoints
# ==========================================

@router.post("/analyze-file", response_model=FileAnalyzeResponse)
async def analyze_file(
    file: UploadFile = File(...),
    user_id: Optional[str] = Form(None)
):
    """
    Scans uploaded PDF, Excel/CSV, Image, HTML, or Source Code files.
    Extracts structured segments, detects hidden cloaking, and evaluates through the firewall.
    """
    filename = file.filename or "uploaded_file"
    data = await file.read()
    fname_lower = filename.lower()

    # Select appropriate extractor
    if fname_lower.endswith(".pdf"):
        extract_result = pdf_extractor.extract(data, filename=filename)
    elif fname_lower.endswith((".xlsx", ".xls", ".csv")):
        extract_result = spreadsheet_extractor.extract(data, filename=filename)
    elif fname_lower.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
        extract_result = image_extractor.extract(data, filename=filename)
    elif fname_lower.endswith((".html", ".htm", ".xhtml")):
        extract_result = web_extractor.extract(data, filename=filename)
    elif fname_lower.endswith((".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs", ".md", ".txt")):
        extract_result = code_extractor.extract(data, filename=filename)
    else:
        # Fallback to general code/text extractor
        extract_result = code_extractor.extract(data, filename=filename)

    # Process all segments through the firewall
    segment_evals: List[SegmentRiskResult] = []
    sanitized_chunks: List[str] = []

    for seg in extract_result.segments:
        seg_eval, sanitized_piece = _evaluate_single_segment(seg)
        segment_evals.append(seg_eval)
        if sanitized_piece:
            sanitized_chunks.append(sanitized_piece)

    # Aggregate file-level decision ("Riskiest Segment Wins" with Structural Defense)
    if segment_evals:
        riskiest_segment = max(segment_evals, key=lambda s: s.risk_score)
        overall_risk_score = riskiest_segment.risk_score
        overall_action = riskiest_segment.action
        overall_category = riskiest_segment.category
    else:
        overall_risk_score = 0
        overall_action = "PASS"
        overall_category = "safe"

    # Audit Logging
    try:
        log_audit(
            user_id=user_id,
            prompt=f"File: {filename} ({extract_result.source_type.value})",
            risk_score=overall_risk_score,
            attack_category=overall_category,
            action_taken=overall_action,
            detection_evidence=f"Total segments: {len(segment_evals)}, Anomalies: {extract_result.anomalies_detected}",
        )
    except Exception as e:
        print(f"Failed to log audit entry: {e}")

    return FileAnalyzeResponse(
        filename=filename,
        source_type=extract_result.source_type.value,
        total_segments=len(segment_evals),
        hidden_segments_count=sum(1 for s in segment_evals if s.is_hidden),
        overall_risk_score=overall_risk_score,
        overall_action=overall_action,
        overall_category=overall_category,
        is_safe=(overall_action == "PASS"),
        segments=segment_evals,
        sanitized_content="\n\n".join(sanitized_chunks) if overall_action != "BLOCK" else None,
        extraction_warnings=extract_result.extraction_warnings,
    )


@router.post("/analyze-web", response_model=FileAnalyzeResponse)
def analyze_web_content(payload: WebAnalyzeRequest):
    """Analyzes raw HTML or scraped web content for DOM-cloaked prompt injections."""
    raw_html = payload.html_content or ""
    if payload.url and not raw_html:
        import urllib.request
        try:
            req = urllib.request.Request(payload.url, headers={"User-Agent": "PromptShieldX-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                raw_html = response.read().decode("utf-8", errors="replace")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {str(e)}")

    extract_result = web_extractor.extract(raw_html.encode("utf-8"), filename=payload.url or "webpage.html")
    
    segment_evals: List[SegmentRiskResult] = []
    sanitized_chunks: List[str] = []

    for seg in extract_result.segments:
        seg_eval, sanitized_piece = _evaluate_single_segment(seg)
        segment_evals.append(seg_eval)
        if sanitized_piece:
            sanitized_chunks.append(sanitized_piece)

    if segment_evals:
        riskiest_segment = max(segment_evals, key=lambda s: s.risk_score)
        overall_risk = riskiest_segment.risk_score
        overall_action = riskiest_segment.action
        overall_cat = riskiest_segment.category
    else:
        overall_risk = 0
        overall_action = "PASS"
        overall_cat = "safe"

    return FileAnalyzeResponse(
        filename=payload.url or "raw_html.html",
        source_type=SourceType.WEB.value,
        total_segments=len(segment_evals),
        hidden_segments_count=sum(1 for s in segment_evals if s.is_hidden),
        overall_risk_score=overall_risk,
        overall_action=overall_action,
        overall_category=overall_cat,
        is_safe=(overall_action == "PASS"),
        segments=segment_evals,
        sanitized_content="\n\n".join(sanitized_chunks) if overall_action != "BLOCK" else None,
        extraction_warnings=extract_result.extraction_warnings,
    )


@router.post("/analyze-code", response_model=FileAnalyzeResponse)
def analyze_code_content(payload: CodeAnalyzeRequest):
    """Analyzes source code snippets, comments, docstrings, or markdown documentation."""
    fname = payload.filename or "snippet.py"
    extract_result = code_extractor.extract(payload.code.encode("utf-8"), filename=fname)

    segment_evals: List[SegmentRiskResult] = []
    sanitized_chunks: List[str] = []

    for seg in extract_result.segments:
        seg_eval, sanitized_piece = _evaluate_single_segment(seg)
        segment_evals.append(seg_eval)
        if sanitized_piece:
            sanitized_chunks.append(sanitized_piece)

    if segment_evals:
        riskiest_segment = max(segment_evals, key=lambda s: s.risk_score)
        overall_risk = riskiest_segment.risk_score
        overall_action = riskiest_segment.action
        overall_cat = riskiest_segment.category
    else:
        overall_risk = 0
        overall_action = "PASS"
        overall_cat = "safe"

    return FileAnalyzeResponse(
        filename=fname,
        source_type=SourceType.CODE.value,
        total_segments=len(segment_evals),
        hidden_segments_count=sum(1 for s in segment_evals if s.is_hidden),
        overall_risk_score=overall_risk,
        overall_action=overall_action,
        overall_category=overall_cat,
        is_safe=(overall_action == "PASS"),
        segments=segment_evals,
        sanitized_content="\n\n".join(sanitized_chunks) if overall_action != "BLOCK" else None,
        extraction_warnings=extract_result.extraction_warnings,
    )


# ==========================================
# 3. Existing Admin & Dashboard Endpoints
# ==========================================

@router.get("/admin/logs")
def get_audit_logs(limit: int = 50):
    """Backs the audit dashboard (Chapter 6.12)."""
    if not DB_PATH.exists():
        return {"status": "ok", "logs": []}
        
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, user_id, prompt, risk_score, attack_category, action_taken, detection_evidence
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "user_id": row[2],
                "prompt": row[3],
                "risk_score": row[4],
                "attack_category": row[5],
                "action_taken": row[6],
                "detection_evidence": row[7]
            })
        return {"status": "ok", "logs": logs}
    except Exception as e:
        return {"status": "error", "message": str(e), "logs": []}
    finally:
        conn.close()


@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serves the dashboard HTML page."""
    template_path = os.path.join("dashboard", "templates", "dashboard.html")
    if not os.path.exists(template_path):
        return HTMLResponse("<h1>Dashboard HTML template not found.</h1>", status_code=404)
    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)