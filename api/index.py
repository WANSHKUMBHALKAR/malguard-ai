import os
import io
import csv
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, UploadFile, File, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from api.auth import router as auth_router, get_current_user
from api.db import get_db
from api.detector import StaticPEAnalyzer
from api.services.virustotal import VirusTotalService

# ReportLab imports for generating exported PDFs
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(
    title="MalGuard AI API",
    description="Backend services for Portable Executable features extraction and threat classification.",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Authentication router
app.include_router(auth_router, prefix="/api")

@app.get("/api/health")
def health_check():
    """
    Service health check endpoint.
    Checks database connection status.
    """
    try:
        db = get_db()
        # Verify db is accessible
        db.table("users").select("id").limit(1).execute()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "database": "unreachable", "error": str(e)}

@app.post("/api/scan")
async def scan_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Accepts executable file, runs static analysis and ML prediction,
    performs optional VirusTotal check, and logs to Supabase PostgreSQL.
    """
    # Max file size limit check: 25MB
    content = await file.read()
    
    # Analyze PE properties
    analyzer = StaticPEAnalyzer(content, file.filename)
    features = analyzer.extract_features()
    
    # Run ML prediction
    scan_result = analyzer.predict(features)
    
    # Optional VirusTotal lookup
    vt_service = VirusTotalService()
    vt_data = vt_service.check_hash(features["sha256"])
    if vt_data:
        scan_result["virustotal_data"] = vt_data

    # Log results to Supabase PostgreSQL
    db = get_db()
    
    insert_payload = {
        "user_id": current_user["id"],
        "filename": features["filename"],
        "file_size": features["file_size"],
        "sha256": features["sha256"],
        "md5": features["md5"],
        "entropy": features["entropy"],
        "num_sections": features["num_sections"],
        "compile_timestamp": features["compile_timestamp"],
        "prediction": scan_result["prediction"],
        "threat_score": scan_result["threat_score"],
        "confidence_score": scan_result["confidence_score"],
        "mitre_mapping": scan_result["mitre_mapping"],
        "ioc_summary": scan_result["ioc_summary"],
        "suspicious_apis": scan_result["suspicious_apis"],
        "imported_dlls": scan_result["imported_dlls"],
        "entropy_analysis": scan_result["entropy_analysis"],
        "section_analysis": scan_result["section_analysis"],
        "recommended_mitigations": scan_result["recommended_mitigations"],
        "feature_importance": scan_result["feature_importance"],
        "virustotal_data": scan_result.get("virustotal_data")
    }

    try:
        db_res = db.table("scans").insert(insert_payload).execute()
        if not db_res.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to record analysis log."
            )
        
        record = db_res.data[0]
        return record
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database logging failed: {str(e)}"
        )

@app.get("/api/scans")
async def get_scans(
    search: Optional[str] = Query(None),
    class_filter: Optional[str] = Query(None),
    limit: int = Query(50),
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieves user scanning history with searching and filtering.
    Administrators see all records. Regular users see only their own.
    """
    db = get_db()
    
    # Base query
    query = db.table("scans").select("*")
    
    # Access control: Regular users can only see their own scans
    if current_user["role"] != "admin":
        query = query.eq("user_id", current_user["id"])
        
    if class_filter:
        query = query.eq("prediction", class_filter)

    try:
        res = query.order("created_at", desc=True).execute()
        records = res.data
        
        # Apply search filter client-side/post-query for ease
        if search:
            search_lower = search.lower()
            records = [
                r for r in records if 
                search_lower in r["filename"].lower() or 
                search_lower in r["sha256"].lower() or 
                search_lower in r["md5"].lower()
            ]
            
        return records[:limit]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database fetch failed: {str(e)}"
        )

@app.get("/api/scans/{scan_id}")
async def get_scan_by_id(
    scan_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Fetches details of a single scan by ID.
    """
    db = get_db()
    
    try:
        res = db.table("scans").select("*").eq("id", scan_id).execute()
        if not res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan report not found."
            )
        
        record = res.data[0]
        
        # Access control check
        if current_user["role"] != "admin" and record["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view this report."
            )
            
        return record
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}"
        )

@app.delete("/api/scans/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Deletes scan record. Regular users can delete their own; admins can delete any.
    """
    db = get_db()
    
    try:
        # Check ownership first
        res = db.table("scans").select("user_id").eq("id", scan_id).execute()
        if not res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan report not found."
            )
            
        record = res.data[0]
        if current_user["role"] != "admin" and record["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to delete this report."
            )
            
        db.table("scans").delete().eq("id", scan_id).execute()
        return {"message": "Scan report successfully deleted."}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Delete operation failed: {str(e)}"
        )

@app.get("/api/analytics")
async def get_analytics(current_user: dict = Depends(get_current_user)):
    """
    Aggregates threat analytics, risk metrics, and history distribution.
    Regular users see statistics for their own history. Admins see global analytics.
    """
    db = get_db()
    
    try:
        query = db.table("scans").select("prediction, threat_score, created_at")
        if current_user["role"] != "admin":
            query = query.eq("user_id", current_user["id"])
            
        res = query.execute()
        scans = res.data
        
        total_scans = len(scans)
        if total_scans == 0:
            return {
                "total_scans": 0,
                "average_risk_score": 0,
                "malware_family_distribution": {},
                "threat_level_distribution": {"Clean": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "timeline": []
            }
            
        avg_risk = sum(s["threat_score"] for s in scans) / total_scans
        
        # Family Distribution
        families = {}
        for s in scans:
            pred = s["prediction"]
            families[pred] = families.get(pred, 0) + 1
            
        # Threat Level Distribution
        levels = {"Clean": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for s in scans:
            score = s["threat_score"]
            if score <= 10:
                levels["Clean"] += 1
            elif score <= 35:
                levels["Low"] += 1
            elif score <= 60:
                levels["Medium"] += 1
            elif score <= 85:
                levels["High"] += 1
            else:
                levels["Critical"] += 1

        # Timeline aggregate (Grouped by date, last 14 days)
        # Formatted: {"date": "YYYY-MM-DD", "scans": count, "malicious": count}
        timeline_data = {}
        for s in scans:
            date_str = s["created_at"][:10]  # Get YYYY-MM-DD
            if date_str not in timeline_data:
                timeline_data[date_str] = {"scans": 0, "malicious": 0}
            timeline_data[date_str]["scans"] += 1
            if s["prediction"] != "Benign":
                timeline_data[date_str]["malicious"] += 1
                
        sorted_timeline = sorted(
            [{"date": k, "scans": v["scans"], "malicious": v["malicious"]} for k, v in timeline_data.items()],
            key=lambda x: x["date"]
        )

        return {
            "total_scans": total_scans,
            "average_risk_score": round(avg_risk, 1),
            "malware_family_distribution": families,
            "threat_level_distribution": levels,
            "timeline": sorted_timeline[-14:]  # Last 14 active days
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analytics failed: {str(e)}"
        )

# Admin Operations
@app.get("/api/admin/users")
async def get_admin_users(current_user: dict = Depends(get_current_user)):
    """
    Lists users for user management screen. Requires Admin role.
    """
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    db = get_db()
    try:
        res = db.table("users").select("id, email, role, created_at").execute()
        return res.data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch users: {str(e)}"
        )

@app.delete("/api/admin/users/{user_id}", status_code=status.HTTP_200_OK)
async def delete_admin_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """
    Deletes user by ID. Requires Admin role. Prevents self deletion.
    """
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    if current_user["id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-deletion is forbidden."
        )
    db = get_db()
    try:
        db.table("users").delete().eq("id", user_id).execute()
        return {"message": "User successfully deleted."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )

# Export Reports Endpoint
@app.get("/api/scans/{scan_id}/export")
async def export_scan_report(
    scan_id: str,
    format: str = Query("json", enum=["json", "csv", "pdf"]),
    current_user: dict = Depends(get_current_user)
):
    """
    Exports a threat analysis report in JSON, CSV, or PDF formats.
    """
    db = get_db()
    try:
        res = db.table("scans").select("*").eq("id", scan_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Report not found.")
            
        record = res.data[0]
        
        # Access control checks
        if current_user["role"] != "admin" and record["user_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Unauthorized access.")
            
        if format == "json":
            # Stream JSON
            json_data = json.dumps(record, indent=4)
            return StreamingResponse(
                io.BytesIO(json_data.encode()),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
            )
            
        elif format == "csv":
            # Stream CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Field", "Value"])
            for key, val in record.items():
                if isinstance(val, (dict, list)):
                    writer.writerow([key, json.dumps(val)])
                else:
                    writer.writerow([key, str(val)])
                    
            output.seek(0)
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode()),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.csv"}
            )
            
        elif format == "pdf":
            # Stream PDF
            pdf_buffer = io.BytesIO()
            build_pdf_report(pdf_buffer, record)
            pdf_buffer.seek(0)
            return StreamingResponse(
                pdf_buffer,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"}
            )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

import json

def build_pdf_report(buffer, record):
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'RepTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=12
    )
    
    section_title = ParagraphStyle(
        'RepSec',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#0284c7'),
        spaceBefore=12,
        spaceAfter=8
    )

    meta_label = ParagraphStyle(
        'MetaLbl',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=colors.HexColor('#475569')
    )

    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#0f172a')
    )
    
    story = []
    
    # Header Banner
    story.append(Paragraph("MALGUARD AI - FORENSIC THREAT ANALYSIS REPORT", title_style))
    story.append(Paragraph(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", meta_val))
    story.append(Spacer(1, 10))
    
    # Threat score color coding
    score = record["threat_score"]
    score_color = colors.HexColor('#10b981') # Clean
    if score > 85:
        score_color = colors.HexColor('#ef4444') # Critical
    elif score > 60:
        score_color = colors.HexColor('#f97316') # High
    elif score > 35:
        score_color = colors.HexColor('#f59e0b') # Medium
    elif score > 10:
        score_color = colors.HexColor('#84cc16') # Low
        
    score_data = [[
        Paragraph(f"<b>THREAT LEVEL: {record['prediction'].upper()}</b>", ParagraphStyle('TText', parent=styles['Normal'], textColor=colors.white, fontSize=12, fontName='Helvetica-Bold')),
        Paragraph(f"<b>RISK SCORE: {score}/100</b>", ParagraphStyle('SText', parent=styles['Normal'], textColor=colors.white, fontSize=12, fontName='Helvetica-Bold', alignment=2))
    ]]
    score_table = Table(score_data, colWidths=[270, 270])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), score_color),
        ('ALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    
    story.append(score_table)
    story.append(Spacer(1, 15))
    
    # File Metadata
    story.append(Paragraph("1. File Metadata", section_title))
    metadata_table_data = [
        [Paragraph("Filename", meta_label), Paragraph(record["filename"], meta_val)],
        [Paragraph("File Size", meta_label), Paragraph(f"{record['file_size']:,} bytes", meta_val)],
        [Paragraph("SHA256 Hash", meta_label), Paragraph(record["sha256"], meta_val)],
        [Paragraph("MD5 Hash", meta_label), Paragraph(record["md5"], meta_val)],
        [Paragraph("Shannon Entropy", meta_label), Paragraph(f"{record['entropy']:.4f}", meta_val)],
        [Paragraph("Sections Count", meta_label), Paragraph(str(record["num_sections"]), meta_val)],
        [Paragraph("Compile Timestamp", meta_label), Paragraph(record["compile_timestamp"] or "N/A", meta_val)]
    ]
    meta_table = Table(metadata_table_data, colWidths=[130, 410])
    meta_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Section Analysis
    story.append(Paragraph("2. Portable Executable Sections Analysis", section_title))
    sec_headers = ["Section Name", "Virtual Size", "Raw Size", "Entropy", "Flags"]
    sec_data = [sec_headers]
    for s in record["section_analysis"][:10]: # Limit to 10 sections max in PDF
        flags = []
        if s["is_writable"]: flags.append("W")
        if s["is_executable"]: flags.append("X")
        flags_str = "|".join(flags) or "R"
        if s["suspicious"]:
            flags_str += " (Suspicious)"
            
        sec_data.append([
            s["name"],
            f"{s['virtual_size']:,}",
            f"{s['raw_size']:,}",
            f"{s['entropy']:.3f}",
            flags_str
        ])
        
    sec_table = Table(sec_data, colWidths=[120, 100, 100, 100, 120])
    sec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(sec_table)
    story.append(Spacer(1, 15))

    # MITRE ATT&CK Mapping
    story.append(Paragraph("3. MITRE ATT&CK Mapping Matrix", section_title))
    mitre_list = record.get("mitre_mapping", [])
    if not mitre_list:
        story.append(Paragraph("No dynamic technique mappings identified from static imports.", meta_val))
    else:
        mitre_data = [["Technique ID", "Technique Name", "Category"]]
        for t in mitre_list:
            mitre_data.append([t["id"], t["name"], t["category"]])
            
        mitre_table = Table(mitre_data, colWidths=[100, 200, 240])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(mitre_table)
        
    story.append(Spacer(1, 15))
    story.append(PageBreak()) # Move to next page for mitigations and VirusTotal

    # Suspicious APIs
    story.append(Paragraph("4. Suspicious Imports Identified", section_title))
    api_list = record.get("suspicious_apis", [])
    if not api_list:
        story.append(Paragraph("No high-risk security API imports matched signatures.", meta_val))
    else:
        story.append(Paragraph(", ".join(api_list), meta_val))
        
    story.append(Spacer(1, 10))

    # Recommended Actions
    story.append(Paragraph("5. Recommended Incident Response Mitigations", section_title))
    for m in record.get("recommended_mitigations", []):
        story.append(Paragraph(f"• {m}", meta_val))
        story.append(Spacer(1, 3))
        
    story.append(Spacer(1, 10))

    # VirusTotal (if available)
    vt_data = record.get("virustotal_data")
    if vt_data and vt_data.get("status") == "found":
        story.append(Paragraph("6. VirusTotal Multi-Engine Intelligence Enrichment", section_title))
        vt_stats = [
            [Paragraph("Detection Engine Stats", meta_label), Paragraph(f"Malicious: {vt_data['malicious']}  |  Suspicious: {vt_data['suspicious']}  |  Undetected: {vt_data['undetected']}  |  Harmless: {vt_data['harmless']}", meta_val)],
            [Paragraph("VirusTotal Report Link", meta_label), Paragraph(vt_data["permalink"], ParagraphStyle('LinkS', parent=styles['Normal'], textColor=colors.HexColor('#0284c7'), fontSize=8))]
        ]
        vt_table = Table(vt_stats, colWidths=[150, 390])
        vt_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(vt_table)

    # Build PDF
    doc.build(story)
