# Enhanced pdf_utils.py with proper formatting and text wrapping

from reportlab.lib.pagesizes import A4, letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, black, white, red, green, orange
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.flowables import HRFlowable
from io import BytesIO
import textwrap
from datetime import datetime

def wrap_text(text, width):
    """Wrap text to fit within specified width"""
    if not text or text == "N/A":
        return ["N/A"]
    
    # Handle very long strings by breaking them
    text = str(text)
    if len(text) > 1000:
        text = text[:1000] + "..."
    
    # Split by newlines first, then wrap each line
    lines = text.split('\n')
    wrapped_lines = []
    
    for line in lines:
        if len(line) <= width:
            wrapped_lines.append(line)
        else:
            wrapped_lines.extend(textwrap.wrap(line, width=width))
    
    return wrapped_lines

def generate_summary_pdf(candidate):
    """Generate a professional, properly formatted PDF summary"""
    buffer = BytesIO()
    
    # Use SimpleDocTemplate for better layout control
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
        title=f"Resume Analysis - {candidate.get('name', 'Unknown')}"
    )
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=20,
        textColor=HexColor('#2E86AB'),
        alignment=1  # Center alignment
    )
    
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=12,
        spaceAfter=10,
        textColor=HexColor('#A23B72'),
        spaceBefore=15
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8,
        leading=12
    )
    
    bold_style = ParagraphStyle(
        'CustomBold',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8,
        leading=12,
        fontName='Helvetica-Bold'
    )
    
    # Story elements
    story = []
    
    # Title
    story.append(Paragraph("📄 CANDIDATE FITMENT ANALYSIS", title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#2E86AB')))
    story.append(Spacer(1, 15))
    
    # Contact Information Section
    story.append(Paragraph("👤 CANDIDATE INFORMATION", header_style))
    
    # Contact info table
    contact_data = [
        ['Name:', candidate.get('name', 'N/A')],
        ['Email:', candidate.get('email', 'N/A')],
        ['Phone:', candidate.get('phone', 'N/A')],
        ['Target Role:', candidate.get('jd_role', 'N/A')],
        ['Analysis Date:', datetime.now().strftime('%Y-%m-%d %H:%M')]
    ]
    
    contact_table = Table(contact_data, colWidths=[30*mm, 120*mm])
    contact_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(contact_table)
    story.append(Spacer(1, 15))
    
    # Scoring Section
    story.append(Paragraph("📊 ASSESSMENT SCORES", header_style))
    
    # Score data with color coding
    def get_score_color(score):
        try:
            score_val = int(float(score)) if score != "N/A" else 0
            if score_val >= 75:
                return HexColor('#10B981')  # Green
            elif score_val >= 50:
                return HexColor('#F59E0B')  # Orange
            else:
                return HexColor('#EF4444')  # Red
        except:
            return black
    
    scores_data = [
        ['Metric', 'Score', 'Status']
    ]
    
    score_fields = [
        ('JD Similarity', 'jd_similarity'),
        ('Skills Match', 'skills_match'),
        ('Domain Match', 'domain_match'),
        ('Experience Match', 'experience_match'),
        ('FINAL SCORE', 'score')
    ]
    
    for label, field in score_fields:
        score = candidate.get(field, 0)
        try:
            score_val = int(float(score)) if score != "N/A" else 0
            score_display = f"{score_val}%"
            if score_val >= 75:
                status = "Excellent"
            elif score_val >= 50:
                status = "Good"
            else:
                status = "Needs Improvement"
        except:
            score_display = "N/A"
            status = "Unknown"
        
        scores_data.append([label, score_display, status])
    
    scores_table = Table(scores_data, colWidths=[60*mm, 30*mm, 50*mm])
    scores_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, black),
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#F3F4F6')),
        ('ALIGN', (1, 1), (1, -1), 'CENTER'),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(scores_table)
    story.append(Spacer(1, 15))
    
    # Verdict Section
    verdict = candidate.get('verdict', 'N/A').upper()
    verdict_color = HexColor('#10B981') if verdict == 'SHORTLIST' else HexColor('#EF4444') if verdict == 'REJECT' else HexColor('#F59E0B')
    
    verdict_style = ParagraphStyle(
        'VerdictStyle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=verdict_color,
        fontName='Helvetica-Bold',
        alignment=1
    )
    
    story.append(Paragraph(f"🏆 FINAL VERDICT: {verdict}", verdict_style))
    story.append(Spacer(1, 15))
    
    # Fitment Summary
    story.append(Paragraph("📌 FITMENT ANALYSIS", header_style))
    fitment_text = candidate.get('fitment', 'No analysis available')
    
    # Wrap and format fitment text
    fitment_wrapped = '\n'.join(wrap_text(fitment_text, 80))
    story.append(Paragraph(fitment_wrapped, normal_style))
    story.append(Spacer(1, 15))
    
    # Professional Summary
    story.append(Paragraph("📝 PROFESSIONAL SUMMARY", header_style))
    summary_text = candidate.get('summary_5_lines', 'No summary available')
    summary_wrapped = '\n'.join(wrap_text(summary_text, 80))
    story.append(Paragraph(summary_wrapped, normal_style))
    story.append(Spacer(1, 15))
    
    # Highlights Section
    highlights = candidate.get('highlights', [])
    if highlights and isinstance(highlights, list) and len(highlights) > 0:
        story.append(Paragraph("🌟 KEY HIGHLIGHTS", header_style))
        for highlight in highlights[:8]:  # Limit to 8 highlights
            story.append(Paragraph(f"• {highlight}", normal_style))
        story.append(Spacer(1, 15))
    
    # Red Flags Section
    red_flags = candidate.get('red_flags', [])
    if red_flags and isinstance(red_flags, list) and len(red_flags) > 0:
        story.append(Paragraph("🚩 AREAS OF CONCERN", header_style))
        for flag in red_flags[:8]:  # Limit to 8 flags
            flag_style = ParagraphStyle(
                'FlagStyle',
                parent=normal_style,
                textColor=HexColor('#EF4444')
            )
            story.append(Paragraph(f"• {flag}", flag_style))
        story.append(Spacer(1, 15))
    
    # Missing Information
    missing_gaps = candidate.get('missing_gaps', [])
    if missing_gaps and isinstance(missing_gaps, list) and len(missing_gaps) > 0:
        story.append(Paragraph("❓ INFORMATION GAPS", header_style))
        for gap in missing_gaps[:8]:  # Limit to 8 gaps
            story.append(Paragraph(f"• {gap}", normal_style))
        story.append(Spacer(1, 15))
    
    # Recruiter Notes
    notes = candidate.get('recruiter_notes', '').strip()
    if notes and notes != 'N/A':
        story.append(Paragraph("🗒️ RECRUITER NOTES", header_style))
        notes_wrapped = '\n'.join(wrap_text(notes, 80))
        notes_style = ParagraphStyle(
            'NotesStyle',
            parent=normal_style,
            backColor=HexColor('#F9FAFB'),
            borderColor=HexColor('#E5E7EB'),
            borderWidth=1,
            leftIndent=10,
            rightIndent=10,
            spaceAfter=10,
            spaceBefore=5
        )
        story.append(Paragraph(notes_wrapped, notes_style))
        story.append(Spacer(1, 15))
    
    # Rejection Reasons (if applicable)
    if verdict == 'REJECT':
        rejection_reasons = candidate.get('reasons_if_rejected', [])
        if rejection_reasons and isinstance(rejection_reasons, list):
            story.append(Paragraph("❌ REJECTION REASONS", header_style))
            for reason in rejection_reasons[:6]:
                reason_style = ParagraphStyle(
                    'RejectStyle',
                    parent=normal_style,
                    textColor=HexColor('#EF4444')
                )
                story.append(Paragraph(f"• {reason}", reason_style))
            story.append(Spacer(1, 15))
    
    # Recommendations
    recommendation = candidate.get('recommendation', '').strip()
    if recommendation and recommendation != 'N/A':
        story.append(Paragraph("🎯 RECOMMENDATIONS", header_style))
        rec_wrapped = '\n'.join(wrap_text(recommendation, 80))
        story.append(Paragraph(rec_wrapped, normal_style))
        story.append(Spacer(1, 15))
    
    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#E5E7EB')))
    
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=HexColor('#6B7280'),
        alignment=1  # Center
    )
    
    story.append(Paragraph(
        f"Generated by EazyAI Resume Screener | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Confidential Document",
        footer_style
    ))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
    c.showPage()
    c.save()
    buffer.seek(0)