# email_generator.py — Enhanced email functionality with better error handling

import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from constants import EMAIL_TEMPLATES
import os

# Configure logging
logger = logging.getLogger(__name__)

# Email configuration from environment variables
EMAIL_CONFIG = {
    "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_user": os.getenv("SMTP_USER", "demoprojectid3@gmail.com"),
    "smtp_pass": os.getenv("SMTP_PASS", "rpdsmhgbvppgldjx"),
    "hr_email": os.getenv("HR_EMAIL", "demoprojectid3@gmail.com")
}

def validate_email(email: str) -> bool:
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def send_email(to_email: str, subject: str, body: str, from_email: Optional[str] = None) -> bool:
    """
    Send email with enhanced error handling and validation
    """
    try:
        # Validate inputs
        if not to_email or not validate_email(to_email):
            logger.error(f"Invalid recipient email: {to_email}")
            return False
        
        if not subject or not body:
            logger.error("Subject or body is empty")
            return False
        
        # Use default from_email if not provided
        if not from_email:
            from_email = EMAIL_CONFIG["hr_email"]
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = from_email
        message["To"] = to_email
        
        # Create HTML and plain text versions
        text_part = MIMEText(body, "plain")
        html_body = body.replace('\n', '<br>')
        html_part = MIMEText(f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                {html_body}
                <br><br>
                <hr>
                <p style="font-size: 12px; color: #666;">
                    This email was sent by EazyAI Resume Screener
                </p>
            </body>
        </html>
        """, "html")
        
        message.attach(text_part)
        message.attach(html_part)
        
        # Send email
        context = ssl.create_default_context()
        
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls(context=context)
            server.login(EMAIL_CONFIG["smtp_user"], EMAIL_CONFIG["smtp_pass"])
            text = message.as_string()
            server.sendmail(from_email, to_email, text)
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {str(e)}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"Recipient email refused: {str(e)}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {str(e)}")
        return False

def generate_email_content(candidate: Dict[str, Any], verdict: str, role: str = "Position", company_name: str = "Our Company") -> Dict[str, str]:
    """
    Generate email content based on candidate data and verdict
    """
    try:
        name = candidate.get("name", "Candidate")
        
        # Get template based on verdict
        template = EMAIL_TEMPLATES.get(verdict.lower(), EMAIL_TEMPLATES["review"])
        
        # Format subject
        subject = template["subject"].format(role=role)
        
        # Format body with candidate-specific information
        body = template["body"].format(
            name=name,
            role=role,
            company_name=company_name,
            highlights=format_highlights(candidate.get("highlights", [])),
        )
        
        return {
            "subject": subject,
            "body": body
        }
        
    except Exception as e:
        logger.error(f"Error generating email content: {str(e)}")
        return {
            "subject": f"Application Update - {role}",
            "body": f"Dear {candidate.get('name', 'Candidate')},\n\nThank you for your application.\n\nBest regards,\n{company_name} Team"
        }

def format_highlights(highlights: List[str]) -> str:
    """Format highlights list for email"""
    try:
        if not highlights:
            return "• Your qualifications and experience"
        
        formatted = []
        for highlight in highlights[:5]:  # Limit to 5 highlights
            if highlight and highlight.strip():
                formatted.append(f"• {highlight.strip()}")
        
        return "\n".join(formatted) if formatted else "• Your qualifications and experience"
        
    except Exception as e:
        logger.error(f"Error formatting highlights: {str(e)}")
        return "• Your qualifications and experience"

def send_bulk_emails(candidates: List[Dict[str, Any]], verdict: str, role: str = "Position", company_name: str = "Our Company") -> Dict[str, int]:
    """
    Send bulk emails to multiple candidates
    """
    results = {
        "sent": 0,
        "failed": 0,
        "invalid_emails": 0
    }
    
    try:
        for candidate in candidates:
            email = candidate.get("email", "").strip()
            
            if not email or not validate_email(email):
                results["invalid_emails"] += 1
                continue
            
            # Generate email content
            email_content = generate_email_content(candidate, verdict, role, company_name)
            
            # Send email
            if send_email(email, email_content["subject"], email_content["body"]):
                results["sent"] += 1
            else:
                results["failed"] += 1
        
        logger.info(f"Bulk email results: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error in bulk email sending: {str(e)}")
        return results

def check_missing_info(candidate: Dict[str, Any]) -> List[str]:
    """
    Check for missing information in candidate data
    """
    missing_info = []
    
    try:
        # Check required fields
        required_fields = {
            "name": "Full name",
            "email": "Email address",
            "phone": "Phone number"
        }
        
        for field, description in required_fields.items():
            value = candidate.get(field, "").strip()
            if not value or value.lower() in ["n/a", "na", "none", "null"]:
                missing_info.append(description)
        
        # Check for empty scores
        score_fields = ["skills_match", "domain_match", "experience_match", "jd_similarity"]
        for field in score_fields:
            if candidate.get(field, 0) == 0:
                missing_info.append(f"{field.replace('_', ' ').title()} score")
        
        # Check for missing content
        content_fields = {
            "fitment": "Fitment analysis",
            "summary_5_lines": "Candidate summary"
        }
        
        for field, description in content_fields.items():
            value = str(candidate.get(field, "")).strip()
            if not value or value.lower() in ["n/a", "na", "none", "null", "analysis not available"]:
                missing_info.append(description)
        
        return missing_info
        
    except Exception as e:
        logger.error(f"Error checking missing info: {str(e)}")
        return ["Error checking information completeness"]

def send_missing_info_email(candidate: Dict[str, Any], missing_info: List[str], role: str = "Position") -> bool:
    """
    Send email requesting missing information from candidate
    """
    try:
        email = candidate.get("email", "").strip()
        if not email or not validate_email(email):
            logger.error(f"Invalid email for missing info request: {email}")
            return False
        
        name = candidate.get("name", "Candidate")
        missing_list = "\n".join([f"• {item}" for item in missing_info])
        
        subject = f"Additional Information Required - {role} Application"
        
        body = f"""Dear {name},

Thank you for your application for the {role} position.

To complete our review of your application, we need some additional information:

{missing_list}

Please provide the missing information at your earliest convenience by replying to this email.

If you have any questions, please don't hesitate to contact us.

Best regards,
Recruitment Team"""
        
        return send_email(email, subject, body)
        
    except Exception as e:
        logger.error(f"Error sending missing info email: {str(e)}")
        return False

def create_interview_invitation(candidate: Dict[str, Any], interview_details: Dict[str, str], role: str = "Position") -> Dict[str, str]:
    """
    Create interview invitation email content
    """
    try:
        name = candidate.get("name", "Candidate")
        
        subject = f"Interview Invitation - {role} Position"
        
        body = f"""Dear {name},

Congratulations! We are pleased to invite you for an interview for the {role} position.

Interview Details:
• Date: {interview_details.get('date', 'To be confirmed')}
• Time: {interview_details.get('time', 'To be confirmed')}
• Duration: {interview_details.get('duration', '45-60 minutes')}
• Format: {interview_details.get('format', 'In-person/Video call')}
• Location: {interview_details.get('location', 'To be confirmed')}

Please confirm your availability by replying to this email within 24 hours.

What to expect:
• Technical discussion about your experience
• Questions about the role and our company
• Opportunity for you to ask questions

Please bring:
• Updated resume
• Portfolio (if applicable)
• Valid ID

If you need to reschedule, please let us know as soon as possible.

We look forward to meeting you!

Best regards,
Recruitment Team"""
        
        return {"subject": subject, "body": body}
        
    except Exception as e:
        logger.error(f"Error creating interview invitation: {str(e)}")
        return {
            "subject": f"Interview Invitation - {role}",
            "body": f"Dear {candidate.get('name', 'Candidate')},\n\nWe would like to invite you for an interview.\n\nBest regards,\nRecruitment Team"
        }

def send_interview_invitation(candidate: Dict[str, Any], interview_details: Dict[str, str], role: str = "Position") -> bool:
    """
    Send interview invitation email
    """
    try:
        email = candidate.get("email", "").strip()
        if not email or not validate_email(email):
            logger.error(f"Invalid email for interview invitation: {email}")
            return False
        
        email_content = create_interview_invitation(candidate, interview_details, role)
        return send_email(email, email_content["subject"], email_content["body"])
        
    except Exception as e:
        logger.error(f"Error sending interview invitation: {str(e)}")
        return False

def create_follow_up_email(candidate: Dict[str, Any], role: str = "Position", days_since_application: int = 7) -> Dict[str, str]:
    """
    Create follow-up email content for candidates under review
    """
    try:
        name = candidate.get("name", "Candidate")
        
        subject = f"Application Status Update - {role} Position"
        
        body = f"""Dear {name},

Thank you for your interest in the {role} position and for your patience during our review process.

We wanted to provide you with an update on your application status:

Your application is currently under review by our hiring team. We have received a high volume of applications for this position, and we are carefully evaluating each candidate to ensure we make the best hiring decision.

What happens next:
• Our team will complete the initial review within the next 3-5 business days
• Qualified candidates will be contacted for the next stage of the process
• All applicants will be notified of their status regardless of the outcome

We appreciate your continued interest in our organization and will be in touch soon with an update.

If you have any questions in the meantime, please don't hesitate to reach out.

Best regards,
Recruitment Team

---
Application submitted: {days_since_application} days ago
Current status: Under Review"""
        
        return {"subject": subject, "body": body}
        
    except Exception as e:
        logger.error(f"Error creating follow-up email: {str(e)}")
        return {
            "subject": f"Application Update - {role}",
            "body": f"Dear {candidate.get('name', 'Candidate')},\n\nYour application is under review.\n\nBest regards,\nRecruitment Team"
        }

def send_follow_up_email(candidate: Dict[str, Any], role: str = "Position", days_since_application: int = 7) -> bool:
    """
    Send follow-up email to candidate
    """
    try:
        email = candidate.get("email", "").strip()
        if not email or not validate_email(email):
            logger.error(f"Invalid email for follow-up: {email}")
            return False
        
        email_content = create_follow_up_email(candidate, role, days_since_application)
        return send_email(email, email_content["subject"], email_content["body"])
        
    except Exception as e:
        logger.error(f"Error sending follow-up email: {str(e)}")
        return False

def test_email_connection() -> Dict[str, Any]:
    """
    Test email configuration and connection
    """
    test_result = {
        "connection_successful": False,
        "authentication_successful": False,
        "error_message": None
    }
    
    try:
        # Test SMTP connection
        context = ssl.create_default_context()
        
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls(context=context)
            test_result["connection_successful"] = True
            
            # Test authentication
            server.login(EMAIL_CONFIG["smtp_user"], EMAIL_CONFIG["smtp_pass"])
            test_result["authentication_successful"] = True
        
        logger.info("Email connection test successful")
        
    except smtplib.SMTPAuthenticationError as e:
        test_result["error_message"] = f"Authentication failed: {str(e)}"
        logger.error(f"Email authentication failed: {str(e)}")
    except smtplib.SMTPConnectError as e:
        test_result["error_message"] = f"Connection failed: {str(e)}"
        logger.error(f"Email connection failed: {str(e)}")
    except Exception as e:
        test_result["error_message"] = f"Unexpected error: {str(e)}"
        logger.error(f"Email test failed: {str(e)}")
    
    return test_result

def send_test_email(test_recipient: str = None) -> bool:
    """
    Send a test email to verify functionality
    """
    try:
        recipient = test_recipient or EMAIL_CONFIG["hr_email"]
        
        if not validate_email(recipient):
            logger.error(f"Invalid test email recipient: {recipient}")
            return False
        
        subject = "EazyAI Resume Screener - Test Email"
        body = """This is a test email from EazyAI Resume Screener.

If you received this email, the email configuration is working correctly.

Test Details:
• SMTP Server: {smtp_server}
• Port: {smtp_port} 
• Sender: {smtp_user}

Best regards,
EazyAI System""".format(**EMAIL_CONFIG)
        
        return send_email(recipient, subject, body)
        
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}")
        return False

def get_email_statistics(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics about email addresses in candidate list
    """
    stats = {
        "total_candidates": len(candidates),
        "valid_emails": 0,
        "invalid_emails": 0,
        "missing_emails": 0,
        "email_domains": {},
        "duplicate_emails": 0
    }
    
    try:
        seen_emails = set()
        
        for candidate in candidates:
            email = candidate.get("email", "").strip().lower()
            
            if not email or email in ["n/a", "na", "none", "null"]:
                stats["missing_emails"] += 1
            elif not validate_email(email):
                stats["invalid_emails"] += 1
            else:
                if email in seen_emails:
                    stats["duplicate_emails"] += 1
                else:
                    seen_emails.add(email)
                    stats["valid_emails"] += 1
                    
                    # Extract domain
                    domain = email.split("@")[1]
                    stats["email_domains"][domain] = stats["email_domains"].get(domain, 0) + 1
        
        # Sort domains by frequency
        stats["email_domains"] = dict(sorted(stats["email_domains"].items(), key=lambda x: x[1], reverse=True))
        
        return stats
        
    except Exception as e:
        logger.error(f"Error calculating email statistics: {str(e)}")
        return stats

def create_rejection_with_feedback(candidate: Dict[str, Any], role: str = "Position", feedback_points: List[str] = None) -> Dict[str, str]:
    """
    Create constructive rejection email with feedback
    """
    try:
        name = candidate.get("name", "Candidate")
        
        subject = f"Application Status Update - {role} Position"
        
        feedback_section = ""
        if feedback_points:
            feedback_section = """
Areas for potential development based on our requirements:
""" + "\n".join([f"• {point}" for point in feedback_points[:3]])  # Limit to 3 points
        
        body = f"""Dear {name},

Thank you for your interest in the {role} position and for taking the time to apply.

After careful consideration of all applications, we have decided not to proceed with your candidacy for this specific role. This decision was difficult given the quality of applications we received.
{feedback_section}

We encourage you to continue developing your skills and to apply for future opportunities that may be a better match for your background.

We will keep your resume on file for future openings that may align with your experience.

Thank you again for considering us, and we wish you all the best in your career journey.

Best regards,
Recruitment Team

---
If you have any questions about this decision, please feel free to reach out."""
        
        return {"subject": subject, "body": body}
        
    except Exception as e:
        logger.error(f"Error creating rejection with feedback: {str(e)}")
        return {
            "subject": f"Application Status - {role}",
            "body": f"Dear {candidate.get('name', 'Candidate')},\n\nThank you for your application.\n\nBest regards,\nRecruitment Team"
        }

def schedule_email_batch(candidates: List[Dict[str, Any]], verdict: str, role: str, delay_hours: int = 0) -> Dict[str, Any]:
    """
    Schedule batch emails to be sent (placeholder for future scheduling functionality)
    """
    try:
        # For now, this is a placeholder that returns scheduling info
        # In a full implementation, this would integrate with a task queue
        
        valid_emails = [c for c in candidates if validate_email(c.get("email", ""))]
        
        schedule_info = {
            "total_candidates": len(candidates),
            "valid_emails": len(valid_emails),
            "invalid_emails": len(candidates) - len(valid_emails),
            "verdict": verdict,
            "role": role,
            "delay_hours": delay_hours,
            "scheduled": True,
            "estimated_send_time": f"In {delay_hours} hours" if delay_hours > 0 else "Immediately"
        }
        
        logger.info(f"Email batch scheduled: {schedule_info}")
        return schedule_info
        
    except Exception as e:
        logger.error(f"Error scheduling email batch: {str(e)}")
        return {"scheduled": False, "error": str(e)}

# Email template customization functions
def customize_email_template(template_type: str, custom_content: Dict[str, str]) -> bool:
    """
    Customize email templates (placeholder for template management)
    """
    try:
        if template_type not in EMAIL_TEMPLATES:
            logger.error(f"Unknown template type: {template_type}")
            return False
        
        # In a full implementation, this would save custom templates
        logger.info(f"Template customization requested for: {template_type}")
        return True
        
    except Exception as e:
        logger.error(f"Error customizing email template: {str(e)}")
        return False

def get_email_template_preview(template_type: str, sample_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate preview of email template with sample data
    """
    try:
        if template_type not in EMAIL_TEMPLATES:
            return {"error": f"Unknown template type: {template_type}"}
        
        # Create sample candidate data
        sample_candidate = {
            "name": sample_data.get("name", "John Doe"),
            "highlights": sample_data.get("highlights", ["Strong technical skills", "Relevant experience", "Good cultural fit"])
        }
        
        role = sample_data.get("role", "Software Developer")
        company_name = sample_data.get("company_name", "Tech Company")
        
        preview = generate_email_content(sample_candidate, template_type, role, company_name)
        preview["template_type"] = template_type
        
        return preview
        
    except Exception as e:
        logger.error(f"Error generating email preview: {str(e)}")
        return {"error": str(e)}
