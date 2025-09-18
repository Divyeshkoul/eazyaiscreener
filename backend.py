# backend.py — Enhanced GPT Evaluator + Role Extractor with improved performance and error handling

import json
import asyncio
import time
import logging
from typing import Dict, Any, Optional
from constants import AZURE_CONFIG, MODEL_CONFIG, WEIGHTS, STRICT_GPT_PROMPT
from openai import AzureOpenAI
from utils import chunk_text
import numpy as np
import pandas as pd

# Configure logging
logger = logging.getLogger(__name__)

# GPT client with connection pooling
client = AzureOpenAI(
    api_key=AZURE_CONFIG["openai_key"],
    api_version=AZURE_CONFIG["api_version"],
    azure_endpoint=AZURE_CONFIG["azure_endpoint"],
    max_retries=3,
    timeout=30.0
)

# Cache for role extraction to avoid repeated calls
_role_cache = {}

def extract_role_from_jd(jd_text: str) -> str:
    """Extract job role from JD with caching and improved error handling"""
    # Use first 500 chars as cache key
    cache_key = hash(jd_text[:500])
    
    if cache_key in _role_cache:
        return _role_cache[cache_key]
    
    try:
        # Truncate JD for faster processing
        jd_truncated = jd_text[:2000]  # Reduced from 4000 for speed
        
        prompt = f"""
Extract the primary job title from this job description. Return only the role title (2-4 words max).
If unclear, return "N/A".

Examples: "Data Analyst", "Frontend Developer", "Product Manager"

Job Description:
{jd_truncated}

Role:"""

        response = client.chat.completions.create(
            model=MODEL_CONFIG["fast_gpt_model"],
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=15,  # Reduced for faster response
        )
        
        role = response.choices[0].message.content.strip()
        
        # Validate role format
        if 2 <= len(role.split()) <= 6 and not any(char in role for char in ['\n', '\t', '|']):
            _role_cache[cache_key] = role
            return role
        else:
            _role_cache[cache_key] = "N/A"
            return "N/A"
            
    except Exception as e:
        logger.error(f"Role extraction failed: {str(e)}")
        _role_cache[cache_key] = "N/A"
        return "N/A"

async def get_resume_analysis_async(
    jd: str,
    resume_text: str,
    contact: dict,
    role: str,
    domain: str,
    skills: str,
    experience_range: str,
    jd_similarity: float,
    resume_file: str
) -> dict:
    """
    Enhanced async resume evaluator with improved performance and error handling
    """
    start_time = time.time()
    
    try:
        # Optimize text chunking - use only first 2 chunks for speed
        chunks = chunk_text(resume_text, max_tokens=1500)
        combined_text = "\n\n".join(chunks[:2])  # Reduced from 3 to 2 chunks
        
        # Construct optimized prompt
        user_prompt = f"""
JD: {jd[:1500]}

REQUIREMENTS:
- ROLE: {role}
- DOMAIN: {domain}
- SKILLS: {skills}
- EXPERIENCE: {experience_range}

RESUME:
{combined_text}

Analyze this resume against the job requirements. Focus on accuracy and be strict about scoring."""

        messages = [
            {"role": "system", "content": STRICT_GPT_PROMPT.strip()},
            {"role": "user", "content": user_prompt}
        ]

        # Make API call with optimized settings
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=MODEL_CONFIG["deep_gpt_model"],
            messages=messages,
            temperature=0.1,  # Reduced for more consistent results
            max_tokens=1000,  # Reduced from 1200 for speed
            timeout=25.0
        )

        raw_response = response.choices[0].message.content
        processing_time = time.time() - start_time
        
        logger.info(f"GPT analysis completed for {resume_file} in {processing_time:.2f}s")
        
        return parse_gpt_response(
            raw_response, contact, role, jd_similarity, 
            resume_text, resume_file, processing_time
        )

    except asyncio.TimeoutError:
        logger.error(f"Timeout processing {resume_file}")
        return create_fallback_response(
            contact, role, jd_similarity, resume_text, 
            resume_file, "Analysis timeout"
        )
    except Exception as e:
        logger.error(f"Error processing {resume_file}: {str(e)}")
        return create_fallback_response(
            contact, role, jd_similarity, resume_text, 
            resume_file, f"Processing error: {str(e)[:100]}"
        )

def parse_gpt_response(
    raw_json: str, 
    contact: dict, 
    role: str, 
    jd_similarity: float, 
    resume_text: str, 
    resume_file: str,
    processing_time: float = 0.0
) -> dict:
    """Enhanced GPT response parser with better error handling and fallbacks"""
    
    try:
        # Clean the JSON response
        json_str = raw_json.strip()
        if json_str.startswith('```json'):
            json_str = json_str[7:]
        if json_str.endswith('```'):
            json_str = json_str[:-3]
        
        parsed = json.loads(json_str)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing failed for {resume_file}: {str(e)}")
        logger.debug(f"Raw response: {raw_json[:200]}...")
        return create_fallback_response(
            contact, role, jd_similarity, resume_text, 
            resume_file, "JSON parsing failed"
        )

    # Extract scores with validation
    def get_score(key: str, fallback: int = 0) -> int:
        value = parsed.get(key, fallback)
        try:
            score = int(float(value)) if value is not None else fallback
            return max(0, min(100, score))  # Ensure 0-100 range
        except (ValueError, TypeError):
            return fallback

    skills_match = get_score("skills_match")
    domain_match = get_score("domain_match") 
    experience_match = get_score("experience_match")

    # Calculate weighted final score
    final_score = (
        skills_match * WEIGHTS["skills_match"] +
        domain_match * WEIGHTS["domain_match"] +
        experience_match * WEIGHTS["experience_match"] +
        jd_similarity * WEIGHTS["jd_similarity"]
    )

    score_rounded = round(final_score, 2)

    # Enhanced verdict logic
    verdict = parsed.get("verdict", "review").lower()
    if verdict not in ["shortlist", "review", "reject"]:
        verdict = "review"  # Default to review for invalid verdicts

    # Extract other fields with fallbacks and proper handling
    def get_field(key: str, fallback: Any = "N/A") -> Any:
        value = parsed.get(key, fallback)
        if value is None or value == "" or value == "null":
            return fallback
        if isinstance(value, str):
            value = value.strip()
            if not value or value.lower() in ["n/a", "na", "none", "null"]:
                return fallback
        return value

    # Handle name extraction with multiple fallbacks
    extracted_name = get_field("name")
    if extracted_name == "N/A" or not extracted_name:
        extracted_name = contact.get("name", "N/A")
    
    # Enhanced fitment handling with better fallbacks
    fitment = get_field("fitment")
    if fitment == "N/A" or not fitment:
        # Generate basic fitment based on scores
        if score_rounded >= 75:
            fitment = f"Strong candidate with {score_rounded}% overall match. Good alignment with job requirements."
        elif score_rounded >= 50:
            fitment = f"Potential candidate with {score_rounded}% overall match. Some gaps in requirements."
        else:
            fitment = f"Limited match with {score_rounded}% overall compatibility. Significant gaps identified."
    
    # Ensure fitment is not too long
    if len(str(fitment)) > 500:
        fitment = str(fitment)[:500] + "..."
    
    # Enhanced summary handling
    summary = get_field("summary_5_lines")
    if summary == "N/A" or not summary:
        # Generate basic summary based on available data
        summary = f"Candidate analysis for {role} position. Overall score: {score_rounded}%. "
        if skills_match > 0:
            summary += f"Skills match: {skills_match}%. "
        if domain_match > 0:
            summary += f"Domain experience: {domain_match}%. "
        summary += "Manual review recommended for detailed evaluation."
    
    # Ensure lists are properly handled
    def get_list_field(key: str) -> list:
        value = parsed.get(key, [])
        if isinstance(value, list):
            return [str(item).strip() for item in value if item and str(item).strip()]
        elif isinstance(value, str) and value.strip() and value.strip() not in ["N/A", "n/a", "none", "null"]:
            # Split string by common delimiters
            items = []
            for delimiter in [';', ',', '\n', '|']:
                if delimiter in value:
                    items = [item.strip() for item in value.split(delimiter) if item.strip()]
                    break
            return items if items else [value.strip()]
        return []

    red_flags = get_list_field("red_flags")
    missing_gaps = get_list_field("missing_gaps") 
    highlights = get_list_field("highlights")
    rejection_reasons = get_list_field("reasons_if_rejected")

    # Add automatic rejection reasons based on score
    if score_rounded < 30:
        rejection_reasons.append(f"Very low overall score ({score_rounded}%)")
        verdict = "reject"
    elif score_rounded < 50 and verdict == "shortlist":
        verdict = "review"  # Downgrade from shortlist if score is low

    # Enhanced fraud detection
    fraud_detected = bool(parsed.get("fraud_detected", False))
    if not fraud_detected:
        # Additional fraud checks based on patterns
        suspicious_patterns = [
            len(red_flags) > 5,  # Too many red flags
            score_rounded > 95,  # Suspiciously perfect score
            skills_match == 100 and domain_match == 100,  # Perfect matches are rare
            "fake" in str(fitment).lower() or "template" in str(fitment).lower()
        ]
        fraud_detected = any(suspicious_patterns)

    return {
        "name": extracted_name or "N/A",
        "email": contact.get("email", "N/A"),
        "phone": contact.get("phone", "N/A"),
        "jd_role": get_field("jd_role", role),
        "skills_match": skills_match,
        "domain_match": domain_match,
        "experience_match": experience_match,
        "jd_similarity": jd_similarity,
        "score": score_rounded,
        "fitment": str(fitment),
        "summary_5_lines": str(summary),
        "red_flags": red_flags[:10],  # Limit number of red flags
        "missing_gaps": missing_gaps[:10],  # Limit number of gaps
        "fraud_detected": fraud_detected,
        "reasons_if_rejected": rejection_reasons[:10],  # Limit reasons
        "recommendation": str(get_field("recommendation"))[:500],  # Limit length
        "highlights": highlights[:15],  # Limit number of highlights
        "verdict": verdict,
        "resume_text": resume_text,
        "resume_file": resume_file,
        "processing_time": processing_time,
        "analysis_timestamp": time.time()
    }

def create_fallback_response(
    contact: dict, 
    role: str, 
    jd_similarity: float, 
    resume_text: str, 
    resume_file: str, 
    error_reason: str = "Analysis failed"
) -> dict:
    """Create a fallback response when GPT analysis fails"""
    
    # Basic scoring based on available data
    basic_score = max(0, jd_similarity * 0.6)  # Conservative scoring
    
    # Extract basic info from contact
    candidate_name = contact.get("name", "N/A")
    
    # Generate basic fitment message
    fitment = f"Automated analysis incomplete due to: {error_reason}. "
    if jd_similarity > 60:
        fitment += f"However, resume shows {jd_similarity}% similarity to job description. Manual review recommended."
    else:
        fitment += "Low similarity to job requirements detected. Manual screening suggested."
    
    return {
        "name": candidate_name,
        "email": contact.get("email", "N/A"), 
        "phone": contact.get("phone", "N/A"),
        "jd_role": role,
        "skills_match": 0,
        "domain_match": 0,
        "experience_match": 0,
        "jd_similarity": jd_similarity,
        "score": round(basic_score, 2),
        "fitment": fitment,
        "summary_5_lines": f"Analysis for {role} position was incomplete. Manual review required to assess candidate suitability.",
        "red_flags": ["Analysis failed - manual review required"],
        "missing_gaps": ["Complete analysis unavailable"],
        "fraud_detected": True,  # Flag for manual review
        "reasons_if_rejected": [f"Analysis failure: {error_reason}"],
        "recommendation": "Manual review recommended due to analysis failure",
        "highlights": [],
        "verdict": "review",  # Default to review for failed analyses
        "resume_text": resume_text,
        "resume_file": resume_file,
        "processing_time": 0.0,
        "analysis_timestamp": time.time()
    }

# Enhanced batch processing helper for improved performance
async def batch_process_resumes(
    resume_data_list: list,
    jd: str,
    role: str,
    domain: str,
    skills: str,
    experience_range: str,
    batch_size: int = 5  # Process in smaller batches to avoid rate limits
) -> list:
    """Process resumes in batches for better performance and rate limit management"""
    
    results = []
    total_resumes = len(resume_data_list)
    
    for i in range(0, total_resumes, batch_size):
        batch = resume_data_list[i:i + batch_size]
        batch_start = time.time()
        
        # Create tasks for current batch
        tasks = []
        for resume_data in batch:
            task = get_resume_analysis_async(
                jd=jd,
                resume_text=resume_data['resume_text'],
                contact=resume_data['contact'], 
                role=role,
                domain=domain,
                skills=skills,
                experience_range=experience_range,
                jd_similarity=resume_data['jd_similarity'],
                resume_file=resume_data['resume_file']
            )
            tasks.append(task)
        
        # Process batch
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle results and exceptions
        for j, result in enumerate(batch_results):
            if isinstance(result, Exception):
                logger.error(f"Batch processing error: {str(result)}")
                # Create a fallback response using batch data
                batch_data = batch[j] if j < len(batch) else {}
                results.append(create_fallback_response(
                    batch_data.get('contact', {}), 
                    role, 
                    batch_data.get('jd_similarity', 0.0), 
                    batch_data.get('resume_text', ''), 
                    batch_data.get('resume_file', 'unknown'), 
                    str(result)
                ))
            else:
                results.append(result)
        
        batch_time = time.time() - batch_start
        logger.info(f"Processed batch {i//batch_size + 1}/{(total_resumes-1)//batch_size + 1} "
                   f"({len(batch)} resumes) in {batch_time:.2f}s")
        
        # Small delay between batches to respect rate limits
        if i + batch_size < total_resumes:
            await asyncio.sleep(0.5)
    
    return results

# Performance monitoring
class PerformanceMonitor:
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.start_time = None
        self.end_time = None
        self.resume_count = 0
        self.successful_analyses = 0
        self.failed_analyses = 0
        self.total_gpt_time = 0.0
        
    def start_analysis(self, resume_count: int):
        self.start_time = time.time()
        self.resume_count = resume_count
        logger.info(f"Starting analysis of {resume_count} resumes")
    
    def end_analysis(self):
        self.end_time = time.time()
        total_time = self.end_time - self.start_time if self.start_time else 0
        avg_time = total_time / self.resume_count if self.resume_count > 0 else 0
        
        logger.info(f"Analysis completed: {self.resume_count} resumes in {total_time:.2f}s "
                   f"(avg: {avg_time:.2f}s per resume)")
        logger.info(f"Success rate: {self.successful_analyses}/{self.resume_count} "
                   f"({(self.successful_analyses/self.resume_count)*100:.1f}%)")
        
        return {
            'total_time': total_time,
            'resume_count': self.resume_count,
            'avg_time_per_resume': avg_time,
            'successful_analyses': self.successful_analyses,
            'failed_analyses': self.failed_analyses,
            'success_rate': (self.successful_analyses/self.resume_count)*100 if self.resume_count > 0 else 0
        }
    
    def record_success(self, processing_time: float = 0.0):
        self.successful_analyses += 1
        self.total_gpt_time += processing_time
    
    def record_failure(self):
        self.failed_analyses += 1

# Utility functions for data validation and cleaning
def validate_candidate_data(candidate_data: dict) -> dict:
    """Validate and clean candidate data before processing"""
    cleaned_data = {}
    
    # Ensure required fields exist
    required_fields = ["name", "email", "score", "verdict", "fitment"]
    for field in required_fields:
        value = candidate_data.get(field, "N/A")
        if pd.isna(value) or value == "" or value is None:
            if field == "score":
                cleaned_data[field] = 0
            elif field == "verdict":
                cleaned_data[field] = "review"
            else:
                cleaned_data[field] = "N/A"
        else:
            cleaned_data[field] = value
    
    # Copy other fields
    for key, value in candidate_data.items():
        if key not in cleaned_data:
            if pd.isna(value) or value == "" or value is None:
                cleaned_data[key] = "N/A" if isinstance(value, str) else 0 if key.endswith('_match') or key == 'score' else []
            else:
                cleaned_data[key] = value
    
    return cleaned_data

def sanitize_text_field(text: str, max_length: int = 1000) -> str:
    """Sanitize and truncate text fields"""
    if not text or pd.isna(text):
        return "N/A"
    
    text = str(text).strip()
    if not text or text.lower() in ["n/a", "na", "none", "null"]:
        return "N/A"
    
    # Remove excessive whitespace and newlines
    text = " ".join(text.split())
    
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "..."
    
    return text

# Global performance monitor instance
performance_monitor = PerformanceMonitor()
