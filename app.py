import streamlit as st
import pandas as pd
import base64
import asyncio
from datetime import datetime
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import time
import logging

# Configure logging for performance tracking
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import your existing modules
from constants import AZURE_CONFIG
from utils import (
    parse_resume,
    get_text_chunks,
    get_embedding_cached,
    get_cosine_similarity,
    upload_to_blob,
    extract_contact_info,
    save_summary_to_blob,
    save_csv_to_blob
)
from backend import get_resume_analysis_async, extract_role_from_jd
from pdf_utils import generate_summary_pdf
from email_generator import send_email, check_missing_info, send_missing_info_email

# Import Gmail service
from gmail_to_blob import auto_sync_gmail_on_startup, get_gmail_service

# Azure Blob Storage
from azure.storage.blob import BlobServiceClient

# Enhanced Design with fixed light mode styling
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0f1419 0%, #1a2332 50%, #0f1419 100%);
        font-family: 'Inter', sans-serif;
    }

    /* Light mode compatibility */
    [data-theme="light"] .stApp {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #f1f5f9 100%);
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e2a3a 0%, #0f1419 100%) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }

    [data-theme="light"] section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%) !important;
        border-right: 1px solid rgba(0, 0, 0, 0.1);
    }

    .main-title {
        text-align: center;
        background: linear-gradient(135deg, #00d4ff 0%, #5865f2 50%, #ff6b6b 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        text-shadow: 0 0 30px rgba(0, 212, 255, 0.3);
    }

    .subtitle {
        text-align: center;
        color: #94a3b8;
        font-size: 1.4rem;
        font-weight: 400;
        margin-bottom: 2rem;
    }

    [data-theme="light"] .subtitle {
        color: #475569;
    }

    .candidate-card {
        background: linear-gradient(135deg, rgba(30, 42, 58, 0.8) 0%, rgba(15, 20, 25, 0.9) 100%);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
        color: #e2e8f0;
    }

    [data-theme="light"] .candidate-card {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 250, 252, 0.9) 100%);
        border: 1px solid rgba(0, 0, 0, 0.1);
        color: #1e293b;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }

    .candidate-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 12px 40px rgba(0, 212, 255, 0.2);
        border-color: rgba(0, 212, 255, 0.3);
    }

    .metric-container {
        background: rgba(30, 42, 58, 0.6);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: #e2e8f0;
    }

    [data-theme="light"] .metric-container {
        background: rgba(255, 255, 255, 0.8);
        border: 1px solid rgba(0, 0, 0, 0.1);
        color: #1e293b;
    }

    .status-shortlist {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 500;
    }

    .status-review {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 500;
    }

    .status-reject {
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 500;
    }

    .sidebar-section {
        background: rgba(0, 212, 255, 0.1);
        padding: 0.5rem 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        border-left: 3px solid #00d4ff;
        color: #e2e8f0;
    }

    [data-theme="light"] .sidebar-section {
        background: rgba(0, 212, 255, 0.1);
        color: #1e293b;
    }

    .performance-metrics {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        border-radius: 12px;
        padding: 1rem;
        margin: 1rem 0;
        color: #e2e8f0;
    }

    [data-theme="light"] .performance-metrics {
        color: #1e293b;
    }

    .gmail-sync-status {
        background: rgba(88, 101, 242, 0.1);
        border: 1px solid rgba(88, 101, 242, 0.2);
        border-radius: 12px;
        padding: 1rem;
        margin: 1rem 0;
        color: #e2e8f0;
    }

    [data-theme="light"] .gmail-sync-status {
        color: #1e293b;
        background: rgba(88, 101, 242, 0.1);
    }

    .sync-active {
        background: rgba(16, 185, 129, 0.1) !important;
        border-color: rgba(16, 185, 129, 0.3) !important;
    }

    .sync-error {
        background: rgba(239, 68, 68, 0.1) !important;
        border-color: rgba(239, 68, 68, 0.3) !important;
    }

    .candidate-name {
        color: #e2e8f0;
        font-weight: 600;
    }

    [data-theme="light"] .candidate-name {
        color: #1e293b;
    }

    .candidate-contact {
        color: #94a3b8;
    }

    [data-theme="light"] .candidate-contact {
        color: #64748b;
    }

    .candidate-fitment {
        color: #cbd5e1;
    }

    [data-theme="light"] .candidate-fitment {
        color: #475569;
    }

    .stButton > button {
        background: linear-gradient(135deg, #00d4ff 0%, #5865f2 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.5rem 1.5rem !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3) !important;
    }

    .stButton > button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(0, 212, 255, 0.4) !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Initialize session state
def initialize_session_state():
    if "candidate_df" not in st.session_state:
        st.session_state["candidate_df"] = None
    if "analysis_done" not in st.session_state:
        st.session_state["analysis_done"] = False
    if "processing_metrics" not in st.session_state:
        st.session_state["processing_metrics"] = {}
    # Initialize candidate notes and verdicts tracking
    if "candidate_updates" not in st.session_state:
        st.session_state["candidate_updates"] = {}
    # Gmail sync initialization
    if "gmail_service_initialized" not in st.session_state:
        st.session_state["gmail_service_initialized"] = False
    if "gmail_sync_status" not in st.session_state:
        st.session_state["gmail_sync_status"] = {}

initialize_session_state()



# Initialize BlobServiceClient
@st.cache_resource
def get_blob_service_client():
    return BlobServiceClient.from_connection_string(AZURE_CONFIG["connection_string"])

blob_service_client = get_blob_service_client()
resumes_container_client = blob_service_client.get_container_client(AZURE_CONFIG["resumes_container"])

# Initialize Gmail service on app startup
@st.cache_resource
def initialize_gmail_service():
    """Initialize Gmail service once when app starts"""
    try:
        service = auto_sync_gmail_on_startup(AZURE_CONFIG["connection_string"])
        logger.info("Gmail service initialized and background sync started")
        return service
    except Exception as e:
        logger.error(f"Failed to initialize Gmail service: {str(e)}")
        return None

# Start Gmail service when app loads
gmail_service = initialize_gmail_service()
if gmail_service and not st.session_state["gmail_service_initialized"]:
    st.session_state["gmail_service_initialized"] = True

def download_all_supported_resume_blobs():
    """Download all supported resume files (PDF, DOCX, DOC) from Azure Blob Storage"""
    try:
        blobs = resumes_container_client.list_blobs()
        resume_files = []
        supported_extensions = ['.pdf', '.docx', '.doc']
        
        for blob in blobs:
            if any(blob.name.lower().endswith(ext) for ext in supported_extensions):
                try:
                    downloader = resumes_container_client.download_blob(blob.name)
                    file_bytes = downloader.readall()
                    resume_files.append((blob.name, file_bytes))
                except Exception as e:
                    logger.error(f"Error downloading {blob.name}: {str(e)}")
                    continue
        
        logger.info(f"Downloaded {len(resume_files)} supported resume files")
        return resume_files
    except Exception as e:
        st.error(f"Error downloading from blob storage: {str(e)}")
        return []

def render_gmail_sync_status():
    """Render Gmail sync status in the main area"""
    if gmail_service:
        status = gmail_service.get_status()
        st.session_state["gmail_sync_status"] = status
        
        # Determine status class
        status_class = "gmail-sync-status"
        if status.get("is_active", False):
            status_class += " sync-active"
        elif status.get("errors", []):
            status_class += " sync-error"
        
        # Render status box
        status_icon = "🔄" if status.get("is_active") else "✅" if status.get("last_sync") else "⏳"
        active_text = " (Active)" if status.get("is_active") else ""
        
        st.markdown(f"""
        <div class="{status_class}">
            <h4>{status_icon} Gmail Auto-Sync Status{active_text}</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem;">
                <div>
                    <strong>Last Sync:</strong><br>
                    {status.get('last_sync', 'Never')}
                </div>
                <div>
                    <strong>Emails Processed:</strong><br>
                    {status.get('emails_processed', 0)}
                </div>
                <div>
                    <strong>Resumes Uploaded:</strong><br>
                    {status.get('files_uploaded', 0)}
                </div>
                <div>
                    <strong>Status:</strong><br>
                    {'🔄 Processing...' if status.get('is_active') else '✅ Ready'}
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Show errors if any
        if status.get("errors"):
            with st.expander("⚠️ Sync Errors", expanded=False):
                for error in status["errors"][-5:]:  # Show last 5 errors
                    st.error(error)
        
        return status
    else:
        st.markdown("""
        <div class="gmail-sync-status sync-error">
            <h4>❌ Gmail Auto-Sync Unavailable</h4>
            <p>Gmail service could not be initialized. Please check your configuration.</p>
        </div>
        """, unsafe_allow_html=True)
        return {}

# Enhanced Header
st.markdown('<h1 class="main-title">EazyAI</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Intelligent Resume Screening Platform</p>', unsafe_allow_html=True)

# Gmail Sync Status (always visible at the top)
col1, col2 = st.columns([3, 1])
with col1:
    gmail_status = render_gmail_sync_status()
with col2:
    st.markdown("### 🔄 Manual Sync")
    if gmail_service:
        if st.button("📧 Sync Gmail Now", type="secondary", use_container_width=True):
            if not gmail_status.get("is_active", False):
                with st.spinner("Syncing Gmail..."):
                    result = gmail_service.sync_now()
                    if "error" in result:
                        st.error(result["error"])
                    else:
                        st.success(f"Sync completed! {result.get('files_uploaded', 0)} files uploaded")
                        st.rerun()
            else:
                st.warning("Sync already in progress")
    else:
        st.error("Gmail service unavailable")

st.markdown("---")

# Sidebar Configuration
with st.sidebar:
    st.markdown('<div class="sidebar-section"><h3>📋 Job Configuration</h3></div>', unsafe_allow_html=True)
    
    jd = st.text_area("📄 Paste Job Description", height=200, placeholder="Enter the complete job description here...")
    
    role = "N/A"
    if jd:
        with st.spinner("Extracting role from JD..."):
            role = extract_role_from_jd(jd)
            if role != "N/A":
                st.success(f"🎯 **Detected Role:** {role}")
            else:
                st.warning("⚠️ Could not extract role from JD")

    domain = st.text_input("🏢 Preferred Domain", placeholder="e.g., Healthcare, Fintech, E-commerce")
    skills = st.text_area("🛠️ Required Skills (comma separated)", placeholder="Python, React, AWS, Machine Learning")
    exp_range = st.selectbox("📈 Required Experience", ["0–1 yrs", "1–3 yrs", "2–4 yrs", "4+ yrs"])

    st.markdown('<div class="sidebar-section"><h3>🎚️ Matching Thresholds</h3></div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        jd_thresh = st.slider("JD Similarity", 0, 100, 60, help="Minimum similarity with job description")
        domain_thresh = st.slider("Domain Match", 0, 100, 50, help="Minimum domain experience match")
    with col2:
        skill_thresh = st.slider("Skills Match", 0, 100, 65, help="Minimum required skills match")
        exp_thresh = st.slider("Experience Match", 0, 100, 55, help="Experience level compatibility")
    
    # Enhanced scoring thresholds
    shortlist_thresh = st.slider("🟢 Shortlist Threshold", 0, 100, 75, help="Score for automatic shortlisting")
    reject_thresh = st.slider("🔴 Reject Threshold", 0, 100, 40, help="Score below which candidates are rejected")
    top_n = st.number_input("🏆 Top-N Candidates", 0, 50, 0, help="Limit shortlisted candidates (0 = no limit)")

    st.markdown('<div class="sidebar-section"><h3>📂 Resume Source</h3></div>', unsafe_allow_html=True)
    
    load_from_blob = st.checkbox("☁️ Load from Azure Blob Storage", value=True, help="Automatically loads resumes from Gmail sync")

    if not load_from_blob:
        uploaded_files = st.file_uploader(
            "📤 Upload Resume Files", 
            type=["pdf", "docx", "doc"], 
            accept_multiple_files=True,
            help="Select multiple resume files (PDF, DOCX, DOC formats supported)"
        )
    else:
        uploaded_files = None
        st.info("📧 Resumes will be loaded from Azure Blob Storage (including Gmail sync)")

    # Gmail sync controls in sidebar
    st.markdown('<div class="sidebar-section"><h3>📧 Gmail Integration</h3></div>', unsafe_allow_html=True)
    
    if gmail_service:
        sync_status = gmail_service.get_status()
        
        st.markdown(f"""
        **Status:** {'🔄 Active' if sync_status.get('is_active') else '✅ Ready'}  
        **Last Sync:** {sync_status.get('last_sync', 'Never')}  
        **Files Uploaded:** {sync_status.get('files_uploaded', 0)}
        """)
        
        if sync_status.get("errors"):
            st.warning(f"⚠️ {len(sync_status['errors'])} sync errors")
    else:
        st.error("❌ Gmail service unavailable")

    st.markdown("---")
    analyze = st.button("🚀 Start Analysis", type="primary", use_container_width=True)

# Main Processing Logic
if jd and analyze and not st.session_state["analysis_done"]:
    start_time = time.time()
    logger.info("Starting resume analysis")
    
    progress_container = st.container()
    with progress_container:
        st.markdown("### 🔄 Processing Resumes...")
        progress_bar = st.progress(0, text="Initializing analysis...")
        status_text = st.empty()

    # Load resumes
    if load_from_blob:
        status_text.info("📥 Loading resumes from Azure Blob Storage...")
        blob_files = download_all_supported_resume_blobs()  # Now supports PDF, DOCX, DOC
        total = len(blob_files)
        if total == 0:
            st.error("❌ No resume files found in Azure Blob storage container.")
            st.info("💡 **Tip:** Send resumes (PDF, DOCX, DOC) to **eazyai111@gmail.com** and they will be automatically uploaded!")
            st.stop()
        else:
            file_types = {}
            for file_name, _ in blob_files:
                ext = file_name.lower().split('.')[-1]
                file_types[ext] = file_types.get(ext, 0) + 1
            
            types_text = ", ".join([f"{count} {ext.upper()}" for ext, count in file_types.items()])
            st.info(f"📊 Found {total} resumes in blob storage ({types_text})")
    else:
        blob_files = None
        total = len(uploaded_files) if uploaded_files else 0
        if total == 0:
            st.error("❌ Please upload at least one resume or enable blob storage option.")
            st.stop()

    # Performance tracking
    processing_start = time.time()
    results = []
    
    # Pre-compute JD embedding once
    jd_embedding_start = time.time()
    jd_embedding = get_embedding_cached(jd)
    jd_embedding_time = time.time() - jd_embedding_start
    logger.info(f"JD embedding computed in {jd_embedding_time:.2f} seconds")

    async def process_all_resumes():
        tasks = []
        resume_processing_start = time.time()

        if load_from_blob:
            for idx, (file_name, file_bytes) in enumerate(blob_files):
                # Update progress
                progress = (idx + 1) / total
                progress_bar.progress(progress, text=f"Processing {file_name} ({idx+1}/{total})")
                
                try:
                    # Upload to blob (if not already there)
                    upload_to_blob(file_bytes, file_name, AZURE_CONFIG["resumes_container"])
                    
                    # Parse resume
                    resume_text = parse_resume(file_bytes)
                    contact = extract_contact_info(resume_text)

                    # Compute similarity
                    chunks = get_text_chunks(resume_text)
                    resume_embedding = get_embedding_cached(" ".join(chunks[:3]))  # Limit chunks for speed
                    jd_sim = round(get_cosine_similarity(resume_embedding, jd_embedding) * 100, 2)

                    # Create async task
                    task = get_resume_analysis_async(
                        jd=jd, resume_text=resume_text, contact=contact, role=role,
                        domain=domain, skills=skills, experience_range=exp_range,
                        jd_similarity=jd_sim, resume_file=file_name
                    )
                    tasks.append(task)
                except Exception as e:
                    logger.error(f"Error processing {file_name}: {str(e)}")
                    continue
        else:
            for idx, file in enumerate(uploaded_files):
                # Update progress
                progress = (idx + 1) / total
                progress_bar.progress(progress, text=f"Processing {file.name} ({idx+1}/{total})")
                
                try:
                    file_bytes = file.read()
                    file_name = file.name.replace(".pdf", "")
                    
                    # Upload to blob
                    upload_to_blob(file_bytes, file_name + ".pdf", AZURE_CONFIG["resumes_container"])

                    # Parse resume
                    resume_text = parse_resume(file_bytes)
                    contact = extract_contact_info(resume_text)

                    # Compute similarity
                    chunks = get_text_chunks(resume_text)
                    resume_embedding = get_embedding_cached(" ".join(chunks[:3]))  # Limit chunks for speed
                    jd_sim = round(get_cosine_similarity(resume_embedding, jd_embedding) * 100, 2)

                    # Create async task
                    task = get_resume_analysis_async(
                        jd=jd, resume_text=resume_text, contact=contact, role=role,
                        domain=domain, skills=skills, experience_range=exp_range,
                        jd_similarity=jd_sim, resume_file=file_name
                    )
                    tasks.append(task)
                except Exception as e:
                    logger.error(f"Error processing {file.name}: {str(e)}")
                    continue

        # Execute all tasks concurrently
        if tasks:
            status_text.info("🧠 Running AI analysis on all resumes...")
            return await asyncio.gather(*tasks, return_exceptions=True)
        return []

    # Run async processing
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(process_all_resumes())
        loop.close()
    except Exception as e:
        st.error(f"Error during processing: {str(e)}")
        logger.error(f"Processing error: {str(e)}")
        st.stop()

    # Filter out exceptions and process results
    valid_results = []
    for r in results:
        if isinstance(r, Exception):
            logger.error(f"Task failed: {str(r)}")
            continue
        if isinstance(r, dict):
            # Add recruiter notes field
            r["recruiter_notes"] = ""
            valid_results.append(r)

    if not valid_results:
        st.error("❌ No resumes were successfully processed.")
        st.stop()

    results = valid_results
    processing_time = time.time() - processing_start
    total_time = time.time() - start_time

    # Enhanced verdict logic with three categories
    def determine_verdict(row):
        score = row["score"]
        if (
            row["jd_similarity"] < jd_thresh or
            row["skills_match"] < skill_thresh or
            row["domain_match"] < domain_thresh or
            row["experience_match"] < exp_thresh or
            score < reject_thresh
        ):
            return "reject"
        elif score >= shortlist_thresh:
            return "shortlist"
        else:
            return "review"

    # Create DataFrame and apply verdict logic
    df = pd.DataFrame(results).fillna("N/A")
    df.replace("n/a", "N/A", regex=True, inplace=True)
    df["verdict"] = df.apply(determine_verdict, axis=1)

    # Apply Top-N logic
    if top_n > 0:
        sorted_df = df.sort_values("score", ascending=False)
        top_candidates = sorted_df.head(top_n).copy()
        top_candidates["verdict"] = "shortlist"
        
        # Remaining candidates keep their original verdicts
        remaining = sorted_df.iloc[top_n:].copy()
        df = pd.concat([top_candidates, remaining], ignore_index=True)

    # Store results and metrics
    st.session_state["candidate_df"] = df
    st.session_state["analysis_done"] = True
    st.session_state["processing_metrics"] = {
        "total_time": total_time,
        "processing_time": processing_time,
        "jd_embedding_time": jd_embedding_time,
        "resumes_processed": len(df),
        "avg_time_per_resume": processing_time / len(df) if len(df) > 0 else 0
    }

    # Display performance metrics
    progress_bar.progress(1.0, text="✅ Analysis completed!")
    
    metrics = st.session_state["processing_metrics"]
    st.markdown(f"""
    <div class="performance-metrics">
        <h4>⚡ Performance Metrics</h4>
        <ul>
            <li><strong>Total Processing Time:</strong> {metrics['total_time']:.2f} seconds</li>
            <li><strong>Resumes Processed:</strong> {metrics['resumes_processed']}</li>
            <li><strong>Average Time per Resume:</strong> {metrics['avg_time_per_resume']:.2f} seconds</li>
            <li><strong>JD Embedding Time:</strong> {metrics['jd_embedding_time']:.2f} seconds</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    st.success(f"🎉 Successfully processed {len(results)} resumes in {total_time:.2f} seconds!")
    logger.info(f"Analysis completed: {len(results)} resumes in {total_time:.2f} seconds")

# Display Results
if st.session_state["candidate_df"] is not None:
    df = st.session_state["candidate_df"]
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    shortlisted_count = len(df[df["verdict"] == "shortlist"])
    review_count = len(df[df["verdict"] == "review"]) 
    rejected_count = len(df[df["verdict"] == "reject"])
    total_count = len(df)
    
    with col1:
        st.markdown(f'<div class="metric-container"><h3>✅ {shortlisted_count}</h3><p>Shortlisted</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-container"><h3>🟨 {review_count}</h3><p>Under Review</p></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="metric-container"><h3>❌ {rejected_count}</h3><p>Rejected</p></div>', unsafe_allow_html=True)
    with col4:
        st.markdown(f'<div class="metric-container"><h3>📊 {total_count}</h3><p>Total Processed</p></div>', unsafe_allow_html=True)

    # Display processing metrics if available
    if "processing_metrics" in st.session_state and st.session_state["processing_metrics"]:
        metrics = st.session_state["processing_metrics"]
        st.markdown(f"""
        <div class="performance-metrics">
            <h4>⚡ Last Analysis Performance</h4>
            <p><strong>{metrics['resumes_processed']} resumes</strong> processed in <strong>{metrics['total_time']:.2f}s</strong> 
            (avg: {metrics['avg_time_per_resume']:.2f}s per resume)</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    
    # Enhanced tabs
    tabs = st.tabs([
        f"✅ Shortlisted ({shortlisted_count})", 
        f"🟨 Under Review ({review_count})", 
        f"❌ Rejected ({rejected_count})", 
        "📊 Analytics Dashboard"
    ])

    # Function to render candidate cards with improved session state handling
    def render_candidate_card(row, verdict, idx):
        with st.container():
            st.markdown('<div class="candidate-card">', unsafe_allow_html=True)
            
            # Header section
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Candidate name with status badge
                status_class = f"status-{verdict}"
                candidate_name = row.get('name', 'Unknown')
                st.markdown(f"""
                <div class="candidate-name">
                    <h3>👤 {candidate_name} <span class="{status_class}">{verdict.upper()}</span></h3>
                </div>
                """, unsafe_allow_html=True)
                
                # Contact info - with proper fallbacks
                email = row.get('email', 'N/A')
                phone = row.get('phone', 'N/A')
                st.markdown(f'<div class="candidate-contact">📧 <strong>{email}</strong> | 📞 <strong>{phone}</strong></div>', unsafe_allow_html=True)
                
                # Fitment summary - with proper fallback and truncation
                fitment = row.get('fitment', 'N/A')
                if pd.isna(fitment) or fitment == '' or fitment == 'None':
                    fitment = 'Analysis pending'
                # Truncate long fitment text
                if len(str(fitment)) > 200:
                    fitment = str(fitment)[:200] + "..."
                st.markdown(f'<div class="candidate-fitment">💡 <strong>Fitment:</strong> {fitment}</div>', unsafe_allow_html=True)
                
                # Score metrics with visual indicators - with proper fallbacks
                col_jd, col_skills, col_domain, col_exp, col_final = st.columns(5)
                
                def safe_get_score(key, default=0):
                    value = row.get(key, default)
                    try:
                        return int(float(value)) if pd.notna(value) else default
                    except (ValueError, TypeError):
                        return default
                
                with col_jd:
                    st.metric("JD Match", f"{safe_get_score('jd_similarity')}%")
                with col_skills:
                    st.metric("Skills", f"{safe_get_score('skills_match')}%")
                with col_domain:
                    st.metric("Domain", f"{safe_get_score('domain_match')}%")
                with col_exp:
                    st.metric("Experience", f"{safe_get_score('experience_match')}%")
                with col_final:
                    st.metric("Final Score", f"{safe_get_score('score')}%")

            with col2:
                # Action buttons with proper unique keys
                st.markdown("### 🎬 Actions")
                
                # Create a unique candidate identifier
                candidate_id = f"{candidate_name}_{idx}_{hash(str(row))}"[:50].replace(" ", "_")
                
                # Email button
                email_key = f"email_{candidate_id}"
                if st.button(f"✉️ Send Email", key=email_key, type="primary"):
                    email_addr = row.get('email', '').strip()
                    if email_addr and email_addr not in ['N/A', '', 'nan', 'None']:
                        # Get role for email template
                        current_role = role if role != "N/A" else "this position"
                        
                        # Email templates based on verdict
                        if verdict == "shortlist":
                            subject = f"Congratulations! You've been shortlisted for {current_role}"
                            highlights = row.get('highlights', [])
                            highlights_text = ""
                            if highlights and isinstance(highlights, list) and len(highlights) > 0:
                                highlights_text = "• " + "\n• ".join(highlights[:3])
                            else:
                                highlights_text = "• Your qualifications and experience"
                            
                            body = f"""Dear {candidate_name},

Congratulations! After reviewing your application for the {current_role} position, we are pleased to inform you that you have been shortlisted for the next round.

Our team was impressed with your qualifications and experience, particularly:
{highlights_text}

We will be in touch soon with details about the next steps in our selection process.

Best regards,
EazyAI Recruitment Team"""
                        
                        elif verdict == "review":
                            subject = f"Application Under Review - {current_role}"
                            body = f"""Dear {candidate_name},

Thank you for your application for the {current_role} position. 

Your profile is currently under review by our recruitment team. We may need some additional information to proceed and will be in touch shortly.

Thank you for your patience during this process.

Best regards,
EazyAI Recruitment Team"""
                        
                        else:  # reject
                            subject = f"Application Status Update - {current_role}"
                            body = f"""Dear {candidate_name},

Thank you for your interest in our {current_role} position. After careful consideration, we have decided not to proceed with your application at this time.

We appreciate the time you invested in the application process and wish you success in your future endeavors.

Best regards,
EazyAI Recruitment Team"""
                        
                        try:
                            with st.spinner("Sending email..."):
                                if send_email(email_addr, subject, body):
                                    st.success("✅ Email sent successfully!")
                                else:
                                    st.error("❌ Failed to send email - please check email configuration")
                        except Exception as e:
                            st.error(f"❌ Email error: {str(e)}")
                            logger.error(f"Email sending error: {str(e)}")
                    else:
                        st.error("❌ No valid email address available")

                # Download summary button
                summary_key = f"summary_{candidate_id}"
                if st.button(f"📄 Generate Summary", key=summary_key):
                    try:
                        with st.spinner("Generating PDF summary..."):
                            # Ensure all required fields are present for PDF generation
                            pdf_data = {
                                "name": candidate_name,
                                "email": email,
                                "phone": phone,
                                "jd_role": row.get('jd_role', role),
                                "score": safe_get_score('score'),
                                "verdict": verdict,
                                "jd_similarity": safe_get_score('jd_similarity'),
                                "skills_match": safe_get_score('skills_match'),
                                "domain_match": safe_get_score('domain_match'),
                                "experience_match": safe_get_score('experience_match'),
                                "fitment": fitment,
                                "summary_5_lines": row.get('summary_5_lines', 'Summary not available'),
                                "highlights": row.get('highlights', []),
                                "red_flags": row.get('red_flags', []),
                                "missing_gaps": row.get('missing_gaps', []),
                                "reasons_if_rejected": row.get('reasons_if_rejected', []),
                                "recommendation": row.get('recommendation', ''),
                                "recruiter_notes": row.get('recruiter_notes', ''),
                                "fraud_detected": row.get('fraud_detected', False)
                            }
                            
                            pdf_bytes = generate_summary_pdf(pdf_data)
                            summary_name = f"{candidate_name.replace(' ', '_')}_Summary.pdf"
                            
                            # Save to Azure Blob
                            save_summary_to_blob(pdf_bytes, summary_name, AZURE_CONFIG["summaries_container"])
                            
                            # Provide download link
                            b64 = base64.b64encode(pdf_bytes).decode()
                            st.markdown(f'''
                            <a href="data:application/octet-stream;base64,{b64}" 
                               download="{summary_name}" 
                               style="color: #00d4ff; text-decoration: none; font-weight: bold;">
                               📥 Download Summary PDF
                            </a>
                            ''', unsafe_allow_html=True)
                            st.success("✅ Summary generated and saved to Azure Blob!")
                    except Exception as e:
                        st.error(f"❌ Summary generation failed: {str(e)}")
                        logger.error(f"PDF generation error for {candidate_name}: {str(e)}")

            # Interactive elements for status updates and notes
            st.markdown("### 📝 Recruiter Actions")
            
            # Create unique keys for interactive elements
            note_key = f"note_{candidate_id}"
            verdict_key = f"verdict_{candidate_id}"
            
            # Use candidate updates from session state to avoid direct DataFrame modification
            if candidate_id not in st.session_state["candidate_updates"]:
                st.session_state["candidate_updates"][candidate_id] = {
                    "notes": row.get("recruiter_notes", ""),
                    "verdict": row.get("verdict", verdict)
                }

            col_note, col_verdict = st.columns(2)
            
            with col_note:
                new_note = st.text_area(
                    "Recruiter Notes", 
                    value=st.session_state["candidate_updates"][candidate_id]["notes"], 
                    key=note_key,
                    height=100
                )
            
            with col_verdict:
                new_verdict = st.selectbox(
                    "Update Status", 
                    ["shortlist", "review", "reject"],
                    index=["shortlist", "review", "reject"].index(
                        st.session_state["candidate_updates"][candidate_id]["verdict"]
                    ),
                    key=verdict_key
                )

            # Update session state
            st.session_state["candidate_updates"][candidate_id]["notes"] = new_note
            st.session_state["candidate_updates"][candidate_id]["verdict"] = new_verdict
            
            # Apply updates to the main dataframe
            try:
                # Find the row index in the dataframe
                mask = (df['name'] == candidate_name) & (df['email'] == email)
                if mask.any():
                    idx_in_df = df[mask].index[0]
                    df.at[idx_in_df, "recruiter_notes"] = new_note
                    df.at[idx_in_df, "verdict"] = new_verdict
            except Exception as e:
                logger.warning(f"Could not update dataframe for {candidate_name}: {str(e)}")

            st.markdown('</div>', unsafe_allow_html=True)
            st.markdown("---")

    # Process each verdict tab
    for verdict, tab in zip(["shortlist", "review", "reject"], tabs[:3]):
        with tab:
            filtered = df[df["verdict"] == verdict].copy()
            
            if len(filtered) == 0:
                st.info(f"No candidates in {verdict} category")
                continue
            
            # Bulk actions for rejected candidates
            if verdict == "reject" and len(filtered) > 0:
                st.markdown("### 📧 Bulk Actions")
                bulk_email_key = f"bulk_email_{verdict}"
                if st.button(f"📬 Send Bulk Rejection Emails ({len(filtered)} candidates)", 
                           key=bulk_email_key, type="secondary"):
                    sent_count = 0
                    failed_count = 0
                    
                    progress = st.progress(0)
                    status = st.empty()
                    
                    current_role = role if role != "N/A" else "this position"
                    
                    for idx, (_, row) in enumerate(filtered.iterrows()):
                        progress.progress((idx + 1) / len(filtered))
                        candidate_name = row.get('name', 'Candidate')
                        status.text(f"Sending email to {candidate_name}...")
                        
                        email_addr = row.get('email', '').strip()
                        if email_addr and email_addr not in ['N/A', '', 'nan', 'None']:
                            subject = f"Application Status Update - {current_role}"
                            body = f"""Dear {candidate_name},

Thank you for your interest in our {current_role} position. After careful consideration, we have decided not to proceed with your application at this time.

We appreciate the time you invested in the application process and wish you success in your future endeavors.

Best regards,
EazyAI Recruitment Team"""
                            
                            try:
                                if send_email(email_addr, subject, body):
                                    sent_count += 1
                                else:
                                    failed_count += 1
                            except Exception as e:
                                logger.error(f"Bulk email error for {candidate_name}: {str(e)}")
                                failed_count += 1
                        else:
                            failed_count += 1
                            logger.warning(f"No valid email for {candidate_name}")
                    
                    progress.empty()
                    status.empty()
                    
                    if sent_count > 0:
                        st.success(f"✅ Successfully sent {sent_count} rejection emails")
                    if failed_count > 0:
                        st.warning(f"⚠️ Failed to send {failed_count} emails (check email addresses and configuration)")
                
                st.markdown("---")

            # Display candidates
            for idx, (i, row) in enumerate(filtered.iterrows()):
                render_candidate_card(row, verdict, idx)

            # Export functionality
            if len(filtered) > 0:
                st.markdown("### 📤 Export Data")
                export_df = filtered.drop(columns=["resume_text", "embedding"], errors="ignore")
                csv_name = f"{verdict}_candidates_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                
                col1, col2 = st.columns(2)
                with col1:
                    csv_download_key = f"csv_download_{verdict}"
                    csv_data = export_df.to_csv(index=False)
                    st.download_button(
                        "📊 Download CSV", 
                        csv_data,
                        file_name=csv_name,
                        mime="text/csv",
                        key=csv_download_key
                    )
                with col2:
                    blob_save_key = f"blob_save_{verdict}"
                    if st.button(f"☁️ Save to Blob", key=blob_save_key):
                        try:
                            with st.spinner("Saving to Azure Blob..."):
                                save_csv_to_blob(export_df, csv_name, AZURE_CONFIG["csv_container"])
                                st.success("✅ Saved to Azure Blob!")
                        except Exception as e:
                            st.error(f"❌ Failed to save to blob: {str(e)}")
                            logger.error(f"Blob save error: {str(e)}")

    # Analytics Dashboard Tab
    with tabs[3]:
        st.markdown("### 📊 Comprehensive Analytics")
        
        # Performance metrics display
        if "processing_metrics" in st.session_state and st.session_state["processing_metrics"]:
            metrics = st.session_state["processing_metrics"]
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("⏱️ Total Time", f"{metrics['total_time']:.1f}s")
            with col2:
                st.metric("📄 Resumes", metrics['resumes_processed'])
            with col3:
                st.metric("⚡ Avg per Resume", f"{metrics['avg_time_per_resume']:.1f}s")
            with col4:
                throughput = metrics['resumes_processed'] / metrics['total_time'] * 3600 if metrics['total_time'] > 0 else 0
                st.metric("🚀 Throughput", f"{throughput:.0f}/hour")
            
            st.markdown("---")
        
        # Gmail sync analytics
        if gmail_service:
            sync_status = gmail_service.get_status()
            st.markdown("### 📧 Gmail Sync Analytics")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📧 Emails Processed", sync_status.get('emails_processed', 0))
            with col2:
                st.metric("📄 Files Uploaded", sync_status.get('files_uploaded', 0))
            with col3:
                st.metric("❌ Sync Errors", len(sync_status.get('errors', [])))
            with col4:
                last_sync = sync_status.get('last_sync', 'Never')
                st.metric("🕐 Last Sync", last_sync.split()[1] if last_sync != 'Never' and len(last_sync.split()) > 1 else last_sync)
            
            st.markdown("---")
        
        # Summary statistics
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📈 Verdict Distribution")
            verdict_counts = df["verdict"].value_counts()
            
            # Create a proper chart
            chart_data = pd.DataFrame({
                'Verdict': verdict_counts.index,
                'Count': verdict_counts.values
            })
            st.bar_chart(chart_data.set_index('Verdict'))
            
            # Score statistics
            st.markdown("#### 🎯 Score Statistics")
            score_stats = df['score'].describe()
            st.write(f"**Average Score:** {score_stats['mean']:.1f}%")
            st.write(f"**Median Score:** {score_stats['50%']:.1f}%")
            st.write(f"**Highest Score:** {score_stats['max']:.1f}%")
            st.write(f"**Lowest Score:** {score_stats['min']:.1f}%")
            st.write(f"**Standard Deviation:** {score_stats['std']:.1f}%")
        
        with col2:
            st.markdown("#### 📊 Score Distribution by Category")
            score_cols = ["jd_similarity", "skills_match", "domain_match", "experience_match"]
            available_cols = [col for col in score_cols if col in df.columns]
            
            if available_cols:
                score_data = df[available_cols + ['score']].copy()
                score_data.columns = [col.replace('_', ' ').title() for col in available_cols] + ['Final Score']
                
                # Show average scores
                avg_scores = score_data.mean()
                st.dataframe(avg_scores.to_frame('Average Score'), use_container_width=True)
            
            # Top performers
            st.markdown("#### 🏆 Top 5 Candidates")
            display_cols = ['name', 'score', 'verdict']
            if 'jd_similarity' in df.columns:
                display_cols.append('jd_similarity')
            if 'skills_match' in df.columns:
                display_cols.append('skills_match')
            
            available_display_cols = [col for col in display_cols if col in df.columns]
            if available_display_cols:
                top_candidates = df.nlargest(5, 'score')[available_display_cols]
                # Rename columns for display
                column_names = []
                for col in available_display_cols:
                    if col == 'jd_similarity':
                        column_names.append('JD Match')
                    elif col == 'skills_match':
                        column_names.append('Skills Match')
                    else:
                        column_names.append(col.replace('_', ' ').title())
                
                top_candidates.columns = column_names
                st.dataframe(top_candidates, hide_index=True, use_container_width=True)

        # Threshold analysis
        st.markdown("#### 🎯 Threshold Analysis")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            above_shortlist = len(df[df['score'] >= shortlist_thresh])
            st.metric("Above Shortlist Threshold", above_shortlist, f"{(above_shortlist/total_count)*100:.1f}%")
        
        with col2:
            in_review_range = len(df[(df['score'] >= reject_thresh) & (df['score'] < shortlist_thresh)])
            st.metric("In Review Range", in_review_range, f"{(in_review_range/total_count)*100:.1f}%")
        
        with col3:
            below_reject = len(df[df['score'] < reject_thresh])
            st.metric("Below Reject Threshold", below_reject, f"{(below_reject/total_count)*100:.1f}%")

        # Score distribution histogram
        st.markdown("#### 📈 Score Distribution Histogram")
        try:
            score_ranges = pd.cut(df['score'], bins=[0, 20, 40, 60, 80, 100], labels=['0-20', '21-40', '41-60', '61-80', '81-100'])
            score_dist = score_ranges.value_counts().sort_index()
            st.bar_chart(score_dist)
        except Exception as e:
            st.warning(f"Could not generate score histogram: {str(e)}")

        # Detailed data table with enhanced filtering
        st.markdown("#### 🗂️ Complete Dataset")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            verdict_filter = st.multiselect("Filter by Verdict", options=['shortlist', 'review', 'reject'], default=['shortlist', 'review', 'reject'])
        with col2:
            min_score = st.slider("Minimum Score", 0, 100, 0)
        with col3:
            max_score = st.slider("Maximum Score", 0, 100, 100)
        
        # Apply filters
        filtered_df = df[
            (df['verdict'].isin(verdict_filter)) & 
            (df['score'] >= min_score) & 
            (df['score'] <= max_score)
        ]
        
        display_df = filtered_df.drop(columns=["resume_text", "embedding"], errors="ignore")
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Download filtered data
        if len(filtered_df) > 0:
            filtered_csv = filtered_df.drop(columns=["resume_text", "embedding"], errors="ignore").to_csv(index=False)
            st.download_button(
                "📥 Download Filtered Data", 
                filtered_csv,
                file_name=f"filtered_candidates_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

        # Quality control summary
        st.markdown("#### 🚨 Quality Control")
        if 'fraud_detected' in df.columns:
            flagged = df[df["fraud_detected"] == True]
            if not flagged.empty:
                st.error(f"⚠️ Found {len(flagged)} profiles with potential issues:")
                display_cols = ["name"]
                if 'red_flags' in flagged.columns:
                    display_cols.append("red_flags")
                if 'missing_gaps' in flagged.columns:
                    display_cols.append("missing_gaps")
                if 'email' in flagged.columns:
                    display_cols.append("email")
                if 'score' in flagged.columns:
                    display_cols.append("score")
                
                flagged_display = flagged[display_cols]
                column_names = [col.replace('_', ' ').title() for col in display_cols]
                flagged_display.columns = column_names
                st.dataframe(flagged_display, use_container_width=True, hide_index=True)
            else:
                st.success("✅ No fraud or quality issues detected in any profiles")
        else:
            st.info("Quality control data not available")

        # Skills analysis
        if 'skills_match' in df.columns:
            st.markdown("#### 🛠️ Skills Analysis")
            skills_data = df[df['skills_match'] > 0]['skills_match']
            if not skills_data.empty:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Average Skills Match", f"{skills_data.mean():.1f}%")
                    st.metric("High Skills Match (>80%)", len(skills_data[skills_data > 80]))
                with col2:
                    st.metric("Low Skills Match (<40%)", len(skills_data[skills_data < 40]))
                    st.metric("Skills Match Std Dev", f"{skills_data.std():.1f}%")

elif not st.session_state["analysis_done"]:
    # Welcome screen with enhanced features
    st.markdown("""
    <div style="text-align: center; padding: 3rem 2rem; background: rgba(30, 42, 58, 0.6); border-radius: 16px; margin: 2rem 0;">
        <h2>🚀 Welcome to EazyAI Resume Screener</h2>
        <p style="font-size: 1.2rem; color: #94a3b8; margin-bottom: 2rem;">
            Streamline your hiring process with AI-powered resume analysis and automated Gmail integration
        </p>
        <div style="background: rgba(0, 212, 255, 0.1); padding: 1.5rem; border-radius: 12px; margin: 2rem 0; border: 1px solid rgba(0, 212, 255, 0.2);">
            <h3>📧 Email Integration Active</h3>
            <p style="margin-bottom: 1rem;">Send resumes directly to: <strong>eazyai111@gmail.com</strong></p>
            <p style="color: #00d4ff; font-size: 0.9rem;">
                Supported formats: PDF, DOCX, DOC • Auto-sync every time you open the app
            </p>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem; margin-top: 2rem;">
            <div style="background: rgba(0, 212, 255, 0.1); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(0, 212, 255, 0.2);">
                <h4>📋 Step 1</h4>
                <p>Paste your job description in the sidebar</p>
            </div>
            <div style="background: rgba(88, 101, 242, 0.1); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(88, 101, 242, 0.2);">
                <h4>⚙️ Step 2</h4>
                <p>Configure matching thresholds and criteria</p>
            </div>
            <div style="background: rgba(16, 185, 129, 0.1); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(16, 185, 129, 0.2);">
                <h4>📤 Step 3</h4>
                <p>Upload resumes or use Gmail auto-sync</p>
            </div>
            <div style="background: rgba(255, 107, 107, 0.1); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255, 107, 107, 0.2);">
                <h4>🚀 Step 4</h4>
                <p>Click 'Start Analysis' and review results</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced feature highlights
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 🧠 AI-Powered Analysis
        - **Intelligent role extraction** from JD
        - **Semantic similarity matching** using embeddings
        - **Multi-factor scoring** (skills, experience, domain)
        - **Automated fraud detection** and quality control
        - **Three-tier verdict system** (Shortlist/Review/Reject)
        """)
    
    with col2:
        st.markdown("""
        ### ⚡ Advanced Features  
        - **Gmail auto-sync** for resume collection
        - **Multi-format support** (PDF, DOCX, DOC)
        - **Bulk email automation** with custom templates
        - **PDF summary generation** for candidates
        - **Real-time progress tracking** and performance metrics
        """)
    
    with col3:
        st.markdown("""
        ### 📊 Smart Insights
        - **Comprehensive analytics dashboard** with charts
        - **Customizable scoring thresholds** and criteria
        - **Interactive candidate management** with status updates
        - **Advanced filtering** and export capabilities
        - **Gmail sync monitoring** and error tracking
        """)
    
    # Performance expectations
    st.markdown("---")
    st.info("""
    🚀 **Performance Expectations:**
    - **Gmail Auto-Sync**: Automatically processes new resumes when app starts
    - **~17 resumes**: Processed in 45-90 seconds (avg 3-5 seconds per resume)
    - **Multi-format support**: PDF, DOCX, and DOC files supported
    - **Real-time progress**: Live updates during analysis and sync
    """)
    
    st.markdown("---")
    st.success("📧 **Gmail Integration**: Send resumes to **eazyai111@gmail.com** - they'll be automatically processed when you run analysis!")

    st.info("👈 **Get Started:** Fill in the job description and configuration options in the sidebar, then click 'Start Analysis' to begin!")

