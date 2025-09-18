import imaplib
import email
import threading
import time
import logging
from email.header import decode_header
from azure.storage.blob import BlobServiceClient
from typing import Dict, List, Tuple, Optional
import streamlit as st

# Configure logging
logger = logging.getLogger(__name__)

# Gmail credentials
EMAIL = "eazyhire111@gmail.com"
PASSWORD = "vdla vduu aepn lbng"  # Your App Password
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

class GmailToAzureService:
    def __init__(self, azure_connection_string: str, container_name: str = "resumes"):
        self.azure_connection_string = azure_connection_string
        self.container_name = container_name
        self.is_running = False
        self.last_check = None
        self.status = {
            "last_sync": None,
            "emails_processed": 0,
            "files_uploaded": 0,
            "errors": [],
            "is_active": False
        }
        
    def connect_to_gmail(self) -> Optional[imaplib.IMAP4_SSL]:
        """Connect to Gmail with error handling"""
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(EMAIL, PASSWORD)
            return mail
        except Exception as e:
            logger.error(f"Gmail connection failed: {str(e)}")
            self.status["errors"].append(f"Gmail connection failed: {str(e)}")
            return None
    
    def connect_to_azure(self) -> Optional[BlobServiceClient]:
        """Connect to Azure Blob Storage"""
        try:
            blob_service_client = BlobServiceClient.from_connection_string(self.azure_connection_string)
            # Test connection by getting container properties
            container_client = blob_service_client.get_container_client(self.container_name)
            container_client.get_container_properties()
            return blob_service_client
        except Exception as e:
            logger.error(f"Azure connection failed: {str(e)}")
            self.status["errors"].append(f"Azure connection failed: {str(e)}")
            return None
    
    def process_unread_emails(self) -> Dict[str, any]:
        """Process unread emails and extract attachments"""
        self.status["is_active"] = True
        self.status["errors"] = []  # Clear previous errors
        processed_count = 0
        uploaded_count = 0
        
        try:
            # Connect to Gmail
            mail = self.connect_to_gmail()
            if not mail:
                return self.get_status()
            
            # Connect to Azure
            blob_service_client = self.connect_to_azure()
            if not blob_service_client:
                mail.logout()
                return self.get_status()
            
            container_client = blob_service_client.get_container_client(self.container_name)
            
            # Select inbox and search for unread emails
            mail.select("inbox")
            status, messages = mail.search(None, '(UNSEEN)')
            email_ids = messages[0].split()
            
            logger.info(f"Found {len(email_ids)} unread emails")
            
            if len(email_ids) == 0:
                self.status["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.status["is_active"] = False
                mail.logout()
                return self.get_status()
            
            # Process each email
            for e_id in email_ids:
                try:
                    _, msg_data = mail.fetch(e_id, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Decode subject
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")
                    
                    logger.info(f"Processing email: {subject}")
                    processed_count += 1
                    
                    # Process attachments
                    for part in msg.walk():
                        if part.get_content_maintype() == "multipart":
                            continue
                        if part.get("Content-Disposition") is None:
                            continue
                        
                        filename = part.get_filename()
                        if filename:
                            # Decode filename
                            filename = decode_header(filename)[0][0]
                            if isinstance(filename, bytes):
                                filename = filename.decode()
                            
                            # Check if it's a supported resume format (PDF, DOCX, DOC)
                            supported_extensions = ['.pdf', '.docx', '.doc']
                            file_extension = ''.join(filename.lower().split('.')[1:])  # Handle multiple dots
                            
                            if any(filename.lower().endswith(ext) for ext in supported_extensions):
                                try:
                                    payload = part.get_payload(decode=True)
                                    
                                    # Ensure filename has proper extension
                                    if not any(filename.lower().endswith(ext) for ext in supported_extensions):
                                        # Add .pdf as default if no extension
                                        filename += '.pdf'
                                    
                                    blob_client = container_client.get_blob_client(filename)
                                    blob_client.upload_blob(payload, overwrite=True)
                                    
                                    logger.info(f"Uploaded '{filename}' ({file_extension.upper()}) to Azure Blob Storage")
                                    uploaded_count += 1
                                    
                                except Exception as upload_error:
                                    error_msg = f"Failed to upload {filename}: {str(upload_error)}"
                                    logger.error(error_msg)
                                    self.status["errors"].append(error_msg)
                            else:
                                logger.info(f"Skipping unsupported file format: {filename}")
                    
                    # Mark email as read
                    mail.store(e_id, "+FLAGS", "\\Seen")
                    
                except Exception as email_error:
                    error_msg = f"Error processing email {e_id}: {str(email_error)}"
                    logger.error(error_msg)
                    self.status["errors"].append(error_msg)
                    continue
            
            # Update status
            self.status["emails_processed"] = processed_count
            self.status["files_uploaded"] = uploaded_count
            self.status["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            mail.logout()
            logger.info(f"Gmail sync completed: {processed_count} emails, {uploaded_count} files uploaded")
            
        except Exception as e:
            error_msg = f"Gmail sync failed: {str(e)}"
            logger.error(error_msg)
            self.status["errors"].append(error_msg)
        
        finally:
            self.status["is_active"] = False
        
        return self.get_status()
    
    def get_status(self) -> Dict[str, any]:
        """Get current sync status"""
        return self.status.copy()
    
    def start_background_sync(self) -> None:
        """Start background Gmail sync in a separate thread"""
        if self.is_running:
            return
        
        def background_task():
            self.is_running = True
            try:
                self.process_unread_emails()
            except Exception as e:
                logger.error(f"Background sync error: {str(e)}")
            finally:
                self.is_running = False
        
        thread = threading.Thread(target=background_task, daemon=True)
        thread.start()
    
    def sync_now(self) -> Dict[str, any]:
        """Manually trigger sync and return status"""
        if self.is_running:
            return {"error": "Sync already in progress"}
        
        return self.process_unread_emails()

# Global service instance (will be initialized in app.py)
gmail_service = None

def initialize_gmail_service(azure_connection_string: str) -> GmailToAzureService:
    """Initialize the Gmail service"""
    global gmail_service
    gmail_service = GmailToAzureService(azure_connection_string)
    return gmail_service

def get_gmail_service() -> Optional[GmailToAzureService]:
    """Get the Gmail service instance"""
    return gmail_service

def auto_sync_gmail_on_startup(azure_connection_string: str) -> GmailToAzureService:
    """Initialize and start Gmail sync when app starts"""
    service = initialize_gmail_service(azure_connection_string)
    service.start_background_sync()
    return service