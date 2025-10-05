import imaplib
import email
import threading
import time
import logging
from email.header import decode_header
from email import policy
from email.parser import BytesParser
from azure.storage.blob import BlobServiceClient
from typing import Dict, List, Tuple, Optional
import streamlit as st
import io

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
            "eml_files_processed": 0,
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
            container_client = blob_service_client.get_container_client(self.container_name)
            container_client.get_container_properties()
            return blob_service_client
        except Exception as e:
            logger.error(f"Azure connection failed: {str(e)}")
            self.status["errors"].append(f"Azure connection failed: {str(e)}")
            return None
    
    def extract_attachments_from_eml(self, eml_bytes: bytes, eml_filename: str, 
                                    container_client) -> int:
        """
        Extract resume attachments from .eml file
        Returns count of resumes uploaded
        """
        uploaded_count = 0
        
        try:
            # Parse the .eml file
            msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
            
            logger.info(f"Processing .eml file: {eml_filename}")
            
            # Iterate through all parts of the email
            for part in msg.walk():
                # Skip multipart containers
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Check if this part has a filename (attachment)
                filename = part.get_filename()
                
                if filename:
                    # Decode filename if needed
                    if isinstance(filename, bytes):
                        filename = filename.decode('utf-8', errors='ignore')
                    else:
                        # Handle encoded filenames
                        try:
                            decoded_parts = decode_header(filename)
                            filename_parts = []
                            for content, encoding in decoded_parts:
                                if isinstance(content, bytes):
                                    if encoding:
                                        filename_parts.append(content.decode(encoding))
                                    else:
                                        filename_parts.append(content.decode('utf-8', errors='ignore'))
                                else:
                                    filename_parts.append(content)
                            filename = ''.join(filename_parts)
                        except Exception as e:
                            logger.warning(f"Could not decode filename: {str(e)}")
                    
                    # Check if it's a supported resume format
                    supported_extensions = ['.pdf', '.docx', '.doc']
                    
                    if any(filename.lower().endswith(ext) for ext in supported_extensions):
                        try:
                            # Get the attachment payload
                            payload = part.get_payload(decode=True)
                            
                            if payload:
                                # Clean filename for Azure blob
                                clean_filename = self.sanitize_filename(filename)
                                
                                # Upload to Azure
                                blob_client = container_client.get_blob_client(clean_filename)
                                blob_client.upload_blob(payload, overwrite=True)
                                
                                logger.info(f"Uploaded '{clean_filename}' from .eml file '{eml_filename}'")
                                uploaded_count += 1
                        
                        except Exception as upload_error:
                            error_msg = f"Failed to upload {filename} from {eml_filename}: {str(upload_error)}"
                            logger.error(error_msg)
                            self.status["errors"].append(error_msg)
                    else:
                        logger.debug(f"Skipping non-resume attachment: {filename}")
        
        except Exception as e:
            error_msg = f"Failed to process .eml file {eml_filename}: {str(e)}"
            logger.error(error_msg)
            self.status["errors"].append(error_msg)
        
        return uploaded_count
    
    def sanitize_filename(self, filename: str) -> str:
        """Clean filename for Azure blob storage"""
        # Remove or replace invalid characters
        import re
        # Replace spaces and special characters
        filename = re.sub(r'[^\w\s.-]', '_', filename)
        filename = re.sub(r'\s+', '_', filename)
        
        # Ensure it has a valid extension
        supported_extensions = ['.pdf', '.docx', '.doc']
        if not any(filename.lower().endswith(ext) for ext in supported_extensions):
            filename += '.pdf'  # Default extension
        
        return filename
    
    def process_unread_emails(self) -> Dict[str, any]:
        """Process unread emails and extract attachments (including from .eml files)"""
        self.status["is_active"] = True
        self.status["errors"] = []
        processed_count = 0
        uploaded_count = 0
        eml_processed = 0
        
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
                            decoded = decode_header(filename)[0]
                            filename = decoded[0]
                            if isinstance(filename, bytes):
                                filename = filename.decode(decoded[1] or 'utf-8', errors='ignore')
                            
                            payload = part.get_payload(decode=True)
                            
                            # Check if it's an .eml file
                            if filename.lower().endswith('.eml'):
                                logger.info(f"Found .eml file: {filename}")
                                eml_processed += 1
                                
                                # Extract resumes from .eml file
                                eml_uploads = self.extract_attachments_from_eml(
                                    payload, filename, container_client
                                )
                                uploaded_count += eml_uploads
                                
                            # Check if it's a supported resume format
                            elif any(filename.lower().endswith(ext) for ext in ['.pdf', '.docx', '.doc']):
                                try:
                                    clean_filename = self.sanitize_filename(filename)
                                    
                                    blob_client = container_client.get_blob_client(clean_filename)
                                    blob_client.upload_blob(payload, overwrite=True)
                                    
                                    logger.info(f"Uploaded '{clean_filename}' to Azure Blob Storage")
                                    uploaded_count += 1
                                    
                                except Exception as upload_error:
                                    error_msg = f"Failed to upload {filename}: {str(upload_error)}"
                                    logger.error(error_msg)
                                    self.status["errors"].append(error_msg)
                            else:
                                logger.debug(f"Skipping unsupported file: {filename}")
                    
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
            self.status["eml_files_processed"] = eml_processed
            self.status["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            mail.logout()
            logger.info(f"Gmail sync completed: {processed_count} emails, {uploaded_count} files uploaded ({eml_processed} from .eml files)")
            
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

# Global service instance
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
