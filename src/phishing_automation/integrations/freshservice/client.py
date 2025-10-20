import requests
import json
import tempfile
import shutil
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class FreshServiceError(Exception):
    pass


class FreshServiceClient:
    def __init__(self, domain: str, api_key: str):
        self.domain = domain
        self.api_key = api_key
        self.base_url = f"https://{domain}/api/v2/"
        self.session = requests.Session()
        self.session.auth = (api_key, "X")
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {method} {url}: {e}")
            logger.error(f"Response content: {response.text}")
            raise FreshServiceError(f"HTTP {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {method} {url}: {e}")
            raise FreshServiceError(f"Request failed: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {method} {url}: {e}")
            raise FreshServiceError(f"Invalid JSON response: {str(e)}")
    
    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        logger.info(f"Retrieving ticket {ticket_id}")
        response = self._make_request("GET", f"tickets/{ticket_id}")
        
        # Log response structure for debugging
        logger.info(f"[API DEBUG] Ticket response keys: {list(response.keys())}")
        ticket = response.get("ticket", {})
        
        # Check if conversations are included in ticket response
        if "conversations" in ticket:
            logger.info(f"[API DEBUG] Found conversations in ticket response: {len(ticket.get('conversations', []))} conversations")
        
        # Check for attachments in ticket
        if "attachments" in ticket:
            logger.info(f"[API DEBUG] Found attachments in ticket response: {len(ticket.get('attachments', []))} attachments")
            for att in ticket.get("attachments", []):
                logger.info(f"[API DEBUG]   - Attachment: {att.get('name', 'unnamed')}")
        
        return ticket
    
    def get_ticket_conversations(self, ticket_id: int) -> List[Dict[str, Any]]:
        logger.info(f"Retrieving conversations for ticket {ticket_id}")
        
        # Log the exact endpoint being called
        logger.info(f"[API DEBUG] Calling endpoint: tickets/{ticket_id}/conversations")
        
        try:
            response = self._make_request("GET", f"tickets/{ticket_id}/conversations")
        except FreshServiceError as e:
            logger.warning(f"[API DEBUG] Failed to get conversations: {e}")
            logger.info(f"[API DEBUG] Trying alternative endpoint: tickets/{ticket_id}/notes")
            
            # Try alternative endpoint
            try:
                response = self._make_request("GET", f"tickets/{ticket_id}/notes")
                logger.info(f"[API DEBUG] Notes endpoint successful")
            except:
                logger.error(f"[API DEBUG] Both endpoints failed, returning empty list")
                return []
        
        # Log raw response structure
        logger.info(f"[API DEBUG] Response keys: {list(response.keys())}")
        logger.info(f"[API DEBUG] Raw response (first 500 chars): {str(response)[:500]}")
        
        # Try different possible keys for conversations
        conversations = response.get("conversations", response.get("notes", []))
        
        # Logging for attachments (temporarily using INFO level for debugging)
        logger.info(f"Found {len(conversations)} conversations for ticket {ticket_id}")
        for i, conv in enumerate(conversations):
            if conv.get("attachments"):
                logger.info(f"Conversation {i+1} (ID: {conv.get('id')}) has {len(conv['attachments'])} attachments:")
                for att in conv['attachments']:
                    logger.info(f"  - '{att.get('name', 'unnamed')}' (type: {att.get('content_type', 'unknown')}, size: {att.get('size', 0)} bytes)")
            else:
                logger.info(f"Conversation {i+1} (ID: {conv.get('id')}) has no attachments")
        
        return conversations
    
    def add_note_to_ticket(self, ticket_id: int, note: str, private: bool = True) -> Dict[str, Any]:
        logger.info(f"Adding note to ticket {ticket_id}")
        
        data = {
            "body": note,
            "private": private,
            "incoming": False
        }
        
        response = self._make_request("POST", f"tickets/{ticket_id}/conversations", 
                                    data=json.dumps(data))
        return response.get("conversation", {})
    
    def update_ticket(self, ticket_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"Updating ticket {ticket_id}")
        
        data = {"ticket": updates}
        response = self._make_request("PUT", f"tickets/{ticket_id}", 
                                    data=json.dumps(data))
        return response.get("ticket", {})
    
    def search_tickets(self, query: str) -> List[Dict[str, Any]]:
        logger.info(f"Searching tickets with query: {query}")
        params = {"query": query}
        response = self._make_request("GET", "search/tickets", params=params)
        return response.get("results", [])
    
    def get_ticket_attachments(self, ticket_id: int) -> List[Dict[str, Any]]:
        logger.info(f"Getting attachments for ticket {ticket_id}")
        conversations = self.get_ticket_conversations(ticket_id)
        attachments = []
        
        for conversation in conversations:
            if conversation.get("attachments"):
                attachments.extend(conversation["attachments"])
        
        return attachments
    
    def download_attachment(self, attachment_id: int) -> bytes:
        logger.info(f"Downloading attachment {attachment_id}")
        url = f"{self.base_url}attachments/{attachment_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        return response.content
    
    def download_eml_attachment(self, attachment_info: Dict[str, Any], save_path: Path) -> Path:
        """Download .eml attachment safely to specified path"""
        attachment_id = attachment_info.get('id')
        attachment_name = attachment_info.get('name', 'unknown.eml')
        
        logger.info(f"Downloading .eml attachment: {attachment_name} (ID: {attachment_id})")
        
        try:
            # Download attachment bytes
            attachment_bytes = self.download_attachment(attachment_id)
            
            # Ensure save directory exists
            save_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to file safely
            with open(save_path, 'wb') as f:
                f.write(attachment_bytes)
            
            logger.info(f"Successfully downloaded .eml attachment to: {save_path}")
            logger.info(f"File size: {len(attachment_bytes)} bytes")
            
            return save_path
            
        except Exception as e:
            logger.error(f"Failed to download .eml attachment {attachment_name}: {e}")
            raise FreshServiceError(f"EML download failed: {e}")
    
    def find_and_download_eml(self, ticket_id: int, ticket_folder: Path) -> Optional[Path]:
        """Find and download the .eml attachment from a phishing ticket"""
        try:
            logger.info(f"Looking for .eml attachment in ticket {ticket_id}")
            
            # Get all conversations to find attachments
            conversations = self.get_ticket_conversations(ticket_id)
            
            for conversation in conversations:
                attachments = conversation.get('attachments', [])
                
                for attachment in attachments:
                    attachment_name = attachment.get('name', '').lower()
                    
                    # Look for .eml files or phish_alert files
                    if (attachment_name.endswith('.eml') or 
                        'phish_alert' in attachment_name):
                        
                        # Found the .eml file - download it
                        original_name = attachment.get('name', 'phishing_email.eml')
                        save_path = ticket_folder / original_name
                        
                        downloaded_path = self.download_eml_attachment(attachment, save_path)
                        
                        logger.info(f"Found and downloaded .eml attachment: {original_name}")
                        return downloaded_path
            
            logger.warning(f"No .eml attachment found in ticket {ticket_id}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to find/download .eml attachment from ticket {ticket_id}: {e}")
            raise FreshServiceError(f"EML search failed: {e}")
    
    def download_attachment_securely(self, attachment_url: str, attachment_name: str, save_folder: Path) -> Tuple[Optional[Path], Optional[Path]]:
        """
        Securely download attachment to temp directory, save parsed data to permanent location
        Returns: (temp_file_path, parsed_data_path) - temp path will be auto-deleted
        """
        try:
            logger.info(f"[SECURE DOWNLOAD] Starting secure download of {attachment_name}")
            
            # Security check: Limit file size (10MB max for .eml files)
            MAX_SIZE = 10 * 1024 * 1024  # 10MB
            
            # Create temporary directory for secure handling
            temp_dir = tempfile.mkdtemp(prefix="phish_scan_")
            temp_file_path = Path(temp_dir) / "suspicious.eml"
            
            logger.info(f"[SECURE DOWNLOAD] Using temp directory: {temp_dir}")
            
            try:
                # Download with size limit
                logger.info(f"[SECURE DOWNLOAD] Downloading from URL (max {MAX_SIZE} bytes)")
                response = requests.get(attachment_url, stream=True, timeout=30)
                response.raise_for_status()
                
                # Check content length
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > MAX_SIZE:
                    raise FreshServiceError(f"File too large: {content_length} bytes (max: {MAX_SIZE})")
                
                # Download to temp file with size limit
                downloaded_size = 0
                with open(temp_file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        downloaded_size += len(chunk)
                        if downloaded_size > MAX_SIZE:
                            raise FreshServiceError(f"Download exceeded size limit: {MAX_SIZE} bytes")
                        f.write(chunk)
                
                logger.info(f"[SECURE DOWNLOAD] Downloaded {downloaded_size} bytes to temp file")
                
                # Create permanent location for PARSED data only (not the .eml)
                parsed_data_path = save_folder / f"{attachment_name}.parsed.txt"
                
                logger.info(f"[SECURE DOWNLOAD] Temp file ready at: {temp_file_path}")
                logger.info(f"[SECURE DOWNLOAD] Parsed data will be saved to: {parsed_data_path}")
                
                return temp_file_path, parsed_data_path
                
            except Exception as e:
                # Clean up temp directory on error
                logger.error(f"[SECURE DOWNLOAD] Download failed, cleaning up temp directory")
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise
                
        except Exception as e:
            logger.error(f"[SECURE DOWNLOAD] Secure download failed: {e}")
            return None, None
    
    def cleanup_temp_directory(self, temp_path: Path):
        """Clean up temporary directory after processing"""
        try:
            if temp_path and temp_path.exists():
                temp_dir = temp_path.parent
                logger.info(f"[SECURE CLEANUP] Removing temp directory: {temp_dir}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.info(f"[SECURE CLEANUP] Temp directory removed successfully")
        except Exception as e:
            logger.warning(f"[SECURE CLEANUP] Failed to cleanup temp directory: {e}")
    
    def validate_connection(self) -> bool:
        try:
            self._make_request("GET", "agents/me")
            logger.info("FreshService connection validated successfully")
            return True
        except FreshServiceError:
            logger.error("FreshService connection validation failed")
            return False