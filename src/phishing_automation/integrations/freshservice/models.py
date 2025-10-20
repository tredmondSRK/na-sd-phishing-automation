import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class TicketStatus(Enum):
    OPEN = 2
    PENDING = 3
    RESOLVED = 4
    CLOSED = 5


class TicketPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    URGENT = 4


class Ticket(BaseModel):
    id: int
    subject: str
    description: str = ""
    description_text: str = ""
    status: int
    priority: int = 1
    type: str = ""
    source: int = 2
    requester_id: int
    responder_id: Optional[int] = None
    group_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    due_by: Optional[datetime] = None
    fr_due_by: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)  # Add attachments field
    
    @property
    def status_name(self) -> str:
        status_map = {
            2: "Open",
            3: "Pending", 
            4: "Resolved",
            5: "Closed"
        }
        return status_map.get(self.status, "Unknown")
    
    @property
    def priority_name(self) -> str:
        priority_map = {
            1: "Low",
            2: "Medium",
            3: "High", 
            4: "Urgent"
        }
        return priority_map.get(self.priority, "Unknown")
    
    def is_phishing_related(self) -> bool:
        phishing_keywords = [
            "phish", "suspicious", "spam", "malicious", 
            "security", "fraud", "scam", "fake"
        ]
        
        text_to_check = f"{self.subject} {self.description_text}".lower()
        return any(keyword in text_to_check for keyword in phishing_keywords)


class TicketConversation(BaseModel):
    id: int
    body: str
    body_text: str = ""
    incoming: bool = True
    private: bool = False
    user_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    
    def has_email_content(self) -> bool:
        email_indicators = ["from:", "to:", "subject:", "message-id:", "received:"]
        return any(indicator in self.body_text.lower() for indicator in email_indicators)


class AttachmentInfo(BaseModel):
    id: int
    name: str
    size: int
    content_type: str = ""
    download_url: Optional[str] = None


class PhishingTicketData(BaseModel):
    ticket: Ticket
    conversations: List[TicketConversation]
    reporter_email: Optional[str] = None
    suspicious_email_subject: Optional[str] = None
    suspicious_email_sender: Optional[str] = None
    suspicious_email_content: Optional[str] = None
    
    # New fields for .eml attachment handling
    eml_attachment: Optional[AttachmentInfo] = None
    user_comments: Optional[str] = None
    report_disposition: Optional[str] = None  # "Phish", etc.
    
    def extract_phish_alert_details(self):
        """Extract details from phish alert ticket format"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"[EXTRACT] Starting extract_phish_alert_details with {len(self.conversations)} conversations")
        
        # Look for the first conversation (ticket description) that contains phish alert format
        for i, conversation in enumerate(self.conversations):
            logger.info(f"[EXTRACT] Checking conversation {i+1}")
            
            if self._is_phish_alert_format(conversation.body_text):
                logger.info(f"[EXTRACT] Found phish alert format in conversation {i+1}")
                self._parse_phish_alert_content(conversation.body_text)
                
                # Extract .eml attachment from this conversation
                logger.info(f"[EXTRACT] Looking for .eml attachment in conversation {i+1}")
                logger.info(f"[EXTRACT] Conversation has {len(conversation.attachments)} attachments")
                
                eml_attachment = self._find_eml_attachment(conversation.attachments)
                if eml_attachment:
                    logger.info(f"[EXTRACT] [FOUND] Set eml_attachment: {eml_attachment.name}")
                    self.eml_attachment = eml_attachment
                else:
                    logger.warning(f"[EXTRACT] [NOT FOUND] No .eml attachment found in conversation {i+1}")
                
                break
            else:
                logger.info(f"[EXTRACT] Conversation {i+1} does not match phish alert format")
    
    def _is_phish_alert_format(self, content: str) -> bool:
        """Check if content matches phish alert format"""
        phish_alert_indicators = [
            "Reporter:", 
            "Disposition:", 
            "User Comments:",
            "phish_alert_sp2"
        ]
        return any(indicator in content for indicator in phish_alert_indicators)
    
    def _parse_phish_alert_content(self, content: str):
        """Parse phish alert ticket content"""
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract reporter email: "Reporter: Name <email@domain>"
            if line.startswith('Reporter:'):
                reporter_match = re.search(r'<([^>]+)>', line)
                if reporter_match:
                    self.reporter_email = reporter_match.group(1).lower()
            
            # Extract disposition: "Disposition: Phish"
            elif line.startswith('Disposition:'):
                self.report_disposition = line.replace('Disposition:', '').strip()
            
            # Extract user comments (everything after "User Comments:" until "EXTERNAL" or attachments)
            elif 'User Comments:' in line:
                # Find the start of user comments section
                user_comments_start = content.find('User Comments:')
                if user_comments_start != -1:
                    # Extract text after "User Comments:" until "EXTERNAL" or "Attachments"
                    comments_section = content[user_comments_start + len('User Comments:'):]
                    
                    # Stop at "EXTERNAL" or "Attachments" markers
                    for stop_marker in ['EXTERNAL', 'Attachments (']:
                        if stop_marker in comments_section:
                            comments_section = comments_section[:comments_section.find(stop_marker)]
                    
                    self.user_comments = comments_section.strip()
                    if self.user_comments == "":
                        self.user_comments = None
    
    def _find_eml_attachment(self, attachments: List[Dict[str, Any]]) -> Optional[AttachmentInfo]:
        """Find the .eml attachment in the list"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"[ATTACHMENT SEARCH] Searching for .eml attachment in {len(attachments)} attachments")
        logger.info(f"[ATTACHMENT SEARCH] Raw attachments data: {attachments}")
        
        for attachment in attachments:
            attachment_name = attachment.get('name', '')
            attachment_type = attachment.get('content_type', '')
            attachment_size = attachment.get('size', 0)
            
            logger.info(f"[ATTACHMENT SEARCH] Checking attachment: '{attachment_name}' (type: {attachment_type}, size: {attachment_size} bytes)")
            
            # Check conditions separately for better debugging
            ends_with_eml = attachment_name.lower().endswith('.eml')
            has_phish_alert = 'phish_alert' in attachment_name.lower()
            
            logger.info(f"[ATTACHMENT SEARCH]   - Ends with .eml? {ends_with_eml}")
            logger.info(f"[ATTACHMENT SEARCH]   - Contains 'phish_alert'? {has_phish_alert}")
            
            # Look for .eml files or phish_alert files (case-insensitive)
            if ends_with_eml or has_phish_alert:
                logger.info(f"[ATTACHMENT SEARCH] [FOUND] .eml attachment: '{attachment_name}'")
                
                attachment_info = AttachmentInfo(
                    id=attachment.get('id', 0),
                    name=attachment.get('name', ''),
                    size=attachment.get('size', 0),
                    content_type=attachment.get('content_type', ''),
                    download_url=attachment.get('attachment_url')
                )
                logger.info(f"[ATTACHMENT SEARCH] Created AttachmentInfo: {attachment_info}")
                return attachment_info
        
        # Log all attachment names if none matched
        attachment_names = [a.get('name', 'unnamed') for a in attachments]
        logger.warning(f"[ATTACHMENT SEARCH] [NOT FOUND] No .eml attachment found. Available attachments: {attachment_names}")
        
        return None
    
    def extract_ticket_attachments(self):
        """Extract attachments directly from ticket level"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"[EXTRACT] Checking for ticket-level attachments")
        
        if self.ticket.attachments:
            logger.info(f"[EXTRACT] Found {len(self.ticket.attachments)} attachments at ticket level")
            
            # Look for .eml attachment in ticket attachments
            eml_attachment = self._find_eml_attachment(self.ticket.attachments)
            if eml_attachment:
                logger.info(f"[EXTRACT] [FOUND] Set eml_attachment from ticket level: {eml_attachment.name}")
                self.eml_attachment = eml_attachment
                return True
            else:
                logger.warning(f"[EXTRACT] No .eml found in ticket-level attachments")
        else:
            logger.info(f"[EXTRACT] No attachments at ticket level")
        
        return False
    
    def extract_email_details(self):
        """Extract email details - check ticket level first, then conversations"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"[EXTRACT] Starting email detail extraction")
        
        # First try ticket-level attachments (FreshService puts them here)
        if self.extract_ticket_attachments():
            logger.info(f"[EXTRACT] Found .eml at ticket level, skipping conversation check")
            return
        
        # If not found at ticket level, check conversations
        logger.info(f"[EXTRACT] No .eml at ticket level, checking conversations")
        self.extract_phish_alert_details()
        
        # Fallback to old parsing if phish alert format not detected
        if not self.reporter_email:
            for conversation in self.conversations:
                if conversation.has_email_content():
                    lines = conversation.body_text.split('\n')
                    
                    for line in lines:
                        line = line.strip().lower()
                        if line.startswith('from:'):
                            self.suspicious_email_sender = line.replace('from:', '').strip()
                        elif line.startswith('subject:'):
                            self.suspicious_email_subject = line.replace('subject:', '').strip()
                    
                    self.suspicious_email_content = conversation.body_text
                    break
    
    def has_eml_attachment(self) -> bool:
        """Check if ticket has an .eml attachment"""
        return self.eml_attachment is not None
    
    def get_eml_attachment_name(self) -> Optional[str]:
        """Get the name of the .eml attachment"""
        return self.eml_attachment.name if self.eml_attachment else None