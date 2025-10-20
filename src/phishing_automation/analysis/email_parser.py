import logging
import email
import email.utils
import re
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from email.message import EmailMessage

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class EmailAttachmentInfo(BaseModel):
    """Information about email attachments (NOT the content itself)"""
    filename: Optional[str] = None
    content_type: str = ""
    size_bytes: Optional[int] = None
    content_disposition: Optional[str] = None
    is_potentially_malicious: bool = False


class ParsedEmailData(BaseModel):
    """Safely parsed email data from .eml file"""
    # Essential fields for mail trace
    sender: str = ""
    sender_display_name: str = ""
    recipients: List[str] = Field(default_factory=list)
    cc_recipients: List[str] = Field(default_factory=list)
    bcc_recipients: List[str] = Field(default_factory=list)
    subject: str = ""
    date_received: Optional[datetime] = None
    message_id: str = ""

    # Additional headers
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[str] = None
    
    # Content (sanitized)
    text_body: str = ""
    html_body: str = ""
    
    # Attachment information (metadata only)
    attachments: List[EmailAttachmentInfo] = Field(default_factory=list)
    has_attachments: bool = False
    
    # Security indicators
    has_suspicious_headers: bool = False
    has_external_links: bool = False
    has_url_shorteners: bool = False
    has_html_forms: bool = False
    has_subject_trick: bool = False
    suspicious_keywords_found: List[str] = Field(default_factory=list)
    financial_keywords_found: List[str] = Field(default_factory=list)
    credential_keywords_found: List[str] = Field(default_factory=list)
    time_pressure_keywords_found: List[str] = Field(default_factory=list)
    
    # Raw headers (for investigation)
    all_headers: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class EmailParsingError(Exception):
    pass


class EmailParser:
    """Safely parse .eml files without executing any content"""

    SUSPICIOUS_KEYWORDS = [
        "urgent", "immediate", "verify", "suspend", "click here", "act now",
        "congratulations", "winner", "prize", "free", "limited time",
        "phishing", "scam", "update payment", "confirm identity"
    ]

    FINANCIAL_KEYWORDS = [
        "wire transfer", "gift card", "urgent payment", "bank details",
        "invoice attached", "payment required", "send money", "financial request",
        "purchase order", "payroll", "direct deposit", "account number",
        "routing number", "bank account", "payment information"
    ]

    CREDENTIAL_KEYWORDS = [
        "verify your password", "update payment info", "confirm your account",
        "validate credentials", "security check required", "verify identity",
        "update your information", "confirm payment method", "re-enter password",
        "account verification", "security alert", "unusual activity"
    ]

    TIME_PRESSURE_KEYWORDS = [
        "within 24 hours", "expires today", "immediate action", "account will be closed",
        "within the next", "urgent action required", "respond immediately",
        "time sensitive", "act quickly", "expires soon", "limited time offer"
    ]

    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "shorte.st", "bc.vc"
    ]

    MALICIOUS_EXTENSIONS = [
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
        ".jar", ".zip", ".rar", ".7z", ".iso", ".img", ".dmg"
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_eml_file(self, eml_file_path: Path) -> ParsedEmailData:
        """Safely parse .eml file and extract metadata"""
        try:
            self.logger.info(f"Parsing .eml file: {eml_file_path}")
            
            if not eml_file_path.exists():
                raise EmailParsingError(f"EML file not found: {eml_file_path}")
            
            # Read the .eml file safely
            with open(eml_file_path, 'rb') as f:
                raw_email = f.read()
            
            # Parse using Python's email library (safe parsing)
            msg = email.message_from_bytes(raw_email)
            
            # Extract all data safely
            parsed_data = self._extract_email_data(msg)
            
            # Perform security analysis
            self._analyze_security_indicators(parsed_data, msg)
            
            self.logger.info(f"Successfully parsed email from: {parsed_data.sender}")
            self.logger.info(f"Subject: {parsed_data.subject}")
            self.logger.info(f"Recipients: {len(parsed_data.recipients)}")
            
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Failed to parse .eml file {eml_file_path}: {e}")
            raise EmailParsingError(f"Email parsing failed: {e}")
    
    def parse_eml_bytes(self, eml_bytes: bytes) -> ParsedEmailData:
        """Safely parse .eml from bytes data"""
        try:
            self.logger.info("Parsing .eml from bytes data")
            
            # Parse using Python's email library
            msg = email.message_from_bytes(eml_bytes)
            
            # Extract all data safely
            parsed_data = self._extract_email_data(msg)
            
            # Perform security analysis
            self._analyze_security_indicators(parsed_data, msg)
            
            self.logger.info(f"Successfully parsed email from: {parsed_data.sender}")
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Failed to parse .eml bytes: {e}")
            raise EmailParsingError(f"Email parsing from bytes failed: {e}")
    
    def _extract_email_data(self, msg: EmailMessage) -> ParsedEmailData:
        """Extract all relevant data from email message"""
        parsed_data = ParsedEmailData()

        # Extract basic headers with display name
        from_header = msg.get('From', '')
        parsed_data.sender = self._clean_email_address(from_header)
        parsed_data.sender_display_name = self._extract_display_name(from_header)
        parsed_data.subject = self._decode_header(msg.get('Subject', ''))
        parsed_data.message_id = msg.get('Message-ID', '')
        parsed_data.reply_to = self._clean_email_address(msg.get('Reply-To', ''))
        parsed_data.return_path = self._clean_email_address(msg.get('Return-Path', ''))
        parsed_data.in_reply_to = msg.get('In-Reply-To', '')
        parsed_data.references = msg.get('References', '')
        
        # Parse recipients
        to_header = msg.get('To', '')
        cc_header = msg.get('CC', '')
        bcc_header = msg.get('BCC', '')
        
        parsed_data.recipients = self._parse_recipient_list(to_header)
        parsed_data.cc_recipients = self._parse_recipient_list(cc_header)
        parsed_data.bcc_recipients = self._parse_recipient_list(bcc_header)
        
        # Parse date
        date_header = msg.get('Date', '')
        if date_header:
            parsed_data.date_received = self._parse_email_date(date_header)
        
        # Extract body content safely
        parsed_data.text_body, parsed_data.html_body = self._extract_body_content(msg)
        
        # Extract attachment information (metadata only)
        parsed_data.attachments = self._extract_attachment_info(msg)
        parsed_data.has_attachments = len(parsed_data.attachments) > 0
        
        # Store all headers for investigation
        parsed_data.all_headers = dict(msg.items())
        
        return parsed_data
    
    def _clean_email_address(self, email_str: str) -> str:
        """Extract and clean email address from header"""
        if not email_str:
            return ""

        # Use email.utils to parse properly
        name, addr = email.utils.parseaddr(email_str)
        return addr.strip().lower()

    def _extract_display_name(self, email_str: str) -> str:
        """Extract display name from email header"""
        if not email_str:
            return ""

        # Use email.utils to parse properly
        name, addr = email.utils.parseaddr(email_str)
        return name.strip() if name else ""
    
    def _parse_recipient_list(self, recipients_str: str) -> List[str]:
        """Parse comma-separated list of recipients"""
        if not recipients_str:
            return []
        
        recipients = []
        # Split by comma and parse each
        for recipient in recipients_str.split(','):
            addr = self._clean_email_address(recipient.strip())
            if addr:
                recipients.append(addr)
        
        return recipients
    
    def _decode_header(self, header_value: str) -> str:
        """Safely decode email header value"""
        if not header_value:
            return ""
        
        try:
            decoded_parts = email.header.decode_header(header_value)
            decoded_str = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_str += part.decode(encoding, errors='ignore')
                    else:
                        decoded_str += part.decode('utf-8', errors='ignore')
                else:
                    decoded_str += str(part)
            
            return decoded_str.strip()
        except Exception as e:
            self.logger.warning(f"Failed to decode header '{header_value}': {e}")
            return str(header_value)
    
    def _parse_email_date(self, date_str: str) -> Optional[datetime]:
        """Parse email date header"""
        try:
            # Use email.utils to parse date properly
            parsed_time = email.utils.parsedate_tz(date_str)
            if parsed_time:
                timestamp = email.utils.mktime_tz(parsed_time)
                return datetime.fromtimestamp(timestamp)
        except Exception as e:
            self.logger.warning(f"Failed to parse date '{date_str}': {e}")
        
        return None
    
    def _extract_body_content(self, msg: EmailMessage) -> Tuple[str, str]:
        """Extract text and HTML body content safely"""
        text_body = ""
        html_body = ""
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    # Skip attachments
                    if 'attachment' in content_disposition.lower():
                        continue
                    
                    if content_type == 'text/plain':
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            text_body = payload.decode(charset, errors='ignore')
                    
                    elif content_type == 'text/html':
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            html_body = payload.decode(charset, errors='ignore')
            else:
                # Single part message
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    decoded_content = payload.decode(charset, errors='ignore')
                    
                    if content_type == 'text/plain':
                        text_body = decoded_content
                    elif content_type == 'text/html':
                        html_body = decoded_content
                    else:
                        # Default to text
                        text_body = decoded_content
            
            # Sanitize content (remove null bytes, control characters)
            text_body = self._sanitize_content(text_body)
            html_body = self._sanitize_content(html_body)
            
        except Exception as e:
            self.logger.warning(f"Failed to extract body content: {e}")
        
        return text_body, html_body
    
    def _extract_attachment_info(self, msg: EmailMessage) -> List[EmailAttachmentInfo]:
        """Extract attachment metadata WITHOUT accessing content"""
        attachments = []
        
        try:
            for part in msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disposition.lower():
                    attachment_info = EmailAttachmentInfo()
                    
                    # Get filename safely
                    filename = part.get_filename()
                    if filename:
                        attachment_info.filename = self._decode_header(filename)
                    
                    # Get content type
                    attachment_info.content_type = part.get_content_type()
                    attachment_info.content_disposition = content_disposition
                    
                    # Estimate size (if possible)
                    try:
                        payload = part.get_payload()
                        if payload:
                            attachment_info.size_bytes = len(str(payload))
                    except:
                        pass  # Size estimation failed, that's OK
                    
                    # Check if potentially malicious
                    if attachment_info.filename:
                        file_ext = Path(attachment_info.filename.lower()).suffix
                        attachment_info.is_potentially_malicious = file_ext in self.MALICIOUS_EXTENSIONS
                    
                    attachments.append(attachment_info)
                    
                    self.logger.info(f"Found attachment: {attachment_info.filename} ({attachment_info.content_type})")
        
        except Exception as e:
            self.logger.warning(f"Failed to extract attachment info: {e}")
        
        return attachments
    
    def _sanitize_content(self, content: str) -> str:
        """Sanitize text content for safe handling"""
        if not content:
            return ""
        
        # Remove null bytes and other dangerous characters
        content = content.replace('\x00', '')
        
        # Remove other control characters except common ones (tab, newline, carriage return)
        content = ''.join(char for char in content 
                         if ord(char) >= 32 or char in '\t\n\r')
        
        # Limit length to prevent memory issues
        if len(content) > 100000:  # 100KB limit
            content = content[:100000] + "\n[CONTENT TRUNCATED]"
        
        return content
    
    def _analyze_security_indicators(self, parsed_data: ParsedEmailData, msg: EmailMessage):
        """Analyze email for security indicators"""
        try:
            # Combine all text for keyword scanning
            all_text = f"{parsed_data.subject} {parsed_data.sender_display_name} {parsed_data.text_body} {parsed_data.html_body}".lower()

            # Check for suspicious keywords
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in all_text:
                    parsed_data.suspicious_keywords_found.append(keyword)

            # Check for financial keywords
            for keyword in self.FINANCIAL_KEYWORDS:
                if keyword in all_text:
                    parsed_data.financial_keywords_found.append(keyword)

            # Check for credential harvesting keywords
            for keyword in self.CREDENTIAL_KEYWORDS:
                if keyword in all_text:
                    parsed_data.credential_keywords_found.append(keyword)

            # Check for time pressure keywords
            for keyword in self.TIME_PRESSURE_KEYWORDS:
                if keyword in all_text:
                    parsed_data.time_pressure_keywords_found.append(keyword)

            # Check for external links in HTML and text
            url_pattern = r'https?://[^\s<>"\'`]+'
            if parsed_data.html_body:
                urls = re.findall(url_pattern, parsed_data.html_body, re.IGNORECASE)
                parsed_data.has_external_links = len(urls) > 0

                # Check for URL shorteners
                for shortener in self.URL_SHORTENERS:
                    if shortener in parsed_data.html_body.lower():
                        parsed_data.has_url_shorteners = True
                        break

                # Check for HTML forms
                if '<form' in parsed_data.html_body.lower():
                    parsed_data.has_html_forms = True

            # Check text body for URL shorteners if not found in HTML
            if not parsed_data.has_url_shorteners and parsed_data.text_body:
                for shortener in self.URL_SHORTENERS:
                    if shortener in parsed_data.text_body.lower():
                        parsed_data.has_url_shorteners = True
                        break

            # Check for subject line tricks (Re:/Fwd: without conversation history)
            if parsed_data.subject:
                subject_lower = parsed_data.subject.lower()
                if (subject_lower.startswith('re:') or subject_lower.startswith('fwd:')) and not parsed_data.in_reply_to:
                    parsed_data.has_subject_trick = True

            # Check for suspicious headers
            suspicious_header_indicators = [
                'x-mailer' in parsed_data.all_headers,
                'x-originating-ip' in parsed_data.all_headers,
                parsed_data.sender != parsed_data.reply_to and parsed_data.reply_to,
            ]

            parsed_data.has_suspicious_headers = any(suspicious_header_indicators)

        except Exception as e:
            self.logger.warning(f"Security analysis failed: {e}")
    
    def save_parsed_data_to_file(self, parsed_data: ParsedEmailData, output_path: Path):
        """Save parsed email data to a readable text file with security warnings"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("SECURITY WARNING: PARSED PHISHING EMAIL DATA\n")
                f.write("=" * 80 + "\n")
                f.write("This file contains parsed data from a suspected phishing email.\n")
                f.write("The original .eml file has been DELETED for security.\n")
                f.write("Attachments listed below were NOT extracted or downloaded.\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("PARSED EMAIL DATA\n")
                f.write("=================\n\n")
                
                f.write(f"From: {parsed_data.sender}\n")
                f.write(f"To: {', '.join(parsed_data.recipients)}\n")
                if parsed_data.cc_recipients:
                    f.write(f"CC: {', '.join(parsed_data.cc_recipients)}\n")
                f.write(f"Subject: {parsed_data.subject}\n")
                f.write(f"Date: {parsed_data.date_received}\n")
                f.write(f"Message-ID: {parsed_data.message_id}\n")
                
                if parsed_data.reply_to and parsed_data.reply_to != parsed_data.sender:
                    f.write(f"Reply-To: {parsed_data.reply_to}\n")
                
                f.write(f"\nAttachments Found (NOT EXTRACTED FOR SECURITY):\n")
                f.write(f"Total: {len(parsed_data.attachments)}\n")
                if parsed_data.attachments:
                    f.write("WARNING: The following attachments were detected but NOT downloaded:\n")
                    for att in parsed_data.attachments:
                        f.write(f"  - {att.filename} ({att.content_type})")
                        if att.is_potentially_malicious:
                            f.write(" [POTENTIALLY MALICIOUS - DO NOT OPEN]")
                        f.write(f" [{att.size_bytes} bytes]\n")
                else:
                    f.write("  No attachments detected in email\n")
                
                f.write(f"\nSecurity Indicators:\n")
                f.write(f"  Suspicious keywords: {', '.join(parsed_data.suspicious_keywords_found)}\n")
                f.write(f"  External links: {'Yes' if parsed_data.has_external_links else 'No'}\n")
                f.write(f"  Suspicious headers: {'Yes' if parsed_data.has_suspicious_headers else 'No'}\n")
                
                if parsed_data.text_body:
                    f.write(f"\n--- EMAIL BODY (TEXT) ---\n")
                    f.write(parsed_data.text_body[:2000])  # Limit for readability
                    if len(parsed_data.text_body) > 2000:
                        f.write("\n[TRUNCATED]")
                
            self.logger.info(f"Saved parsed email data to: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save parsed data to {output_path}: {e}")
            raise