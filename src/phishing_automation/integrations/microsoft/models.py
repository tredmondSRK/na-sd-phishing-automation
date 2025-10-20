from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
from enum import Enum
import re


class SubmissionStatus(str, Enum):
    """Email submission status in Defender"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ThreatVerdict(str, Enum):
    """Threat verdict from Defender analysis"""
    NO_THREATS_FOUND = "noThreatsFound"
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    BULK = "bulk"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class MailTraceStatus(str, Enum):
    """Mail trace delivery status"""
    DELIVERED = "delivered"
    FAILED = "failed"
    PENDING = "pending"
    EXPANDED = "expanded"
    UNKNOWN = "unknown"


class EmailSubmission(BaseModel):
    """Microsoft Defender email submission details"""
    id: str
    submission_time: datetime = Field(alias="submissionTime")
    submitter_id: str = Field(alias="submitterId")
    submitter_name: Optional[str] = Field(None, alias="submitterName")
    
    # Email details
    sender: str
    recipient: str
    subject: str
    message_id: str = Field(alias="networkMessageId")
    internet_message_id: Optional[str] = Field(None, alias="internetMessageId")
    received_date: datetime = Field(alias="receivedDate")
    
    # Analysis results
    status: SubmissionStatus
    verdict: Optional[ThreatVerdict] = None
    
    # Additional metadata
    original_category: Optional[str] = Field(None, alias="originalCategory")
    category: Optional[str] = None
    result_type: Optional[str] = Field(None, alias="resultType")

    class Config:
        populate_by_name = True
        use_enum_values = True

        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @validator('submission_time', 'received_date', pre=True)
    def parse_datetime(cls, v):
        if isinstance(v, str):
            # Handle various datetime formats from Microsoft APIs
            try:
                if 'T' in v:
                    if v.endswith('Z'):
                        return datetime.fromisoformat(v.replace('Z', '+00:00'))
                    return datetime.fromisoformat(v)
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise ValueError(f"Invalid datetime format: {v}")
        return v


class ThreatIntelligence(BaseModel):
    """Microsoft Defender threat intelligence data"""
    indicator_type: str = Field(alias="indicatorType")
    indicator_value: str = Field(alias="indicatorValue")
    threat_type: str = Field(alias="threatType")
    confidence: Optional[int] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    created_time: Optional[datetime] = Field(None, alias="createdTime")
    
    # URL/Domain specific fields
    url_reputation: Optional[str] = Field(None, alias="urlReputation")
    domain_reputation: Optional[str] = Field(None, alias="domainReputation")

    class Config:
        populate_by_name = True
        use_enum_values = True


class MailTraceResult(BaseModel):
    """Exchange Online mail trace result"""
    message_trace_id: str = Field(alias="MessageTraceId")
    received: datetime = Field(alias="Received")
    sender_address: str = Field(alias="SenderAddress")
    recipient_address: str = Field(alias="RecipientAddress")
    subject: str = Field(alias="Subject")
    status: MailTraceStatus = Field(alias="Status")
    to_ip: Optional[str] = Field(None, alias="ToIP")
    from_ip: Optional[str] = Field(None, alias="FromIP")
    size: Optional[int] = Field(None, alias="Size")
    message_id: Optional[str] = Field(None, alias="MessageId")
    
    # Additional trace details
    start_date: Optional[datetime] = Field(None, alias="StartDate")
    end_date: Optional[datetime] = Field(None, alias="EndDate")
    organization: Optional[str] = Field(None, alias="Organization")
    
    class Config:
        populate_by_name = True
        use_enum_values = True

        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

    @validator('received', 'start_date', 'end_date', pre=True)
    def parse_datetime(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            try:
                # Handle .NET JSON date format: /Date(milliseconds)/
                # This format is returned by Get-MessageTraceV2
                if v.startswith('/Date(') and v.endswith(')/'):
                    match = re.match(r'/Date\((\d+)\)/', v)
                    if match:
                        milliseconds = int(match.group(1))
                        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)

                # Handle ISO format
                if 'T' in v:
                    if v.endswith('Z'):
                        return datetime.fromisoformat(v.replace('Z', '+00:00'))
                    return datetime.fromisoformat(v)

                # Handle standard datetime format
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise ValueError(f"Invalid datetime format: {v}")
        return v


class MailTraceSummary(BaseModel):
    """Summary of mail trace results"""
    total_recipients: int
    unique_recipients: int
    delivered_count: int
    failed_count: int
    pending_count: int
    trace_start_time: datetime
    trace_end_time: datetime
    sender_address: str
    subject: str
    
    # File export information
    export_file_path: Optional[str] = None
    export_file_size: Optional[int] = None
    export_record_count: Optional[int] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ExactEmailTrace(MailTraceSummary):
    """Mail trace results for the exact phishing email"""
    message_id: str
    received_time: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SenderHistoryTrace(MailTraceSummary):
    """Mail trace results for sender's email history"""
    days_traced: int
    total_emails_sent: int
    unique_subjects: int
    first_email_date: Optional[datetime] = None
    last_email_date: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EmailAnalysisResult(BaseModel):
    """Complete email analysis from Microsoft services"""
    # Submission details
    submission: Optional[EmailSubmission] = None
    threat_intelligence: List[ThreatIntelligence] = []
    
    # Mail trace results
    exact_email_trace: Optional[ExactEmailTrace] = None
    sender_history_trace: Optional[SenderHistoryTrace] = None
    
    # Analysis metadata
    analysis_start_time: datetime
    analysis_end_time: Optional[datetime] = None
    analysis_duration_seconds: Optional[float] = None
    
    # Error information
    errors: List[str] = []
    warnings: List[str] = []
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_error(self, error: str):
        """Add an error message"""
        self.errors.append(error)
    
    def add_warning(self, warning: str):
        """Add a warning message"""
        self.warnings.append(warning)
    
    def has_errors(self) -> bool:
        """Check if analysis has errors"""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if analysis has warnings"""
        return len(self.warnings) > 0
    
    def is_complete(self) -> bool:
        """Check if analysis is complete"""
        return self.analysis_end_time is not None


class PowerShellExecutionResult(BaseModel):
    """Result of PowerShell command execution"""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time_seconds: float
    start_time: datetime
    end_time: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def is_success(self) -> bool:
        """Check if PowerShell execution was successful"""
        return self.exit_code == 0
    
    def has_output(self) -> bool:
        """Check if PowerShell execution produced output"""
        return bool(self.stdout.strip())
    
    def has_errors(self) -> bool:
        """Check if PowerShell execution has errors"""
        return self.exit_code != 0 or bool(self.stderr.strip())


class ConnectionTestResult(BaseModel):
    """Result of Microsoft service connection test"""
    service_name: str
    is_connected: bool
    response_time_ms: Optional[float] = None
    test_time: datetime
    error_message: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }