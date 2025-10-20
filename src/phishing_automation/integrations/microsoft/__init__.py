# Microsoft integrations

from .auth import MicrosoftAuthenticator, AuthenticationError
from .defender_client import DefenderClient, DefenderClientError
from .exchange_client import ExchangeClient, ExchangeClientError
from .models import (
    # Enums
    SubmissionStatus,
    ThreatVerdict,
    MailTraceStatus,
    
    # Core models
    EmailSubmission,
    ThreatIntelligence,
    MailTraceResult,
    MailTraceSummary,
    ExactEmailTrace,
    SenderHistoryTrace,
    EmailAnalysisResult,
    PowerShellExecutionResult,
    ConnectionTestResult
)

__all__ = [
    # Authentication
    'MicrosoftAuthenticator',
    'AuthenticationError',
    
    # Clients
    'DefenderClient',
    'DefenderClientError',
    'ExchangeClient', 
    'ExchangeClientError',
    
    # Enums
    'SubmissionStatus',
    'ThreatVerdict',
    'MailTraceStatus',
    
    # Models
    'EmailSubmission',
    'ThreatIntelligence',
    'MailTraceResult',
    'MailTraceSummary',
    'ExactEmailTrace',
    'SenderHistoryTrace',
    'EmailAnalysisResult',
    'PowerShellExecutionResult',
    'ConnectionTestResult'
]