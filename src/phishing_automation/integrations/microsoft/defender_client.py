import logging
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .auth import MicrosoftAuthenticator, AuthenticationError
from .models import (
    EmailSubmission, ThreatIntelligence, ConnectionTestResult,
    SubmissionStatus, ThreatVerdict
)
from ...core.config import Config

logger = logging.getLogger(__name__)


class DefenderClientError(Exception):
    pass


class DefenderClient:
    """Microsoft Defender API client for READ-ONLY operations"""
    
    BASE_URL = "https://api.security.microsoft.com"
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    
    def __init__(self, config: Config):
        self.config = config
        self.authenticator = MicrosoftAuthenticator(config)
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        
        # Set proxy if configured
        proxy_config = self.config.get_proxy_config()
        if proxy_config:
            self.session.proxies.update(proxy_config)
    
    def _make_api_request(
        self, 
        url: str, 
        use_graph: bool = False, 
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated API request to Microsoft services"""
        try:
            # Get appropriate token
            if use_graph:
                token = self.authenticator.get_graph_token()
            else:
                token = self.authenticator.get_defender_token()
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=60)
            
            if response.status_code == 401:
                # Token might be expired, clear cache and retry
                self.authenticator.clear_cached_tokens()
                if use_graph:
                    token = self.authenticator.get_graph_token()
                else:
                    token = self.authenticator.get_defender_token()
                
                headers['Authorization'] = f'Bearer {token}'
                response = self.session.get(url, headers=headers, params=params, timeout=60)
            
            if response.status_code == 429:
                # Rate limit hit, wait and retry
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                import time
                time.sleep(retry_after)
                response = self.session.get(url, headers=headers, params=params, timeout=60)
            
            if not response.ok:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                raise DefenderClientError(
                    f"API request failed with status {response.status_code}: {response.text}"
                )
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise DefenderClientError(f"Request failed: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {e}")
            raise DefenderClientError(f"Invalid JSON response: {e}")
    
    def get_email_submission_by_id(self, submission_id: str) -> Optional[EmailSubmission]:
        """Get email submission details by submission ID (READ-ONLY)"""
        try:
            logger.info(f"Retrieving email submission: {submission_id}")
            
            # Use Graph API for email submission details
            url = f"{self.GRAPH_URL}/security/threatSubmission/emailSubmissions/{submission_id}"
            
            response_data = self._make_api_request(url, use_graph=True)
            
            if not response_data:
                logger.warning(f"No submission found with ID: {submission_id}")
                return None
            
            # Convert response to our model
            submission = EmailSubmission(**response_data)
            logger.info(f"Successfully retrieved submission: {submission.id}")
            return submission
            
        except Exception as e:
            logger.error(f"Failed to get submission {submission_id}: {e}")
            raise DefenderClientError(f"Failed to retrieve email submission: {e}")
    
    def search_email_submissions(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        subject: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[EmailSubmission]:
        """Search for email submissions (READ-ONLY)"""
        try:
            logger.info(f"Searching email submissions - sender: {sender}, recipient: {recipient}")
            
            # Build filter string for Graph API
            filters = []
            
            if sender:
                filters.append(f"sender eq '{sender}'")
            
            if recipient:
                filters.append(f"recipient eq '{recipient}'")
            
            if subject:
                filters.append(f"contains(subject, '{subject}')")
            
            if start_time:
                start_iso = start_time.isoformat() + 'Z'
                filters.append(f"receivedDateTime ge {start_iso}")
            
            if end_time:
                end_iso = end_time.isoformat() + 'Z'
                filters.append(f"receivedDateTime le {end_iso}")
            
            params = {}
            if filters:
                params['$filter'] = ' and '.join(filters)
            
            if limit:
                params['$top'] = limit
            
            params['$orderby'] = 'receivedDateTime desc'
            
            url = f"{self.GRAPH_URL}/security/threatSubmission/emailSubmissions"
            response_data = self._make_api_request(url, use_graph=True, params=params)
            
            submissions = []
            for item in response_data.get('value', []):
                try:
                    submission = EmailSubmission(**item)
                    submissions.append(submission)
                except Exception as e:
                    logger.warning(f"Failed to parse submission: {e}")
                    continue
            
            logger.info(f"Found {len(submissions)} email submissions")
            return submissions
            
        except Exception as e:
            logger.error(f"Failed to search submissions: {e}")
            raise DefenderClientError(f"Failed to search email submissions: {e}")
    
    def get_email_by_network_message_id(self, network_message_id: str) -> Optional[EmailSubmission]:
        """Get email submission by network message ID (READ-ONLY)"""
        try:
            logger.info(f"Searching for email with network message ID: {network_message_id}")
            
            # Search for submission with this network message ID
            submissions = self.search_email_submissions(limit=10)
            
            for submission in submissions:
                if submission.message_id == network_message_id:
                    logger.info(f"Found submission for network message ID: {submission.id}")
                    return submission
            
            logger.warning(f"No submission found for network message ID: {network_message_id}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get email by network message ID: {e}")
            raise DefenderClientError(f"Failed to retrieve email: {e}")
    
    def get_threat_intelligence(self, indicator_value: str, indicator_type: str = "url") -> List[ThreatIntelligence]:
        """Get threat intelligence for URL, domain, or file hash (READ-ONLY)"""
        try:
            logger.info(f"Getting threat intelligence for {indicator_type}: {indicator_value}")
            
            # Use Defender API for threat intelligence
            encoded_indicator = quote(indicator_value, safe='')
            url = f"{self.BASE_URL}/api/indicators"
            
            params = {
                '$filter': f"indicatorValue eq '{encoded_indicator}' and indicatorType eq '{indicator_type}'",
                '$top': 50
            }
            
            response_data = self._make_api_request(url, use_graph=False, params=params)
            
            threat_data = []
            for item in response_data.get('value', []):
                try:
                    threat_intel = ThreatIntelligence(**item)
                    threat_data.append(threat_intel)
                except Exception as e:
                    logger.warning(f"Failed to parse threat intelligence: {e}")
                    continue
            
            logger.info(f"Found {len(threat_data)} threat intelligence records")
            return threat_data
            
        except Exception as e:
            logger.error(f"Failed to get threat intelligence: {e}")
            raise DefenderClientError(f"Failed to retrieve threat intelligence: {e}")
    
    def get_url_reputation(self, url: str) -> Dict[str, Any]:
        """Get URL reputation from Microsoft Defender (READ-ONLY)"""
        try:
            logger.info(f"Getting URL reputation: {url}")
            
            # Use Graph API for URL reputation
            encoded_url = quote(url, safe='')
            api_url = f"{self.GRAPH_URL}/security/threatIntelligence/urlReputation(url='{encoded_url}')"
            
            response_data = self._make_api_request(api_url, use_graph=True)
            
            logger.info(f"Retrieved URL reputation for: {url}")
            return response_data
            
        except Exception as e:
            logger.warning(f"Failed to get URL reputation for {url}: {e}")
            # Return empty result if URL reputation check fails (non-critical)
            return {"url": url, "reputation": "unknown", "error": str(e)}
    
    def get_incidents_by_email(
        self, 
        sender: Optional[str] = None, 
        subject: Optional[str] = None,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """Get security incidents related to email (READ-ONLY)"""
        try:
            logger.info(f"Searching incidents for email - sender: {sender}, subject: {subject}")
            
            # Build filter for incidents
            filters = []
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days_back)
            
            filters.append(f"createdDateTime ge {start_time.isoformat()}Z")
            filters.append(f"createdDateTime le {end_time.isoformat()}Z")
            
            if sender:
                filters.append(f"contains(title, '{sender}') or contains(description, '{sender}')")
            
            if subject:
                # Clean subject for search
                clean_subject = subject.replace("'", "''")
                filters.append(f"contains(title, '{clean_subject}') or contains(description, '{clean_subject}')")
            
            params = {
                '$filter': ' and '.join(filters),
                '$top': 50,
                '$orderby': 'createdDateTime desc'
            }
            
            url = f"{self.BASE_URL}/api/incidents"
            response_data = self._make_api_request(url, use_graph=False, params=params)
            
            incidents = response_data.get('value', [])
            logger.info(f"Found {len(incidents)} related incidents")
            return incidents
            
        except Exception as e:
            logger.warning(f"Failed to get incidents: {e}")
            # Return empty list if incidents search fails (non-critical)
            return []
    
    def test_connection(self) -> ConnectionTestResult:
        """Test connection to Microsoft Defender API (READ-ONLY)"""
        start_time = datetime.now()
        
        try:
            # Test both Defender and Graph connectivity
            defender_test = self.authenticator.test_defender_connection()
            graph_test = self.authenticator.test_graph_connection()
            
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            is_connected = defender_test and graph_test
            error_message = None
            
            if not is_connected:
                errors = []
                if not defender_test:
                    errors.append("Defender API")
                if not graph_test:
                    errors.append("Graph API")
                error_message = f"Failed to connect to: {', '.join(errors)}"
            
            return ConnectionTestResult(
                service_name="Microsoft Defender",
                is_connected=is_connected,
                response_time_ms=response_time,
                test_time=start_time,
                error_message=error_message
            )
            
        except Exception as e:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return ConnectionTestResult(
                service_name="Microsoft Defender",
                is_connected=False,
                response_time_ms=response_time,
                test_time=start_time,
                error_message=str(e)
            )