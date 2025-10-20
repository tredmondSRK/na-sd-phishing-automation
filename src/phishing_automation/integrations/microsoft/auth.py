import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

import msal
from azure.identity import ClientSecretCredential

from ...core.config import Config

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    pass


class MicrosoftAuthenticator:
    def __init__(self, config: Config):
        self.config = config
        self._lock = threading.Lock()
        self._graph_token = None
        self._graph_token_expires = None
        self._defender_token = None
        self._defender_token_expires = None
        
        # Validate Microsoft configuration
        if not self.config.is_microsoft_configured():
            raise AuthenticationError("Microsoft credentials not configured")
        
        try:
            self.config.validate_microsoft_fields()
        except Exception as e:
            raise AuthenticationError(f"Invalid Microsoft configuration: {e}")
        
        # Initialize MSAL app
        self._msal_app = self._create_msal_app()
        
        # Initialize Azure credential for Graph API
        self._credential = ClientSecretCredential(
            tenant_id=self.config.microsoft_tenant_id,
            client_id=self.config.microsoft_client_id,
            client_secret=self.config.microsoft_client_secret
        )
    
    def _create_msal_app(self) -> msal.ConfidentialClientApplication:
        """Create MSAL application for authentication"""
        try:
            # Create token cache directory
            token_cache_dir = Path(self.config.logs_dir) / "tokens"
            token_cache_dir.mkdir(parents=True, exist_ok=True)
            token_cache_file = token_cache_dir / "msal_token_cache.json"
            
            # Initialize token cache
            cache = msal.SerializableTokenCache()
            if token_cache_file.exists():
                with open(token_cache_file, 'r') as f:
                    cache.deserialize(f.read())
            
            # Create MSAL app
            app = msal.ConfidentialClientApplication(
                client_id=self.config.microsoft_client_id,
                client_credential=self.config.microsoft_client_secret,
                authority=f"https://login.microsoftonline.com/{self.config.microsoft_tenant_id}",
                token_cache=cache
            )
            
            # Save cache on changes
            if cache.has_state_changed:
                with open(token_cache_file, 'w') as f:
                    f.write(cache.serialize())
            
            return app
            
        except Exception as e:
            raise AuthenticationError(f"Failed to initialize MSAL application: {e}")
    
    def get_graph_token(self, scopes: list = None) -> str:
        """Get Microsoft Graph API access token"""
        if scopes is None:
            scopes = ["https://graph.microsoft.com/.default"]
        
        with self._lock:
            # Check if we have a valid cached token
            if (self._graph_token and self._graph_token_expires and 
                datetime.now() < self._graph_token_expires - timedelta(minutes=5)):
                return self._graph_token
            
            try:
                # Try to get token silently first
                accounts = self._msal_app.get_accounts()
                if accounts:
                    result = self._msal_app.acquire_token_silent(scopes, account=accounts[0])
                    if result and "access_token" in result:
                        self._cache_graph_token(result)
                        return result["access_token"]
                
                # If silent acquisition failed, get token using client credentials
                result = self._msal_app.acquire_token_for_client(scopes=scopes)
                
                if "access_token" not in result:
                    error_msg = result.get("error_description", "Unknown authentication error")
                    raise AuthenticationError(f"Failed to acquire Graph token: {error_msg}")
                
                self._cache_graph_token(result)
                logger.info("Successfully acquired Microsoft Graph access token")
                return result["access_token"]
                
            except Exception as e:
                raise AuthenticationError(f"Graph authentication failed: {e}")
    
    def get_defender_token(self) -> str:
        """Get Microsoft Defender API access token"""
        scopes = ["https://api.security.microsoft.com/.default"]
        
        with self._lock:
            # Check if we have a valid cached token
            if (self._defender_token and self._defender_token_expires and 
                datetime.now() < self._defender_token_expires - timedelta(minutes=5)):
                return self._defender_token
            
            try:
                # Get token using client credentials
                result = self._msal_app.acquire_token_for_client(scopes=scopes)
                
                if "access_token" not in result:
                    error_msg = result.get("error_description", "Unknown authentication error")
                    raise AuthenticationError(f"Failed to acquire Defender token: {error_msg}")
                
                self._cache_defender_token(result)
                logger.info("Successfully acquired Microsoft Defender access token")
                return result["access_token"]
                
            except Exception as e:
                raise AuthenticationError(f"Defender authentication failed: {e}")
    
    def get_azure_credential(self):
        """Get Azure Identity credential for Exchange PowerShell"""
        return self._credential
    
    def _cache_graph_token(self, token_result: Dict[str, Any]):
        """Cache Graph API token"""
        self._graph_token = token_result["access_token"]
        expires_in = token_result.get("expires_in", 3600)
        self._graph_token_expires = datetime.now() + timedelta(seconds=expires_in)
    
    def _cache_defender_token(self, token_result: Dict[str, Any]):
        """Cache Defender API token"""
        self._defender_token = token_result["access_token"]
        expires_in = token_result.get("expires_in", 3600)
        self._defender_token_expires = datetime.now() + timedelta(seconds=expires_in)
    
    def test_graph_connection(self) -> bool:
        """Test Microsoft Graph API connectivity"""
        try:
            token = self.get_graph_token()
            
            # Test with a simple Graph API call
            import requests
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Test endpoint - get application info
            response = requests.get(
                f'https://graph.microsoft.com/v1.0/applications?$filter=appId eq \'{self.config.microsoft_client_id}\'',
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("Microsoft Graph connection test successful")
                return True
            else:
                logger.error(f"Graph connection test failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Graph connection test failed: {e}")
            return False
    
    def test_defender_connection(self) -> bool:
        """Test Microsoft Defender API connectivity"""
        try:
            token = self.get_defender_token()
            
            # Test with a simple Defender API call
            import requests
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Test endpoint - get incidents (limited result)
            response = requests.get(
                'https://api.security.microsoft.com/api/incidents?$top=1',
                headers=headers,
                timeout=30
            )
            
            if response.status_code in [200, 404]:  # 404 is OK if no incidents
                logger.info("Microsoft Defender connection test successful")
                return True
            else:
                logger.error(f"Defender connection test failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Defender connection test failed: {e}")
            return False
    
    def clear_cached_tokens(self):
        """Clear all cached tokens"""
        with self._lock:
            self._graph_token = None
            self._graph_token_expires = None
            self._defender_token = None
            self._defender_token_expires = None
            logger.info("Cleared cached authentication tokens")