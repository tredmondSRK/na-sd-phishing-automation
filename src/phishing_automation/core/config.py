import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator
import logging

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


class Config(BaseModel):
    # FreshService Configuration
    freshservice_domain: Optional[str] = Field(None, env='FRESHSERVICE_DOMAIN')
    freshservice_api_key: Optional[str] = Field(None, env='FRESHSERVICE_API_KEY')
    
    # Microsoft Configuration
    # Option 1: Interactive user authentication (recommended)
    microsoft_user_email: Optional[str] = Field(None, env='MICROSOFT_USER_EMAIL')
    
    # Option 2: App registration authentication (advanced)
    microsoft_tenant_id: Optional[str] = Field(None, env='MICROSOFT_TENANT_ID')
    microsoft_client_id: Optional[str] = Field(None, env='MICROSOFT_CLIENT_ID')
    microsoft_client_secret: Optional[str] = Field(None, env='MICROSOFT_CLIENT_SECRET')
    
    # Application Configuration
    log_level: str = Field("INFO", env='LOG_LEVEL')
    reports_dir: str = Field("./reports", env='REPORTS_DIR')
    logs_dir: str = Field("./logs", env='LOGS_DIR')
    
    # Optional Proxy Configuration
    http_proxy: Optional[str] = Field(None, env='HTTP_PROXY')
    https_proxy: Optional[str] = Field(None, env='HTTPS_PROXY')

    # Organization Configuration (for phishing detection)
    organization_name: str = Field("SRK Consulting", env='ORGANIZATION_NAME')
    organization_domains: str = Field(
        "srk.com,srk.com.mx,srk.uy,srk.com.ar,srk.com.au,srk.cn,srk.com.hk,srk.com.mn,srk.co.in,srk.cl,srk.com.pe,srk.co,srk.com.br,srk.co.uk,srkexploration.com,srk.com.kz,srk.com.se,srk.es,srk.eu,srk.kz,srknordic.com,srkturkiye.com,srk.ru.com,srk.com.gh,srk.co.za,srk.global",
        env='ORGANIZATION_DOMAINS'
    )
    
    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = False
    
    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()
    
    @validator('freshservice_domain')
    def validate_freshservice_domain(cls, v):
        if v and not v.endswith('.freshservice.com'):
            if '.' not in v:
                return f"{v}.freshservice.com"
            return v
        return v
    
    def validate_required_fields(self):
        required_fields = [
            ('freshservice_domain', self.freshservice_domain),
            ('freshservice_api_key', self.freshservice_api_key),
        ]
        
        missing_fields = [field for field, value in required_fields if not value]
        
        if missing_fields:
            raise ConfigError(f"Missing required configuration: {', '.join(missing_fields)}")
    
    def validate_microsoft_fields(self):
        """Validate Microsoft credentials for Defender and Exchange integrations"""
        # Check if using user authentication
        if self.microsoft_user_email:
            # User email authentication - no further validation needed
            return
        
        # Check if using app authentication
        if self.microsoft_tenant_id or self.microsoft_client_id or self.microsoft_client_secret:
            # If any app field is provided, all must be provided
            microsoft_fields = [
                ('microsoft_tenant_id', self.microsoft_tenant_id),
                ('microsoft_client_id', self.microsoft_client_id),
                ('microsoft_client_secret', self.microsoft_client_secret),
            ]
            
            missing_fields = [field for field, value in microsoft_fields if not value]
            
            if missing_fields:
                raise ConfigError(f"Incomplete app registration configuration. Missing: {', '.join(missing_fields)}")
            
            # Validate GUID format for tenant_id and client_id
            import re
            guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            
            if not re.match(guid_pattern, self.microsoft_tenant_id):
                raise ConfigError("microsoft_tenant_id must be a valid GUID format")
            
            if not re.match(guid_pattern, self.microsoft_client_id):
                raise ConfigError("microsoft_client_id must be a valid GUID format")
        
        # If neither auth method is configured, that's okay - Microsoft features will be disabled
    
    def setup_directories(self):
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        Path(self.logs_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directories: {self.reports_dir}, {self.logs_dir}")
    
    def get_proxy_config(self) -> Optional[dict]:
        if self.http_proxy or self.https_proxy:
            return {
                'http': self.http_proxy,
                'https': self.https_proxy or self.http_proxy
            }
        return None
    
    @classmethod
    def load_from_file(cls, config_file: str = '.env') -> 'Config':
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.warning(f"Configuration file {config_file} not found")
            if config_file == '.env':
                logger.info("Using environment variables and defaults")
            else:
                raise ConfigError(f"Configuration file {config_file} not found")
        else:
            load_dotenv(config_path)
            logger.info(f"Loaded configuration from {config_file}")
        
        # Load configuration from environment variables
        config_data = {}
        
        # Map environment variables to config fields
        env_mapping = {
            'FRESHSERVICE_DOMAIN': 'freshservice_domain',
            'FRESHSERVICE_API_KEY': 'freshservice_api_key',
            'MICROSOFT_USER_EMAIL': 'microsoft_user_email',
            'MICROSOFT_TENANT_ID': 'microsoft_tenant_id',
            'MICROSOFT_CLIENT_ID': 'microsoft_client_id',
            'MICROSOFT_CLIENT_SECRET': 'microsoft_client_secret',
            'LOG_LEVEL': 'log_level',
            'REPORTS_DIR': 'reports_dir',
            'LOGS_DIR': 'logs_dir',
            'HTTP_PROXY': 'http_proxy',
            'HTTPS_PROXY': 'https_proxy',
            'ORGANIZATION_NAME': 'organization_name',
            'ORGANIZATION_DOMAINS': 'organization_domains'
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value:
                config_data[config_key] = value
        
        try:
            config = cls(**config_data)
            config.setup_directories()
            return config
        except Exception as e:
            raise ConfigError(f"Invalid configuration: {e}")
    
    def to_dict(self, hide_secrets: bool = True) -> dict:
        data = self.dict()
        
        if hide_secrets:
            secret_fields = ['freshservice_api_key', 'microsoft_client_secret']
            for field in secret_fields:
                if data.get(field):
                    data[field] = '*****'
        
        return data
    
    def is_freshservice_configured(self) -> bool:
        return bool(self.freshservice_domain and self.freshservice_api_key)
    
    def is_microsoft_configured(self) -> bool:
        # Either user email OR app registration credentials
        has_user_auth = bool(self.microsoft_user_email)
        has_app_auth = bool(
            self.microsoft_tenant_id and
            self.microsoft_client_id and
            self.microsoft_client_secret
        )
        return has_user_auth or has_app_auth

    def get_organization_domains(self) -> list:
        """Get list of organization domains from comma-separated string"""
        if not self.organization_domains:
            return []
        return [domain.strip().lower() for domain in self.organization_domains.split(',')]