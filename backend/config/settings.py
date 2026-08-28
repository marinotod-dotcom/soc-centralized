import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
import yaml

class Config:
    
    def __init__(self, config_path: str = None, env_path: str = None):
        if env_path is None:
            env_path = Path(__file__).parent.parent / ".env"
        else:
            env_path = Path(env_path)
            
        if env_path.exists():
            load_dotenv(env_path)
            print(f" Loaded environment variables from {env_path}")
        else:
            print(f".env file not found at {env_path}")
        
        if config_path is None:
            config_path = Path(__file__).parent / "config.yaml"
        
        self.config_path = Path(config_path)
        self._yaml_config = {}
        
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self._yaml_config = yaml.safe_load(file)
        
        self._setup_logging()
        
        self._create_directories()
        
    def _get_env(self, key: str, default: Any = None, required: bool = False) -> Any:
        value = os.getenv(key, default)
        
        if required and value is None:
            raise ValueError(f"Required environment variable '{key}' is not set")
        
        # Convert boolean strings
        if isinstance(value, str) and value.lower() in ['true', 'false', 'yes', 'no', '1', '0']:
            return value.lower() in ['true', 'yes', '1']
        
        return value
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_level = self._get_env('LOG_LEVEL', 'INFO')
        log_file = self._get_env('LOG_FILE_PATH', './logs/wazuh_report.log')
        
        # Create log directory
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
    def _create_directories(self) -> None:
        """Create necessary directories"""
        directories = [
            self.report_output_dir,
            self.report_temp_dir,
            self.report_template_dir,
            Path("./logs"),
            Path("./data")
        ]
        
        for directory in directories:
            if directory and not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
    
    @property
    def wazuh_manager_host(self) -> str:
        """Wazuh Manager API URL"""
        return self._get_env('WAZUH_MANAGER_HOST', required=True)
    
    @property
    def wazuh_manager_username(self) -> str:
        return self._get_env('WAZUH_MANAGER_API_USERNAME', required=True)
    
    @property
    def wazuh_manager_password(self) -> str:
        return self._get_env('WAZUH_MANAGER_API_PASSWORD', required=True)
    
    @property
    def wazuh_manager_api_key(self) -> Optional[str]:
        return self._get_env('WAZUH_MANAGER_API_KEY')
    
    @property
    def wazuh_manager_verify_ssl(self) -> bool:
        return self._get_env('WAZUH_MANAGER_VERIFY_SSL', False)
    
    @property
    def wazuh_manager_timeout(self) -> int:
        return int(self._get_env('WAZUH_MANAGER_TIMEOUT', 30))
    
    @property
    def wazuh_manager_endpoints(self) -> Dict[str, str]:
        return self._yaml_config.get('api_endpoints', {}).get('wazuh_manager', {})
    
    @property
    def wazuh_indexer_host(self) -> str:
        return self._get_env('WAZUH_INDEXER_HOST', required=True)
    
    @property
    def wazuh_indexer_username(self) -> str:
        return self._get_env('WAZUH_INDEXER_USERNAME', required=True)
    
    @property
    def wazuh_indexer_password(self) -> str:
        return self._get_env('WAZUH_INDEXER_PASSWORD', required=True)
    
    @property
    def wazuh_indexer_api_key(self) -> Optional[str]:
        return self._get_env('WAZUH_INDEXER_API_KEY')
    
    @property
    def wazuh_indexer_verify_ssl(self) -> bool:
        """Verify SSL certificate"""
        return self._get_env('WAZUH_INDEXER_VERIFY_SSL', False)
    
    @property
    def wazuh_indexer_timeout(self) -> int:
        """API timeout in seconds"""
        return int(self._get_env('WAZUH_INDEXER_TIMEOUT', 30))
    
    @property
    def wazuh_indexer_index_pattern(self) -> str:
        """Index pattern for alerts"""
        return self._get_env('WAZUH_INDEXER_INDEX_PATTERN', 'wazuh-alerts-*')
    
    @property
    def wazuh_indexer_endpoints(self) -> Dict[str, str]:
        """API endpoints from YAML config"""
        return self._yaml_config.get('api_endpoints', {}).get('wazuh_indexer', {})
    
    # ============================================
    # SMTP EMAIL - CRUCIAL (from .env)
    # ============================================
    @property
    def smtp_server(self) -> str:
        """SMTP server address"""
        return self._get_env('SMTP_SERVER', required=True)
    
    @property
    def smtp_port(self) -> int:
        """SMTP port"""
        return int(self._get_env('SMTP_PORT', 587))
    
    @property
    def smtp_use_tls(self) -> bool:
        """Use TLS for SMTP"""
        return self._get_env('SMTP_USE_TLS', True)
    
    @property
    def smtp_username(self) -> str:
        """SMTP authentication username"""
        return self._get_env('SMTP_USERNAME', required=True)
    
    @property
    def smtp_password(self) -> str:
        """SMTP authentication password"""
        return self._get_env('SMTP_PASSWORD', required=True)
    
    @property
    def smtp_from_address(self) -> str:
        """From email address"""
        return self._get_env('SMTP_FROM_ADDRESS', required=True)
    
    @property
    def smtp_from_name(self) -> str:
        """From display name"""
        return self._get_env('SMTP_FROM_NAME', 'Wazuh Weekly Report')
    
    # ============================================
    # RECIPIENTS - CRUCIAL (from .env)
    # ============================================
    @property
    def recipients_to(self) -> List[str]:
        """Primary recipients (comma-separated in .env)"""
        recipients = self._get_env('REPORT_RECIPIENTS_TO', '')
        return [r.strip() for r in recipients.split(',') if r.strip()]
    
    @property
    def recipients_cc(self) -> List[str]:
        """CC recipients (comma-separated in .env)"""
        recipients = self._get_env('REPORT_RECIPIENTS_CC', '')
        return [r.strip() for r in recipients.split(',') if r.strip()]
    
    @property
    def recipients_bcc(self) -> List[str]:
        """BCC recipients (comma-separated in .env)"""
        recipients = self._get_env('REPORT_RECIPIENTS_BCC', '')
        return [r.strip() for r in recipients.split(',') if r.strip()]
    
    # ============================================
    # REPORT CONFIGURATION (from YAML)
    # ============================================
    @property
    def report_config(self) -> Dict[str, Any]:
        """Report configuration from YAML"""
        return self._yaml_config.get('report', {})
    
    @property
    def report_output_dir(self) -> Path:
        return Path(self.report_config.get('output_dir', './reports'))
    
    @property
    def report_temp_dir(self) -> Path:
        return Path(self.report_config.get('temp_dir', './temp'))
    
    @property
    def report_template_dir(self) -> Path:
        return Path(self.report_config.get('template_dir', './templates'))
    
    @property
    def report_html_template(self) -> str:
        return self.report_config.get('html_template', 'report_template.html')
    
    @property
    def report_thresholds(self) -> Dict[str, Any]:
        return self.report_config.get('thresholds', {})
    
    # ============================================
    # DATABASE (Optionnel - from .env)
    # ============================================
    @property
    def database_path(self) -> str:
        """SQLite database path"""
        return self._get_env('DATABASE_PATH', './data/wazuh_reports.db')
    
    @property
    def database_password(self) -> Optional[str]:
        """Database encryption password (if using SQLCipher)"""
        return self._get_env('DATABASE_PASSWORD')
    
    # ============================================
    # WEBHOOKS (Optionnel - from .env)
    # ============================================
    @property
    def slack_webhook_url(self) -> Optional[str]:
        """Slack webhook URL for notifications"""
        return self._get_env('SLACK_WEBHOOK_URL')
    
    @property
    def teams_webhook_url(self) -> Optional[str]:
        """Microsoft Teams webhook URL"""
        return self._get_env('TEAMS_WEBHOOK_URL')
    
    @property
    def pagerduty_api_key(self) -> Optional[str]:
        """PagerDuty API key"""
        return self._get_env('PAGERDUTY_API_KEY')
    
    # ============================================
    # AWS S3 (Optionnel - from .env)
    # ============================================
    @property
    def aws_access_key_id(self) -> Optional[str]:
        """AWS access key for S3 backup"""
        return self._get_env('AWS_ACCESS_KEY_ID')
    
    @property
    def aws_secret_access_key(self) -> Optional[str]:
        """AWS secret key for S3 backup"""
        return self._get_env('AWS_SECRET_ACCESS_KEY')
    
    @property
    def aws_s3_bucket(self) -> Optional[str]:
        """S3 bucket name for report backup"""
        return self._get_env('AWS_S3_BUCKET')
    
    @property
    def aws_region(self) -> str:
        """AWS region"""
        return self._get_env('AWS_REGION', 'eu-west-3')
    
    @property
    def http_proxy(self) -> Optional[str]:
        return self._get_env('HTTP_PROXY')
    
    @property
    def https_proxy(self) -> Optional[str]:
        return self._get_env('HTTPS_PROXY')
    
    @property
    def no_proxy(self) -> Optional[str]:
        return self._get_env('NO_PROXY')
    
    @property
    def api_max_retries(self) -> int:
        return int(self._get_env('API_MAX_RETRIES', 3))
    
    @property
    def api_retry_delay(self) -> int:
        return int(self._get_env('API_RETRY_DELAY', 5))
    
    @property
    def api_rate_limit(self) -> int:
        return int(self._get_env('API_RATE_LIMIT', 100))
    
    @property
    def scheduler_enabled(self) -> bool:
        return self._get_env('SCHEDULER_ENABLED', True)
    
    @property
    def scheduler_time(self) -> str:
        return self._get_env('SCHEDULER_TIME', '07:00')
    
    @property
    def scheduler_day(self) -> str:
        return self._get_env('SCHEDULER_DAY', 'monday')
    
    @property
    def encryption_key(self) -> Optional[str]:
        return self._get_env('ENCRYPTION_KEY')
    
    @property
    def jwt_secret_key(self) -> Optional[str]:
        return self._get_env('JWT_SECRET_KEY')
    
    @property
    def features(self) -> Dict[str, bool]:
        return self._yaml_config.get('features', {})
    
    def validate_crucial_config(self) -> bool:
        errors = []
        
        try:
            if not self.wazuh_manager_host:
                errors.append("WAZUH_MANAGER_HOST is required")
            if not self.wazuh_manager_username:
                errors.append("WAZUH_MANAGER_API_USERNAME is required")
            if not self.wazuh_manager_password and not self.wazuh_manager_api_key:
                errors.append("Either WAZUH_MANAGER_API_PASSWORD or WAZUH_MANAGER_API_KEY is required")
        except Exception as e:
            errors.append(f"Wazuh Manager configuration error: {e}")
        
        try:
            if not self.wazuh_indexer_host:
                errors.append("WAZUH_INDEXER_HOST is required")
            if not self.wazuh_indexer_username:
                errors.append("WAZUH_INDEXER_USERNAME is required")
            if not self.wazuh_indexer_password and not self.wazuh_indexer_api_key:
                errors.append("Either WAZUH_INDEXER_PASSWORD or WAZUH_INDEXER_API_KEY is required")
        except Exception as e:
            errors.append(f"Wazuh Indexer configuration error: {e}")
        
        try:
            if not self.smtp_server:
                errors.append("SMTP_SERVER is required")
            if not self.smtp_username:
                errors.append("SMTP_USERNAME is required")
            if not self.smtp_password:
                errors.append("SMTP_PASSWORD is required")
            if not self.smtp_from_address:
                errors.append("SMTP_FROM_ADDRESS is required")
        except Exception as e:
            errors.append(f"SMTP configuration error: {e}")
        
        if not self.recipients_to:
            errors.append("REPORT_RECIPIENTS_TO must have at least one recipient")
        
        if errors:
            raise ValueError(f"Configuration validation failed:\n- " + "\n- ".join(errors))
        
        logging.info(" Configuration validation passed")
        return True

_config_instance = None


def get_config(env_path: str = None) -> Config:
    """Get singleton configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(env_path=env_path)
        _config_instance.validate_crucial_config()
    return _config_instance