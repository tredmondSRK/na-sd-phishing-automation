import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import sys


class PhishingAutomationLogger:
    _instance: Optional['PhishingAutomationLogger'] = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.logs_dir = Path("logs")
        self.logs_dir.mkdir(exist_ok=True)
        
        self.setup_logging()
    
    def setup_logging(self, log_level: str = "INFO"):
        log_level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        level = log_level_map.get(log_level.upper(), logging.INFO)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        root_logger.handlers.clear()
        
        # Console handler - COMMENTED OUT FOR CLEAN CLI OUTPUT
        # DEBUGGING: Uncomment the lines below to enable verbose console logging
        # This is useful for troubleshooting errors and seeing detailed execution flow
        # console_handler = logging.StreamHandler(sys.stdout)
        # console_handler.setLevel(level)
        # console_handler.setFormatter(simple_formatter)
        # root_logger.addHandler(console_handler)
        
        # File handler for general logs
        general_log_file = self.logs_dir / f"phishing_automation_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(general_log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
        
        # Error log file handler
        error_log_file = self.logs_dir / f"errors_{datetime.now().strftime('%Y%m%d')}.log"
        error_handler = logging.FileHandler(error_log_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(error_handler)

        # Logging system initialized (logged to file only, no console spam)
    
    def create_ticket_logger(self, ticket_id: int) -> logging.Logger:
        logger_name = f"ticket_{ticket_id}"
        logger = logging.getLogger(logger_name)
        
        # Create ticket-specific log file
        ticket_log_file = self.logs_dir / f"ticket_{ticket_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(ticket_log_file) 
                  for h in logger.handlers):
            
            ticket_handler = logging.FileHandler(ticket_log_file, encoding='utf-8')
            ticket_handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            ticket_handler.setFormatter(formatter)
            logger.addHandler(ticket_handler)
        
        return logger
    
    def create_audit_logger(self) -> logging.Logger:
        logger_name = "audit"
        logger = logging.getLogger(logger_name)
        
        # Create audit log file
        audit_log_file = self.logs_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(audit_log_file) 
                  for h in logger.handlers):
            
            audit_handler = logging.FileHandler(audit_log_file, encoding='utf-8')
            audit_handler.setLevel(logging.INFO)

            formatter = logging.Formatter(
                '%(asctime)s - AUDIT - %(message)s'
            )
            audit_handler.setFormatter(formatter)
            logger.addHandler(audit_handler)
        
        return logger


def get_logger(name: str = __name__) -> logging.Logger:
    PhishingAutomationLogger()
    return logging.getLogger(name)


def get_ticket_logger(ticket_id: int) -> logging.Logger:
    logger_manager = PhishingAutomationLogger()
    return logger_manager.create_ticket_logger(ticket_id)


def get_audit_logger() -> logging.Logger:
    logger_manager = PhishingAutomationLogger()
    return logger_manager.create_audit_logger()


def log_action(ticket_id: int, action: str, details: str = ""):
    audit_logger = get_audit_logger()
    message = f"TICKET_{ticket_id} - {action}"
    if details:
        message += f" - {details}"
    audit_logger.info(message)


def log_error(ticket_id: int, error: str, details: str = ""):
    audit_logger = get_audit_logger()
    ticket_logger = get_ticket_logger(ticket_id)
    
    message = f"ERROR in TICKET_{ticket_id} - {error}"
    if details:
        message += f" - {details}"
    
    audit_logger.error(message)
    ticket_logger.error(message)