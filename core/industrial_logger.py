
import logging
import sys
import os

class IndustrialFormatter(logging.Formatter):
    """
    Standardized Last Bastion Industrial Log Formatter.
    Format: [TIMESTAMP] [LEVEL] [COMPONENT] | MESSAGE
    """
    
    # ANSI Color Codes for terminal visibility
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    CYAN = "\x1b[36;20m"
    GREEN = "\x1b[32;20m"
    RESET = "\x1b[0m"
    
    FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] | %(message)s"

    FORMATS = {
        logging.DEBUG: GREY + FORMAT + RESET,
        logging.INFO: CYAN + FORMAT + RESET,
        logging.WARNING: YELLOW + FORMAT + RESET,
        logging.ERROR: RED + FORMAT + RESET,
        logging.CRITICAL: BOLD_RED + FORMAT + RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

def get_industrial_logger(name: str):
    """Factory for Industrial-Grade Swarm Loggers."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        # Console Handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(IndustrialFormatter())
        logger.addHandler(ch)
        
        # File Handler (Optional persistence)
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        fh = logging.FileHandler(f"{log_dir}/swarm.log")
        fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] | %(message)s"))
        logger.addHandler(fh)
        
    return logger
