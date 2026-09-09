# AegisAI ThreatLens - Threat Intelligence Utilities
# Cryptographic SHA-256 auditing, Shannon Entropy Calculation and Logger configurations.

import math
import hashlib
import logging
import sys

def setup_logger (name: str) -> logging.Logger:

    # Configures high-visibility structured logging for SecOps monitoring.

    logger = logging.getLogger (name)
    if not logger.handlers:
        logger.setLevel (logging.INFO)
        handler = logging.StreamHandler (sys.stdout)
        formatter = logging.Formatter (
            '[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
            datefmt = '%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter (formatter)
        logger.addHandler (handler)
    return logger

def hash_ioc(data: str) -> str:

    # Compute deterministic SHA-256 hash of an indicator or payload.

    return hashlib.sha256 (data.encode ('utf-8')).hexdigest ()

def calculate_shannon_entropy (data: bytes) -> float:

    # Calculate the Shannon entropy of incoming payload bytes.
    # Values > 7.5 indicate encryption, packing, or rootkit obfuscation.
    
    if not data:
        return 0.0
    entropy = 0.0
    length = len (data)
    frequencies = [0] * 256
    for b in data:
        frequencies [b] += 1
    for count in frequencies:
        if count > 0:
            p_x = float (count) / length
            entropy -= p_x * math.log2 (p_x)
    return round (entropy,4)