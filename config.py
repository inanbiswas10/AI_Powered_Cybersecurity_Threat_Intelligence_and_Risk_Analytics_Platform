# AegisAI ThreatLens - Configuration & Environment Validation
# Utilizes Pydantic V2 for cryptographic security, environment loading and zero-leak configuration.

from pydantic import Field
from pydantic_settings import BaseSettings,SettingsConfigDict

class Settings (BaseSettings):

    # Production runtime settings with strict type hinting and validation.
    
    # Core Application Metadata

    APP_NAME: str = "AegisAI ThreatLens"
    VERSION: str = "4.2.0"
    ENVIRONMENT: str = Field (default = "production",env = "AEGIS_ENV")
    DEBUG: bool = Field (default = False,env = "AEGIS_DEBUG")
    
    # Server & API Routing

    HOST: str = "0.0.0.0"
    PORT: int = 8501
    API_PORT: int = 8000
    
    # Security & SOC Clearance

    OPERATOR_ID: str = "SEC_LEAD_S_VANCE"
    CLEARANCE_LEVEL: str = "L5_TOP_SECRET"
    DEFCON_INITIAL_STATE: int = 3
    
    # Threat Feed Endpoints & Thresholds

    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ALIENVAULT_OTX_API_KEY: str = Field (default = "",env = "OTX_API_KEY")
    VIRUSTOTAL_API_KEY: str = Field (default = "",env = "VT_API_KEY")
    
    # Machine Learning Hyperparameters

    ISOLATION_FOREST_CONTAMINATION: float = 0.05
    ISOLATION_FOREST_ESTIMATORS: int = 200
    XGBOOST_MAX_DEPTH: int = 6
    XGBOOST_LEARNING_RATE: float = 0.08
    SHANNON_ENTROPY_THRESHOLD: float = 7.5
    
    # SOAR & Automated Containment Policies

    AUTO_CONTAINMENT_ENABLED: bool = True
    CONTAINMENT_SLA_SECONDS: float = 1.8
    AWS_DEFAULT_REGION: str = "us-east-1"
    
    model_config = SettingsConfigDict (
        env_file = ".env",
        env_file_encoding = "utf-8",
        case_sensitive = True,
        extra = "ignore"
    )

settings = Settings ()