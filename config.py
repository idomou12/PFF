# config.py
"""
Configuration du projet IDS Hybride
"""
import os

class Config:
    """Configuration principale de l'application"""
    
    # ==================== MySQL Configuration ====================
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = '16040064'  # Modifier selon votre configuration
    MYSQL_DB = 'ids_hybride'
    
    # ==================== Flask Configuration ====================
    SECRET_KEY = 'ids_hybride_secret_key_change_in_production_2024'
    DEBUG = True
    
    # ==================== Data Paths ====================
    # Chemins vers les fichiers de données
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    
    TRAINING_DATA = os.path.join(DATA_DIR, 'UNSW_NB15_training-set.csv')
    TESTING_DATA = os.path.join(DATA_DIR, 'UNSW_NB15_testing-set.csv')
    
    # ==================== Model Paths ====================
    MODEL_DIR = os.path.join(BASE_DIR, 'models')
    MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest_model.joblib')
    SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
    ENCODERS_PATH = os.path.join(MODEL_DIR, 'label_encoders.joblib')
    
    # ==================== Rule-Based Thresholds ====================
    PORT_SCAN_THRESHOLD = 100      # Nombre de ports uniques pour détecter un scan
    BRUTE_FORCE_THRESHOLD = 50     # Nombre de connexions pour détecter brute force
    FLOOD_THRESHOLD = 1000         # Taux de paquets/sec pour détecter flood
    
    # ==================== ML Configuration ====================
    ML_CONFIDENCE_THRESHOLD = 0.7  # Seuil de confiance minimum pour alerter
    MODEL_TYPE = 'random_forest'   # 'random_forest' ou 'xgboost'

    # ==================== Risk thresholds (ML) ====================
    RISK_THRESHOLD_CRITICAL = 0.95
    RISK_THRESHOLD_HIGH = 0.85
    RISK_THRESHOLD_MEDIUM = 0.75
    
    # ==================== Features Configuration ====================
    # Features numériques à utiliser
    NUMERIC_FEATURES = [
        'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
        'sload', 'dload', 'spkts', 'dpkts', 'rate',
        'sintpkt', 'dintpkt', 'sjit', 'djit', 'tcprtt',
        'synack', 'ackdat', 'smeansz', 'dmeansz',
        'trans_depth', 'res_bdy_len', 'ct_srv_src',
        'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_flw_http_mthd',
        'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_dst'
    ]
    
    # Features catégoriques à encoder
    CATEGORICAL_FEATURES = ['proto', 'service', 'state']
    
    # Colonnes cibles (labels)
    LABEL_COL = 'label'           # Classification binaire
    ATTACK_CAT_COL = 'attack_cat' # Classification multi-classes


# Instance de configuration par défaut
config = Config()
