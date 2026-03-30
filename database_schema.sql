-- ============================================
-- Script de création de la base de données
-- IDS Hybride - MySQL
-- ============================================

-- Créer la base de données
CREATE DATABASE IF NOT EXISTS ids_hybride 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Utiliser la base de données
USE ids_hybride;

-- ============================================
-- Table des utilisateurs
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username)
) ENGINE=InnoDB;

-- ============================================
-- Table des logs de trafic réseau
-- ============================================
CREATE TABLE IF NOT EXISTS traffic_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    source_port INT,
    dest_port INT,
    protocol VARCHAR(20),
    
    -- Features du dataset UNSW-NB15
    dur FLOAT DEFAULT 0,
    sbytes BIGINT DEFAULT 0,
    dbytes BIGINT DEFAULT 0,
    sttl INT DEFAULT 0,
    dttl INT DEFAULT 0,
    sload FLOAT DEFAULT 0,
    dload FLOAT DEFAULT 0,
    rate FLOAT DEFAULT 0,
    
    -- Labels (du dataset)
    label INT DEFAULT 0,                    -- 0=normal, 1=attack
    attack_cat VARCHAR(50),                 -- Type d'attaque
    
    -- Prédictions du modèle
    predicted_label INT,                    -- Prédiction ML
    predicted_attack VARCHAR(50),           -- Type prédit
    confidence_score FLOAT,                 -- Score de confiance
    
    -- Métadonnées
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Index pour les requêtes fréquentes
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_label (label),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB;

-- ============================================
-- Table des alertes
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45),
    source_port INT,
    dest_port INT,
    
    -- Informations sur l'alerte
    alert_type VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Classification
    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    detection_method ENUM('rule', 'ml', 'hybrid') NOT NULL,
    
    -- Scores
    confidence_score FLOAT DEFAULT 0,
    
    -- Référence au log de trafic associé
    traffic_log_id INT,
    
    -- Métadonnées
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INT,
    acknowledged_at TIMESTAMP NULL,
    
    -- Index
    INDEX idx_source_ip (source_ip),
    INDEX idx_risk_level (risk_level),
    INDEX idx_detection_method (detection_method),
    INDEX idx_timestamp (timestamp),
    INDEX idx_acknowledged (acknowledged),
    
    FOREIGN KEY (traffic_log_id) REFERENCES traffic_logs(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================
-- Table des statistiques
-- ============================================
CREATE TABLE IF NOT EXISTS statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    stat_date DATE NOT NULL,
    
    -- Compteurs
    total_traffic INT DEFAULT 0,
    total_alerts INT DEFAULT 0,
    critical_alerts INT DEFAULT 0,
    high_alerts INT DEFAULT 0,
    medium_alerts INT DEFAULT 0,
    low_alerts INT DEFAULT 0,
    
    -- Par méthode
    rule_alerts INT DEFAULT 0,
    ml_alerts INT DEFAULT 0,
    hybrid_alerts INT DEFAULT 0,
    
    -- Performance ML
    ml_accuracy FLOAT,
    ml_precision FLOAT,
    ml_recall FLOAT,
    ml_f1_score FLOAT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_stat_date (stat_date)
) ENGINE=InnoDB;

-- ============================================
-- Table de configuration
-- ============================================
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_config_key (config_key)
) ENGINE=InnoDB;

-- ============================================
-- Insérer des valeurs par défaut
-- ============================================

-- Utilisateur admin par défaut (mot de passe: admin123 - à changer!)
INSERT INTO users (username, password_hash, role) VALUES 
('admin', 'pbkdf2:sha256:260000$admin$placeholder_change_this', 'admin')
ON DUPLICATE KEY UPDATE username=username;

-- Configuration par défaut
INSERT INTO system_config (config_key, config_value, description) VALUES
('port_scan_threshold', '100', 'Seuil de détection Port Scan'),
('brute_force_threshold', '50', 'Seuil de détection Brute Force'),
('flood_threshold', '1000', 'Seuil de détection Flood/DoS'),
('ml_confidence_threshold', '0.7', 'Seuil de confiance ML minimum'),
('model_type', 'random_forest', 'Type de modèle ML')
ON DUPLICATE KEY UPDATE config_value=VALUES(config_value);

-- ============================================
-- Vues utiles
-- ============================================

-- Vue des alertes récentes
CREATE OR REPLACE VIEW v_recent_alerts AS
SELECT 
    id, source_ip, dest_ip, alert_type, risk_level, 
    detection_method, confidence_score, timestamp
FROM alerts
ORDER BY timestamp DESC
LIMIT 100;

-- Vue des statistiques quotidiennes
CREATE OR REPLACE VIEW v_daily_stats AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_alerts,
    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high,
    SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium,
    SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) as low,
    SUM(CASE WHEN detection_method = 'rule' THEN 1 ELSE 0 END) as rule_based,
    SUM(CASE WHEN detection_method = 'ml' THEN 1 ELSE 0 END) as ml_based,
    SUM(CASE WHEN detection_method = 'hybrid' THEN 1 ELSE 0 END) as hybrid
FROM alerts
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- Vue des IPs les plus suspectes
CREATE OR REPLACE VIEW v_suspicious_ips AS
SELECT 
    source_ip,
    COUNT(*) as alert_count,
    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_count,
    MAX(timestamp) as last_alert
FROM alerts
GROUP BY source_ip
ORDER BY alert_count DESC
LIMIT 50;

-- ============================================
-- Terminé
-- ============================================
SELECT 'Base de données IDS Hybride créée avec succès!' as message;
