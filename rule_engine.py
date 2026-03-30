# rule_engine.py
"""
Moteur de détection basé sur des règles (Rule-Based)
Détecte les attaques connues via des seuils prédéfinis
"""
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime
from config import Config


class RuleEngine:
    """
    Moteur de détection basé sur des règles
    """
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.port_scan_threshold = self.config.PORT_SCAN_THRESHOLD
        self.brute_force_threshold = self.config.BRUTE_FORCE_THRESHOLD
        self.flood_threshold = self.config.FLOOD_THRESHOLD
    
    def detect_port_scan(self, df):
        """
        Détecte les tentatives de scan de ports
        
        Critère: Une IP source tente de se connecter à un nombre
                 élevé de ports différents sur une même IP de destination
                 
        Args:
            df: DataFrame contenant les données de trafic
            
        Returns:
            Liste d'alertes détectées
        """
        alerts = []
        
        # Vérifier si les colonnes nécessaires existent
        required_cols = ['source_ip', 'dest_ip', 'dest_port']
        if not all(col in df.columns for col in required_cols):
            return alerts
        
        # Grouper par IP source et destination, compter les ports uniques
        try:
            grouped = df.groupby(['source_ip', 'dest_ip'])['dest_port'].nunique()
            
            for (src_ip, dest_ip), port_count in grouped.items():
                if port_count > self.port_scan_threshold:
                    alert = {
                        'source_ip': src_ip,
                        'dest_ip': dest_ip,
                        'alert_type': 'Port Scan',
                        'description': f'{port_count} ports uniques scannés (seuil: {self.port_scan_threshold})',
                        'risk_level': 'high',
                        'detection_method': 'rule',
                        'confidence': 1.0,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    alerts.append(alert)
        except Exception as e:
            print(f"Erreur détection Port Scan: {e}")
        
        return alerts
    
    def detect_brute_force(self, df):
        """
        Détecte les tentatives de brute force
        
        Critère: Un grand nombre de connexions depuis une même IP source
                 
        Args:
            df: DataFrame contenant les données de trafic
            
        Returns:
            Liste d'alertes détectées
        """
        alerts = []
        
        if 'source_ip' not in df.columns:
            return alerts
        
        try:
            # Compter les connexions par IP source
            conn_counts = df.groupby('source_ip').size()
            
            for src_ip, count in conn_counts.items():
                if count > self.brute_force_threshold:
                    alert = {
                        'source_ip': src_ip,
                        'dest_ip': 'multiple',
                        'alert_type': 'Brute Force',
                        'description': f'{count} tentatives de connexion (seuil: {self.brute_force_threshold})',
                        'risk_level': 'critical',
                        'detection_method': 'rule',
                        'confidence': 1.0,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    alerts.append(alert)
        except Exception as e:
            print(f"Erreur détection Brute Force: {e}")
        
        return alerts
    
    def detect_flood(self, df):
        """
        Détecte les attaques de type Flood/DoS
        
        Critère: Un taux de paquets anormalement élevé
                 
        Args:
            df: DataFrame contenant les données de trafic
            
        Returns:
            Liste d'alertes détectées
        """
        alerts = []
        
        if 'rate' not in df.columns:
            return alerts
        
        try:
            # Identifier les flux avec taux élevé
            high_rate_mask = df['rate'] > self.flood_threshold
            high_rate_df = df[high_rate_mask]
            
            for idx, row in high_rate_df.iterrows():
                src_ip = row.get('source_ip', 'unknown')
                dest_ip = row.get('dest_ip', 'unknown')
                rate = row['rate']
                
                alert = {
                    'source_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': 'Flood/DoS',
                    'description': f'Taux de paquets élevé: {rate:.2f} paquets/sec (seuil: {self.flood_threshold})',
                    'risk_level': 'critical',
                    'detection_method': 'rule',
                    'confidence': 1.0,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                alerts.append(alert)
        except Exception as e:
            print(f"Erreur détection Flood: {e}")
        
        return alerts
    
    def detect_high_duration(self, df, duration_threshold=3600):
        """
        Détecte les connexions de longue durée (suspicious persistence)
        
        Args:
            df: DataFrame contenant les données de trafic
            duration_threshold: Seuil de durée en secondes
            
        Returns:
            Liste d'alertes détectées
        """
        alerts = []
        
        if 'dur' not in df.columns:
            return alerts
        
        try:
            long_duration = df[df['dur'] > duration_threshold]
            
            for idx, row in long_duration.iterrows():
                src_ip = row.get('source_ip', 'unknown')
                dest_ip = row.get('dest_ip', 'unknown')
                duration = row['dur']
                
                alert = {
                    'source_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': 'Long Duration Connection',
                    'description': f'Connexion longue durée: {duration:.0f} secondes',
                    'risk_level': 'medium',
                    'detection_method': 'rule',
                    'confidence': 0.8,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                alerts.append(alert)
        except Exception as e:
            print(f"Erreur détection Long Duration: {e}")
        
        return alerts
    
    def detect_large_data_transfer(self, df, bytes_threshold=10000000):
        """
        Détecte les transferts de données volumineux
        
        Args:
            df: DataFrame contenant les données de trafic
            bytes_threshold: Seuil en octets
            
        Returns:
            Liste d'alertes détectées
        """
        alerts = []
        
        if 'sbytes' not in df.columns or 'dbytes' not in df.columns:
            return alerts
        
        try:
            # Calculer le total des bytes transférés
            total_bytes = df['sbytes'] + df['dbytes']
            large_transfer = df[total_bytes > bytes_threshold]
            
            for idx, row in large_transfer.iterrows():
                src_ip = row.get('source_ip', 'unknown')
                dest_ip = row.get('dest_ip', 'unknown')
                total = row['sbytes'] + row['dbytes']
                
                alert = {
                    'source_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': 'Large Data Transfer',
                    'description': f'Transfert volumineux: {total/1024/1024:.2f} MB',
                    'risk_level': 'medium',
                    'detection_method': 'rule',
                    'confidence': 0.7,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                alerts.append(alert)
        except Exception as e:
            print(f"Erreur détection Large Transfer: {e}")
        
        return alerts
    
    def analyze_all(self, df):
        """
        Exécute toutes les règles de détection
        
        Args:
            df: DataFrame contenant les données de trafic
            
        Returns:
            Liste de toutes les alertes détectées
        """
        all_alerts = []
        
        print("Exécution des règles de détection...")
        
        # Exécuter chaque type de détection
        port_scan_alerts = self.detect_port_scan(df)
        all_alerts.extend(port_scan_alerts)
        print(f"  -> Port Scan: {len(port_scan_alerts)} alertes")
        
        brute_force_alerts = self.detect_brute_force(df)
        all_alerts.extend(brute_force_alerts)
        print(f"  -> Brute Force: {len(brute_force_alerts)} alertes")
        
        flood_alerts = self.detect_flood(df)
        all_alerts.extend(flood_alerts)
        print(f"  -> Flood/DoS: {len(flood_alerts)} alertes")
        
        long_duration_alerts = self.detect_high_duration(df)
        all_alerts.extend(long_duration_alerts)
        print(f"  -> Long Duration: {len(long_duration_alerts)} alertes")
        
        large_transfer_alerts = self.detect_large_data_transfer(df)
        all_alerts.extend(large_transfer_alerts)
        print(f"  -> Large Transfer: {len(large_transfer_alerts)} alertes")
        
        print(f"TOTAL Rule-Based: {len(all_alerts)} alertes")
        
        return all_alerts
    
    def get_statistics(self, alerts):
        """
        Génère des statistiques sur les alertes
        
        Args:
            alerts: Liste des alertes
            
        Returns:
            Dictionnaire de statistiques
        """
        stats = {
            'total': len(alerts),
            'by_type': defaultdict(int),
            'by_risk': defaultdict(int)
        }
        
        for alert in alerts:
            stats['by_type'][alert['alert_type']] += 1
            stats['by_risk'][alert['risk_level']] += 1
        
        return stats


# Test du module
if __name__ == '__main__':
    print("=" * 60)
    print("TEST DU MOTEUR RULE-BASED")
    print("=" * 60)
    
    # Créer des données de test simulées
    test_data = {
        'source_ip': ['192.168.1.1'] * 150 + ['10.0.0.1'] * 50 + ['172.16.0.1'] * 30,
        'dest_ip': ['10.0.0.2'] * 230,
        'dest_port': list(range(150)) + [80] * 50 + [443] * 30,
        'rate': [50] * 100 + [2000] * 50 + [100] * 50 + [500] * 30,
        'dur': [1] * 200 + [5000] * 30,
        'sbytes': [100] * 200 + [15000000] * 30,
        'dbytes': [100] * 230
    }
    
    df = pd.DataFrame(test_data)
    
    engine = RuleEngine(Config())
    alerts = engine.analyze_all(df)
    
    print("\n" + "=" * 60)
    print("ALERTES DÉTECTÉES:")
    print("=" * 60)
    
    for alert in alerts[:10]:  # Afficher les 10 premières
        print(f"\n[{alert['alert_type']}] {alert['source_ip']} -> {alert['dest_ip']}")
        print(f"  {alert['description']}")
        print(f"  Risque: {alert['risk_level']}")
    
    if len(alerts) > 10:
        print(f"\n... et {len(alerts) - 10} autres alertes")
    
    stats = engine.get_statistics(alerts)
    print(f"\nStatistiques: {stats}")
