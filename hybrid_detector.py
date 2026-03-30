# hybrid_detector.py
"""
Module d'intégration hybride combinant Rule-Based et ML Supervisé
"""
import pandas as pd
import numpy as np
from datetime import datetime
import os
from config import Config
from rule_engine import RuleEngine
from ml_supervised import SupervisedDetector


class HybridDetector:
    """
    Détecteur hybride combinant les approches Rule-Based et ML Supervisé
    """
    
    def __init__(self, config=None):
        """
        Initialise le détecteur hybride
        
        Args:
            config: Configuration du projet
        """
        self.config = config or Config()
        self.rule_engine = RuleEngine(self.config)
        self.ml_detector = SupervisedDetector(self.config, model_type=self.config.MODEL_TYPE)
        self.is_initialized = False
    
    def initialize(self, force_train=False):
        """
        Initialise le détecteur hybride
        
        Args:
            force_train: Si True, force le réentraînement du modèle
        """
        print("=" * 60)
        print("INITIALISATION DU DÉTECTEUR HYBRIDE")
        print("=" * 60)
        
        # Charger ou entraîner le modèle ML
        if not force_train and self.ml_detector.load_model():
            print("✓ Modèle ML chargé depuis le disque")
        else:
            if os.path.exists(self.config.TRAINING_DATA):
                print("Entraînement du modèle ML...")
                self.ml_detector.train(self.config.TRAINING_DATA, multi_class=False)
            else:
                print(f"ATTENTION: Fichier d'entraînement non trouvé: {self.config.TRAINING_DATA}")
                print("Le détecteur ML ne sera pas disponible.")
        
        self.is_initialized = True
        print("✓ Initialisation terminée\n")
    
    def analyze(self, data_path):
        """
        Analyse les données avec les deux méthodes et fusionne les résultats
        
        Args:
            data_path: Chemin vers le fichier de données
            
        Returns:
            all_alerts: Liste de toutes les alertes
            ml_predictions: Prédictions ML
            ml_confidence: Scores de confiance ML
            y_true: Vrais labels (si disponibles)
        """
        if not self.is_initialized:
            self.initialize()
        
        print("=" * 60)
        print("ANALYSE HYBRIDE")
        print("=" * 60)
        
        # Charger les données
        df = pd.read_csv(data_path)
        df.columns = df.columns.str.strip()
        
        # Ajouter des IPs simulées si absentes (pour démonstration)
        self._add_simulated_ips(df)
        
        all_alerts = []
        
        # ==================== 1. Détection Rule-Based ====================
        print("\n[1/2] Détection Rule-Based...")
        rule_alerts = self.rule_engine.analyze_all(df)
        
        for alert in rule_alerts:
            alert['detection_method'] = 'rule'
        all_alerts.extend(rule_alerts)
        
        # ==================== 2. Détection ML Supervisé ====================
        print("\n[2/2] Détection ML Supervisé...")
        ml_predictions = []
        ml_confidence = []
        y_true = None
        
        if self.ml_detector.is_trained:
            ml_predictions, ml_confidence, probs, df_ml, y_true = self.ml_detector.predict(data_path)
            
            ml_alerts = self.ml_detector.get_alerts(
                ml_predictions, ml_confidence, df,
                threshold=self.config.ML_CONFIDENCE_THRESHOLD
            )
            
            # Identifier les alertes hybrides (détectées par les deux méthodes)
            rule_ips = set(a['source_ip'] for a in rule_alerts)
            
            for alert in ml_alerts:
                if alert['source_ip'] in rule_ips:
                    alert['detection_method'] = 'hybrid'
                    alert['description'] += ' [Confirmé par Rule-Based]'
                all_alerts.append(alert)
            
            print(f"  -> ML: {len(ml_alerts)} alertes")
        else:
            print("  -> ML non disponible (modèle non entraîné)")
        
        # ==================== Résumé ====================
        print("\n" + "=" * 60)
        print("RÉSUMÉ")
        print("=" * 60)
        
        rule_count = sum(1 for a in all_alerts if a['detection_method'] == 'rule')
        ml_count = sum(1 for a in all_alerts if a['detection_method'] == 'ml')
        hybrid_count = sum(1 for a in all_alerts if a['detection_method'] == 'hybrid')
        
        print(f"Total alertes: {len(all_alerts)}")
        print(f"  - Rule-Based: {rule_count}")
        print(f"  - ML seul: {ml_count}")
        print(f"  - Hybride: {hybrid_count}")
        
        return all_alerts, ml_predictions, ml_confidence, y_true
    
    def _add_simulated_ips(self, df):
        """Ajoute des IPs simulées si absentes du dataset"""
        if 'source_ip' not in df.columns:
            df['source_ip'] = [f'192.168.1.{i % 255}' for i in range(len(df))]
        if 'dest_ip' not in df.columns:
            df['dest_ip'] = [f'10.0.0.{i % 10}' for i in range(len(df))]
        if 'dest_port' not in df.columns:
            df['dest_port'] = [80 + (i % 100) for i in range(len(df))]
    
    def evaluate_system(self, data_path):
        """
        Évalue le système complet avec les vrais labels
        
        Args:
            data_path: Chemin vers le fichier de test
            
        Returns:
            Dictionnaire avec les statistiques complètes
        """
        print("\n" + "=" * 60)
        print("ÉVALUATION COMPLÈTE DU SYSTÈME")
        print("=" * 60)
        
        # Lancer l'analyse
        all_alerts, ml_predictions, ml_confidence, y_true = self.analyze(data_path)
        
        # Évaluation ML
        ml_metrics = {}
        if self.ml_detector.is_trained and y_true is not None:
            ml_metrics = self.ml_detector.evaluate(y_true, ml_predictions)
        
        # Statistiques globales
        rule_alerts = [a for a in all_alerts if a['detection_method'] == 'rule']
        ml_alerts = [a for a in all_alerts if a['detection_method'] == 'ml']
        hybrid_alerts = [a for a in all_alerts if a['detection_method'] == 'hybrid']
        
        stats = {
            'total_alerts': len(all_alerts),
            'rule_alerts': len(rule_alerts),
            'ml_alerts': len(ml_alerts),
            'hybrid_alerts': len(hybrid_alerts),
            'ml_metrics': ml_metrics,
            'risk_distribution': {
                'critical': sum(1 for a in all_alerts if a['risk_level'] == 'critical'),
                'high': sum(1 for a in all_alerts if a['risk_level'] == 'high'),
                'medium': sum(1 for a in all_alerts if a['risk_level'] == 'medium'),
                'low': sum(1 for a in all_alerts if a['risk_level'] == 'low')
            }
        }
        
        return stats
    
    def analyze_single_record(self, record):
        """
        Analyse un seul enregistrement de trafic
        
        Args:
            record: Dictionnaire avec les données de trafic
            
        Returns:
            Dictionnaire avec les résultats de l'analyse
        """
        if not self.is_initialized:
            self.initialize()
        
        results = {
            'is_attack': False,
            'alerts': [],
            'ml_prediction': None,
            'ml_confidence': None
        }
        
        # Analyse Rule-Based
        df = pd.DataFrame([record])
        rule_alerts = self.rule_engine.analyze_all(df)
        
        if rule_alerts:
            results['is_attack'] = True
            results['alerts'].extend(rule_alerts)
        
        # Analyse ML
        if self.ml_detector.is_trained:
            X, _, _, features = self.ml_detector.preprocessor.preprocess_features(df, fit=False)
            pred = self.ml_detector.model.predict(X)[0]
            proba = self.ml_detector.model.predict_proba(X)[0]
            confidence = max(proba)
            
            results['ml_prediction'] = int(pred)
            results['ml_confidence'] = float(confidence)
            
            if pred == 1 and confidence >= self.config.ML_CONFIDENCE_THRESHOLD:
                results['is_attack'] = True
                results['alerts'].append({
                    'alert_type': 'ML Detection',
                    'confidence': confidence,
                    'detection_method': 'ml' if not rule_alerts else 'hybrid'
                })
        
        return results


# Test du module
if __name__ == '__main__':
    print("=" * 60)
    print("TEST DU DÉTECTEUR HYBRIDE")
    print("=" * 60)
    
    config = Config()
    detector = HybridDetector(config)
    
    # Vérifier si les données existent
    if os.path.exists(config.TRAINING_DATA) and os.path.exists(config.TESTING_DATA):
        # Initialiser et évaluer
        stats = detector.evaluate_system(config.TESTING_DATA)
        
        print("\n" + "=" * 60)
        print("STATISTIQUES FINALES")
        print("=" * 60)
        print(f"Total alertes: {stats['total_alerts']}")
        print(f"Rule-Based: {stats['rule_alerts']}")
        print(f"ML: {stats['ml_alerts']}")
        print(f"Hybride: {stats['hybrid_alerts']}")
        print(f"Distribution risque: {stats['risk_distribution']}")
        
        if stats['ml_metrics']:
            print(f"\nMétriques ML:")
            for k, v in stats['ml_metrics'].items():
                print(f"  {k}: {v:.4f}")
    else:
        print(f"ERREUR: Fichiers de données non trouvés")
        print(f"  Training: {config.TRAINING_DATA}")
        print(f"  Testing: {config.TESTING_DATA}")
        print("\nVeuillez placer les fichiers dans le dossier 'data/'")
