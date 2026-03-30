# ml_supervised.py
"""
Module de Machine Learning Supervisé pour l'IDS Hybride
Utilise Random Forest ou XGBoost pour la classification
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder
import joblib
import os
from datetime import datetime
from config import Config
from preprocess import DataPreprocessor

# Optionnel: XGBoost
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost non disponible. Utilisez 'pip install xgboost' pour l'installer.")


class SupervisedDetector:
    """
    Détecteur basé sur l'apprentissage supervisé
    """
    
    def __init__(self, config=None, model_type='random_forest'):
        """
        Initialise le détecteur supervisé
        
        Args:
            config: Configuration du projet
            model_type: Type de modèle ('random_forest', 'xgboost', 'logistic')
        """
        self.config = config or Config()
        self.model_type = model_type
        self.model = None
        self.preprocessor = DataPreprocessor(self.config)
        self.attack_encoder = LabelEncoder()
        self.multi_class = False
        self.is_trained = False
    
    def _create_model(self):
        """
        Crée le modèle selon le type spécifié
        
        Returns:
            Modèle scikit-learn
        """
        if self.model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1,
                verbose=1
            )
        elif self.model_type == 'xgboost' and XGBOOST_AVAILABLE:
            return XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                objective='binary:logistic',
                random_state=42,
                n_jobs=-1,
                verbosity=1
            )
        elif self.model_type == 'logistic':
            return LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
        else:
            print(f"Modèle {self.model_type} non disponible, utilisation de Random Forest")
            return RandomForestClassifier(
                n_estimators=100,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
    
    def train(self, training_path=None, multi_class=False):
        """
        Entraîne le modèle sur les données d'entraînement
        
        Args:
            training_path: Chemin vers le fichier d'entraînement
            multi_class: Si True, classification multi-classes
            
        Returns:
            Le modèle entraîné
        """
        training_path = training_path or self.config.TRAINING_DATA
        self.multi_class = multi_class
        
        print("=" * 60)
        print("ENTRAÎNEMENT DU MODÈLE SUPERVISÉ")
        print("=" * 60)
        print(f"Type: {self.model_type}")
        print(f"Classification: {'Multi-classes' if multi_class else 'Binaire'}")
        print(f"Données: {training_path}")
        
        # Vérifier que le fichier existe
        if not os.path.exists(training_path):
            raise FileNotFoundError(f"Fichier non trouvé: {training_path}")
        
        # Prétraitement
        print("\n[1/4] Prétraitement des données...")
        X_train, y_train, df_train, features = self.preprocessor.preprocess_pipeline(
            training_path, fit=True, multi_class=multi_class
        )
        
        print(f"  -> Features: {len(features)}")
        print(f"  -> Échantillons: {X_train.shape[0]}")
        
        # Encoder les labels si multi-classes
        if multi_class:
            y_train = self.attack_encoder.fit_transform(y_train.astype(str))
            print(f"  -> Classes: {list(self.attack_encoder.classes_)}")
        else:
            y_train = y_train.astype(int).values
            print(f"  -> Distribution: Normal={sum(y_train==0)}, Attaque={sum(y_train==1)}")
        
        # Créer le modèle
        print(f"\n[2/4] Création du modèle {self.model_type}...")
        self.model = self._create_model()
        
        # Entraîner
        print(f"\n[3/4] Entraînement en cours...")
        self.model.fit(X_train, y_train)
        
        # Évaluer sur training
        y_pred = self.model.predict(X_train)
        train_acc = accuracy_score(y_train, y_pred)
        print(f"  -> Accuracy training: {train_acc:.4f}")
        
        # Sauvegarder
        print(f"\n[4/4] Sauvegarde du modèle...")
        self._save_model()
        
        self.is_trained = True
        print("\n✓ Entraînement terminé!")
        
        return self.model
    
    def _save_model(self):
        """Sauvegarde le modèle et les préprocesseurs"""
        os.makedirs(self.config.MODEL_DIR, exist_ok=True)
        
        # Sauvegarder le modèle
        joblib.dump(self.model, self.config.MODEL_PATH)
        print(f"  -> Modèle: {self.config.MODEL_PATH}")
        
        # Sauvegarder les préprocesseurs
        self.preprocessor.save_preprocessors()
        
        # Sauvegarder l'encodeur de labels si multi-classes
        if self.multi_class:
            encoder_path = os.path.join(self.config.MODEL_DIR, 'attack_encoder.joblib')
            joblib.dump(self.attack_encoder, encoder_path)
            print(f"  -> Encodeur attaques: {encoder_path}")
    
    def load_model(self):
        """
        Charge un modèle pré-entraîné
        
        Returns:
            True si chargement réussi, False sinon
        """
        if not os.path.exists(self.config.MODEL_PATH):
            print(f"Modèle non trouvé: {self.config.MODEL_PATH}")
            return False
        
        try:
            self.model = joblib.load(self.config.MODEL_PATH)
            self.preprocessor.load_preprocessors()
            self.is_trained = True
            print("✓ Modèle chargé avec succès")
            return True
        except Exception as e:
            print(f"Erreur lors du chargement: {e}")
            return False
    
    def predict(self, data_path=None, X=None):
        """
        Prédit les labels pour de nouvelles données
        
        Args:
            data_path: Chemin vers le fichier de données
            X: Features prétraitées (optionnel)
            
        Returns:
            predictions: Labels prédits
            confidence: Scores de confiance
            probabilities: Probabilités complètes
            df: DataFrame original
            y_true: Labels réels (si disponibles)
        """
        if not self.is_trained and self.model is None:
            raise ValueError("Le modèle n'est pas entraîné. Appelez train() ou load_model() d'abord.")
        
        if X is None:
            # Prétraiter les nouvelles données
            X, y_true, df, features = self.preprocessor.preprocess_pipeline(
                data_path, fit=False, multi_class=self.multi_class
            )
        else:
            y_true = None
            df = None
        
        print(f"Prédiction sur {X.shape[0]} échantillons...")
        
        # Prédictions
        predictions = self.model.predict(X)
        
        # Probabilités
        probabilities = self.model.predict_proba(X)
        confidence = np.max(probabilities, axis=1)
        
        # Décoder si multi-classes
        if self.multi_class:
            predictions = self.attack_encoder.inverse_transform(predictions)
        
        return predictions, confidence, probabilities, df, y_true
    
    def evaluate(self, y_true, y_pred):
        """
        Évalue les performances du modèle
        
        Args:
            y_true: Vrais labels
            y_pred: Labels prédits
            
        Returns:
            Dictionnaire de métriques
        """
        # Encoder si nécessaire
        if self.multi_class and isinstance(y_true.iloc[0], str):
            y_true = self.attack_encoder.transform(y_true.astype(str))
        
        y_true = np.array(y_true).astype(int)
        y_pred = np.array(y_pred).astype(int)
        
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
        }
        
        print("\n" + "=" * 60)
        print("ÉVALUATION DU MODÈLE")
        print("=" * 60)
        print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        
        # Matrice de confusion
        cm = confusion_matrix(y_true, y_pred)
        print("\nMatrice de Confusion:")
        print(cm)
        
        # Rapport détaillé
        print("\nRapport de Classification:")
        if self.multi_class:
            target_names = self.attack_encoder.classes_
        else:
            target_names = ['Normal', 'Attaque']
        print(classification_report(y_true, y_pred, target_names=target_names, zero_division=0))
        
        return metrics
    
    def get_alerts(self, predictions, confidence, df, threshold=None):
        """
        Génère des alertes basées sur les prédictions ML
        
        Args:
            predictions: Labels prédits
            confidence: Scores de confiance
            df: DataFrame original
            threshold: Seuil de confiance minimum
            
        Returns:
            Liste d'alertes
        """
        threshold = threshold or self.config.ML_CONFIDENCE_THRESHOLD
        alerts = []
        
        for i, (pred, conf) in enumerate(zip(predictions, confidence)):
            # Ne signaler que si confiance > seuil ET attaque détectée
            is_attack = pred != 'Normal' if self.multi_class else pred == 1
            
            if is_attack and conf >= threshold:
                # Déterminer le niveau de risque via configuration
                if conf >= self.config.RISK_THRESHOLD_CRITICAL:
                    risk_level = 'critical'
                elif conf >= self.config.RISK_THRESHOLD_HIGH:
                    risk_level = 'high'
                elif conf >= self.config.RISK_THRESHOLD_MEDIUM:
                    risk_level = 'medium'
                else:
                    risk_level = 'low'
                
                # Obtenir les IPs
                src_ip = df.iloc[i].get('source_ip', 'unknown') if 'source_ip' in df.columns else 'unknown'
                dest_ip = df.iloc[i].get('dest_ip', 'unknown') if 'dest_ip' in df.columns else 'unknown'
                
                attack_type = pred if self.multi_class else 'Attack'
                
                alert = {
                    'source_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': f'ML Detection: {attack_type}',
                    'description': f'Modèle: {self.model_type}, Confiance: {conf:.2%}',
                    'risk_level': risk_level,
                    'detection_method': 'ml',
                    'confidence': float(conf),
                    'predicted_attack': str(pred),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                alerts.append(alert)
        
        return alerts
    
    def get_feature_importance(self):
        """
        Retourne l'importance des features (si disponible)
        
        Returns:
            DataFrame avec les features et leur importance
        """
        if self.model is None:
            return None
        
        if hasattr(self.model, 'feature_importances_'):
            importance = pd.DataFrame({
                'feature': self.preprocessor.feature_names,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            return importance
        
        return None


# Test du module
if __name__ == '__main__':
    print("=" * 60)
    print("TEST DU MODULE ML SUPERVISÉ")
    print("=" * 60)
    
    config = Config()
    detector = SupervisedDetector(config, model_type='random_forest')
    
    # Vérifier si les données existent
    if os.path.exists(config.TRAINING_DATA):
        # Entraînement
        detector.train(multi_class=False)
        
        # Prédiction sur test
        if os.path.exists(config.TESTING_DATA):
            predictions, confidence, probs, df, y_true = detector.predict(config.TESTING_DATA)
            
            # Évaluation
            metrics = detector.evaluate(y_true, predictions)
            
            # Alertes
            alerts = detector.get_alerts(predictions, confidence, df)
            print(f"\nAlertes générées: {len(alerts)}")
            
            # Importance des features
            importance = detector.get_feature_importance()
            if importance is not None:
                print("\nTop 10 Features:")
                print(importance.head(10).to_string())
    else:
        print(f"ERREUR: Fichier non trouvé: {config.TRAINING_DATA}")
        print("Veuillez placer les fichiers de données dans le dossier 'data/'")
