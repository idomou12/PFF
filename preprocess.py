# preprocess.py
"""
Module de prétraitement des données pour l'IDS Hybride
Gère le chargement, la sélection des features et la normalisation
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os
from config import Config


class DataPreprocessor:
    """
    Classe pour le prétraitement des données du dataset UNSW-NB15
    """
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []
        
    def load_data(self, filepath):
        """
        Charge un fichier CSV et retourne un DataFrame
        
        Args:
            filepath: Chemin vers le fichier CSV
            
        Returns:
            DataFrame pandas
        """
        print(f"Chargement des données: {filepath}")
        df = pd.read_csv(filepath)
        
        # Nettoyer les noms de colonnes (supprimer espaces)
        df.columns = df.columns.str.strip()
        
        print(f"  -> {df.shape[0]} lignes, {df.shape[1]} colonnes")
        return df
    
    def get_available_features(self, df):
        """
        Retourne les features disponibles dans le DataFrame
        
        Args:
            df: DataFrame pandas
            
        Returns:
            Tuple (numeric_features, categorical_features)
        """
        # Features numériques disponibles
        numeric_cols = [c for c in self.config.NUMERIC_FEATURES if c in df.columns]
        
        # Features catégoriques disponibles
        categorical_cols = [c for c in self.config.CATEGORICAL_FEATURES if c in df.columns]
        
        return numeric_cols, categorical_cols
    
    def preprocess_features(self, df, fit=True):
        """
        Prétraite les features pour l'entraînement ou la prédiction
        
        Args:
            df: DataFrame source
            fit: Si True, ajuste les transformateurs (entraînement)
                 Si False, utilise les transformateurs existants (prédiction)
                 
        Returns:
            X: Features prétraitées (numpy array)
            feature_names: Liste des noms de features utilisées
        """
        # Obtenir les features disponibles
        numeric_cols, categorical_cols = self.get_available_features(df)
        
        # 1. Traiter les features numériques
        X_numeric = df[numeric_cols].copy()
        
        # Remplacer les valeurs manquantes et infinies
        X_numeric = X_numeric.fillna(0)
        X_numeric = X_numeric.replace([np.inf, -np.inf], 0)
        
        # 2. Traiter les features catégoriques
        X_categorical = pd.DataFrame()
        
        for col in categorical_cols:
            if col in df.columns:
                # Remplacer les valeurs manquantes
                df[col] = df[col].fillna('unknown')
                
                if fit:
                    # Créer et ajuster l'encodeur
                    le = LabelEncoder()
                    # Gérer les nouvelles catégories potentielles
                    unique_values = df[col].astype(str).unique()
                    le.fit(unique_values)
                    self.label_encoders[col] = le
                
                # Encoder
                try:
                    X_categorical[col] = self.label_encoders[col].transform(df[col].astype(str))
                except ValueError as e:
                    # Gérer les nouvelles catégories non vues pendant l'entraînement
                    X_categorical[col] = df[col].apply(
                        lambda x: self.label_encoders[col].transform([str(x)])[0] 
                        if str(x) in self.label_encoders[col].classes_ 
                        else -1
                    )
        
        # 3. Combiner les features
        if len(categorical_cols) > 0:
            X_combined = pd.concat([X_numeric, X_categorical], axis=1)
        else:
            X_combined = X_numeric
        
        self.feature_names = numeric_cols + list(categorical_cols)
        
        # 4. Normaliser les features numériques
        if fit:
            X_combined[numeric_cols] = self.scaler.fit_transform(X_combined[numeric_cols])
        else:
            X_combined[numeric_cols] = self.scaler.transform(X_combined[numeric_cols])
        
        return X_combined.values, self.feature_names
    
    def extract_labels(self, df, multi_class=False):
        """
        Extrait les labels du DataFrame
        
        Args:
            df: DataFrame source
            multi_class: Si True, retourne attack_cat, sinon label binaire
            
        Returns:
            y: Labels (Series pandas)
        """
        if multi_class:
            if self.config.ATTACK_CAT_COL in df.columns:
                y = df[self.config.ATTACK_CAT_COL].fillna('Normal')
            else:
                raise ValueError(f"Colonne {self.config.ATTACK_CAT_COL} non trouvée")
        else:
            if self.config.LABEL_COL in df.columns:
                y = df[self.config.LABEL_COL]
            else:
                raise ValueError(f"Colonne {self.config.LABEL_COL} non trouvée")
        
        return y
    
    def preprocess_pipeline(self, filepath, fit=True, multi_class=False):
        """
        Pipeline complet de prétraitement
        
        Args:
            filepath: Chemin vers le fichier CSV
            fit: Si True, ajuste les transformateurs
            multi_class: Si True, classification multi-classes
            
        Returns:
            X: Features prétraitées
            y: Labels (ou None si pas de labels)
            df: DataFrame original
            feature_names: Liste des noms de features
        """
        # Charger les données
        df = self.load_data(filepath)
        
        # Extraire les labels si disponibles
        y = None
        if self.config.LABEL_COL in df.columns:
            y = self.extract_labels(df, multi_class=multi_class)
        
        # Prétraiter les features
        X, feature_names = self.preprocess_features(df, fit=fit)
        
        return X, y, df, feature_names
    
    def save_preprocessors(self):
        """Sauvegarde le scaler et les encodeurs"""
        os.makedirs(self.config.MODEL_DIR, exist_ok=True)
        
        joblib.dump(self.scaler, self.config.SCALER_PATH)
        joblib.dump(self.label_encoders, self.config.ENCODERS_PATH)
        
        print(f"  -> Scaler sauvegardé: {self.config.SCALER_PATH}")
        print(f"  -> Encodeurs sauvegardés: {self.config.ENCODERS_PATH}")
    
    def load_preprocessors(self):
        """Charge le scaler et les encodeurs"""
        if os.path.exists(self.config.SCALER_PATH):
            self.scaler = joblib.load(self.config.SCALER_PATH)
        
        if os.path.exists(self.config.ENCODERS_PATH):
            self.label_encoders = joblib.load(self.config.ENCODERS_PATH)
        
        print("  -> Préprocesseurs chargés")


# Test du module
if __name__ == '__main__':
    print("=" * 60)
    print("TEST DU MODULE DE PRÉTRAITEMENT")
    print("=" * 60)
    
    preprocessor = DataPreprocessor()
    
    # Vérifier si le fichier d'entraînement existe
    if os.path.exists(Config.TRAINING_DATA):
        X, y, df, features = preprocessor.preprocess_pipeline(
            Config.TRAINING_DATA, 
            fit=True, 
            multi_class=False
        )
        
        print(f"\nFeatures utilisées ({len(features)}): {features[:5]}...")
        print(f"Shape X: {X.shape}")
        print(f"Shape y: {y.shape if y is not None else 'N/A'}")
        
        if y is not None:
            print(f"\nDistribution des labels:")
            print(y.value_counts())
    else:
        print(f"ERREUR: Fichier non trouvé: {Config.TRAINING_DATA}")
        print("Veuillez placer les fichiers de données dans le dossier 'data/'")
