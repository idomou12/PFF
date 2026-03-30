# evaluate.py
"""
Script d'évaluation complète du système IDS Hybride
"""
import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

from config import Config
from ml_supervised import SupervisedDetector
from rule_engine import RuleEngine
from hybrid_detector import HybridDetector


def print_header(title):
    """Affiche un en-tête formaté"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def evaluate_ml_model(config):
    """
    Évalue le modèle ML de manière détaillée
    """
    print_header("ÉVALUATION DU MODÈLE ML SUPERVISÉ")
    
    detector = SupervisedDetector(config, model_type=config.MODEL_TYPE)
    
    # Vérifier les fichiers
    if not os.path.exists(config.TRAINING_DATA):
        print(f"ERREUR: Fichier d'entraînement non trouvé: {config.TRAINING_DATA}")
        return None
    
    if not os.path.exists(config.TESTING_DATA):
        print(f"ERREUR: Fichier de test non trouvé: {config.TESTING_DATA}")
        return None
    
    # Entraîner le modèle
    print("\n[1] Entraînement du modèle...")
    detector.train(config.TRAINING_DATA, multi_class=False)
    
    # Prédictions sur test
    print("\n[2] Prédictions sur données de test...")
    predictions, confidence, probs, df_test, y_true = detector.predict(config.TESTING_DATA)
    
    # Évaluation
    print("\n[3] Évaluation des performances...")
    metrics = detector.evaluate(y_true, predictions)
    
    # Importance des features
    print("\n[4] Importance des features...")
    importance = detector.get_feature_importance()
    if importance is not None:
        print("\nTop 15 Features les plus importantes:")
        print("-" * 50)
        for idx, row in importance.head(15).iterrows():
            bar = "█" * int(row['importance'] * 50)
            print(f"{row['feature']:<20} {bar} {row['importance']:.4f}")
    
    return {
        'detector': detector,
        'predictions': predictions,
        'confidence': confidence,
        'y_true': y_true,
        'metrics': metrics,
        'importance': importance
    }


def evaluate_rule_engine(config, df):
    """
    Évalue le moteur Rule-Based
    """
    print_header("ÉVALUATION DU MOTEUR RULE-BASED")
    
    engine = RuleEngine(config)
    alerts = engine.analyze_all(df)
    
    stats = engine.get_statistics(alerts)
    
    print(f"\nTotal alertes Rule-Based: {stats['total']}")
    print("\nPar type:")
    for alert_type, count in stats['by_type'].items():
        print(f"  - {alert_type}: {count}")
    
    print("\nPar niveau de risque:")
    for risk, count in stats['by_risk'].items():
        print(f"  - {risk}: {count}")
    
    return alerts, stats


def generate_report(ml_results, rule_alerts, output_dir='results'):
    """
    Génère un rapport visuel
    """
    print_header("GÉNÉRATION DU RAPPORT")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Configuration des graphiques
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Matrice de confusion
    if ml_results and ml_results['y_true'] is not None:
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(
            ml_results['y_true'].astype(int),
            ml_results['predictions'].astype(int)
        )
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
                   xticklabels=['Normal', 'Attaque'],
                   yticklabels=['Normal', 'Attaque'])
        axes[0, 0].set_title('Matrice de Confusion')
        axes[0, 0].set_xlabel('Prédiction')
        axes[0, 0].set_ylabel('Réalité')
    
    # 2. Distribution des scores de confiance
    if ml_results and ml_results['confidence'] is not None:
        axes[0, 1].hist(ml_results['confidence'], bins=50, color='#1F4E79', edgecolor='white')
        axes[0, 1].set_title('Distribution des Scores de Confiance ML')
        axes[0, 1].set_xlabel('Confiance')
        axes[0, 1].set_ylabel('Fréquence')
        axes[0, 1].axvline(x=0.7, color='red', linestyle='--', label='Seuil (0.7)')
        axes[0, 1].legend()
    
    # 3. Importance des features
    if ml_results and ml_results['importance'] is not None:
        top_features = ml_results['importance'].head(10)
        axes[1, 0].barh(top_features['feature'], top_features['importance'], color='#2E75B6')
        axes[1, 0].set_title('Top 10 Features Importantes')
        axes[1, 0].invert_yaxis()
    
    # 4. Métriques de performance
    if ml_results and ml_results['metrics']:
        metrics = ml_results['metrics']
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        metric_values = [metrics['accuracy'], metrics['precision'], 
                        metrics['recall'], metrics['f1_score']]
        
        bars = axes[1, 1].bar(metric_names, metric_values, color=['#1F4E79', '#2E75B6', '#5B9BD5', '#9DC3E6'])
        axes[1, 1].set_title('Métriques de Performance')
        axes[1, 1].set_ylim(0, 1)
        axes[1, 1].set_ylabel('Score')
        
        # Ajouter les valeurs sur les barres
        for bar, val in zip(bars, metric_values):
            axes[1, 1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                          f'{val:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    
    # Sauvegarder
    report_path = os.path.join(output_dir, 'evaluation_report.png')
    plt.savefig(report_path, dpi=150, bbox_inches='tight')
    print(f"\n✓ Rapport sauvegardé: {report_path}")
    
    plt.close()
    
    return report_path


def main():
    """
    Fonction principale d'évaluation
    """
    print("\n" + "=" * 70)
    print("  ÉVALUATION COMPLÈTE DU SYSTÈME IDS HYBRIDE")
    print("  Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)
    
    config = Config()
    
    # Vérifier les fichiers de données
    print("\nVérification des fichiers de données...")
    print(f"  Training: {config.TRAINING_DATA} - {'✓' if os.path.exists(config.TRAINING_DATA) else '✗'}")
    print(f"  Testing: {config.TESTING_DATA} - {'✓' if os.path.exists(config.TESTING_DATA) else '✗'}")
    
    if not os.path.exists(config.TRAINING_DATA) or not os.path.exists(config.TESTING_DATA):
        print("\nERREUR: Fichiers de données non trouvés!")
        print("Veuillez placer les fichiers suivants dans le dossier 'data/':")
        print("  - UNSW_NB15_training-set.csv")
        print("  - UNSW_NB15_testing-set.csv")
        return
    
    # Charger les données de test pour Rule-Based
    print("\nChargement des données de test...")
    df_test = pd.read_csv(config.TESTING_DATA)
    df_test.columns = df_test.columns.str.strip()
    print(f"  {df_test.shape[0]} lignes chargées")
    
    # 1. Évaluation ML Supervisé
    ml_results = evaluate_ml_model(config)
    
    # 2. Évaluation Rule-Based
    rule_alerts, rule_stats = evaluate_rule_engine(config, df_test)
    
    # 3. Évaluation Hybride
    print_header("ÉVALUATION DU SYSTÈME HYBRIDE")
    hybrid = HybridDetector(config)
    hybrid_stats = hybrid.evaluate_system(config.TESTING_DATA)
    
    # 4. Résumé final
    print_header("RÉSUMÉ FINAL")
    
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│               RÉSULTATS DE L'ÉVALUATION                     │")
    print("├─────────────────────────────────────────────────────────────┤")
    
    if ml_results and ml_results['metrics']:
        print("│ MODÈLE ML SUPERVISÉ                                        │")
        print(f"│   Accuracy:  {ml_results['metrics']['accuracy']:.4f}                                   │")
        print(f"│   Precision: {ml_results['metrics']['precision']:.4f}                                   │")
        print(f"│   Recall:    {ml_results['metrics']['recall']:.4f}                                   │")
        print(f"│   F1-Score:  {ml_results['metrics']['f1_score']:.4f}                                   │")
    
    print("├─────────────────────────────────────────────────────────────┤")
    print("│ SYSTÈME HYBRIDE                                             │")
    print(f"│   Total alertes:    {hybrid_stats['total_alerts']:<10}                            │")
    print(f"│   Rule-Based:       {hybrid_stats['rule_alerts']:<10}                            │")
    print(f"│   ML seul:          {hybrid_stats['ml_alerts']:<10}                            │")
    print(f"│   Hybride:          {hybrid_stats['hybrid_alerts']:<10}                            │")
    print("└─────────────────────────────────────────────────────────────┘")
    
    # 5. Générer le rapport visuel
    report_path = generate_report(ml_results, rule_alerts)
    
    print("\n" + "=" * 70)
    print("  ÉVALUATION TERMINÉE AVEC SUCCÈS")
    print("=" * 70)


if __name__ == '__main__':
    main()
