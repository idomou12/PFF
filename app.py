# app.py
"""
Application Flask pour le Dashboard IDS Hybride
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from jinja2 import TemplateNotFound
import mysql.connector
from mysql.connector import Error
import pandas as pd
import os
from datetime import datetime
import threading

from config import Config
from hybrid_detector import HybridDetector

# Créer l'application Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Instance globale du détecteur
detector = None


def get_db_connection():
    """
    Crée une connexion à la base de données MySQL
    
    Returns:
        Connexion MySQL ou None si erreur
    """
    try:
        conn = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )
        return conn
    except Error as e:
        print(f"Erreur connexion MySQL: {e}")
        return None


def init_detector():
    """
    Initialise le détecteur hybride (lazy loading)
    
    Returns:
        Instance de HybridDetector
    """
    global detector
    if detector is None:
        print("Initialisation du détecteur...")
        detector = HybridDetector(Config())
        detector.initialize()
    return detector


# ==================== ROUTES ====================

@app.route('/')
def index():
    """
    Page d'accueil - Dashboard principal
    """
    conn = get_db_connection()
    
    # Données par défaut si pas de connexion DB
    stats = {
        'total_alerts': 0,
        'total_traffic': 0,
        'critical_alerts': 0,
        'today_alerts': 0
    }
    method_stats = []
    risk_stats = []
    recent_alerts = []
    attack_distribution = []
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Total alertes
            cursor.execute("SELECT COUNT(*) as total FROM alerts")
            result = cursor.fetchone()
            if result:
                stats['total_alerts'] = result['total']
            
            # Total trafic
            cursor.execute("SELECT COUNT(*) as total FROM traffic_logs")
            result = cursor.fetchone()
            if result:
                stats['total_traffic'] = result['total']
            
            # Alertes critiques
            cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE risk_level = 'critical'")
            result = cursor.fetchone()
            if result:
                stats['critical_alerts'] = result['total']
            
            # Alertes aujourd'hui
            cursor.execute("""
                SELECT COUNT(*) as total FROM alerts 
                WHERE DATE(timestamp) = CURDATE()
            """)
            result = cursor.fetchone()
            if result:
                stats['today_alerts'] = result['total']
            
            # Alertes par méthode de détection
            cursor.execute("""
                SELECT detection_method, COUNT(*) as count 
                FROM alerts 
                GROUP BY detection_method
            """)
            method_stats = cursor.fetchall()
            
            # Alertes par niveau de risque
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count 
                FROM alerts 
                GROUP BY risk_level
                ORDER BY 
                    CASE risk_level 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                    END
            """)
            risk_stats = cursor.fetchall()
            
            # Distribution par type d'attaque
            cursor.execute("""
                SELECT alert_type, COUNT(*) as count 
                FROM alerts 
                GROUP BY alert_type 
                ORDER BY count DESC 
                LIMIT 10
            """)
            attack_distribution = cursor.fetchall()
            
            # Alertes récentes
            cursor.execute("""
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 20
            """)
            recent_alerts = cursor.fetchall()
            
            cursor.close()
        except Error as e:
            flash(f"Erreur base de données: {e}", "error")
        finally:
            conn.close()
    
    return render_template('dashboard.html',
                         stats=stats,
                         method_stats=method_stats,
                         risk_stats=risk_stats,
                         attack_distribution=attack_distribution,
                         recent_alerts=recent_alerts)


@app.route('/alerts')
def alerts():
    """
    Page des alertes avec filtres
    """
    conn = get_db_connection()
    alerts_list = []
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Filtres
            risk_level = request.args.get('risk_level', '')
            method = request.args.get('method', '')
            search = request.args.get('search', '')
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if risk_level:
                query += " AND risk_level = %s"
                params.append(risk_level)
            
            if method:
                query += " AND detection_method = %s"
                params.append(method)
            
            if search:
                query += " AND (source_ip LIKE %s OR alert_type LIKE %s OR description LIKE %s)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term])
            
            query += " ORDER BY timestamp DESC LIMIT 500"
            
            cursor.execute(query, params)
            alerts_list = cursor.fetchall()
            
            cursor.close()
        except Error as e:
            flash(f"Erreur: {e}", "error")
        finally:
            conn.close()
    
    return render_template('alerts.html', alerts=alerts_list)


@app.route('/run-analysis', methods=['GET', 'POST'])
def run_analysis():
    """
    Alias : route historique + support navigateur. GET retourne un message informatif.
    """
    if request.method == 'GET':
        return jsonify({
            'success': False,
            'error': 'Utilisez POST pour lancer l\'analyse.'
        }), 405
    return analyze()


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Lance l'analyse sur le dataset de test
    """
    try:
        det = init_detector()
        
        if not os.path.exists(Config.TESTING_DATA):
            return jsonify({
                'success': False,
                'error': f"Fichier de test non trouvé: {Config.TESTING_DATA}"
            })
        
        # Analyser les données
        alerts, predictions, confidence, y_true = det.analyze(Config.TESTING_DATA)
        
        # Sauvegarder dans MySQL
        saved_count = 0
        conn = get_db_connection()
        
        if conn:
            try:
                cursor = conn.cursor()

                # Supprimer les anciennes alertes avant d'insérer les nouvelles
                cursor.execute("DELETE FROM alerts")
                
                for alert in alerts:
                    cursor.execute("""
                        INSERT INTO alerts 
                        (source_ip, dest_ip, alert_type, description, 
                         risk_level, confidence_score, detection_method, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        alert['source_ip'],
                        alert.get('dest_ip', 'unknown'),
                        alert['alert_type'],
                        alert['description'],
                        alert['risk_level'],
                        alert.get('confidence', 0),
                        alert['detection_method'],
                        alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    ))
                    saved_count += 1
                
                conn.commit()
                cursor.close()
            except Error as e:
                print(f"Erreur sauvegarde: {e}")
            finally:
                conn.close()
        
        # Calculer les statistiques
        rule_count = sum(1 for a in alerts if a['detection_method'] == 'rule')
        ml_count = sum(1 for a in alerts if a['detection_method'] == 'ml')
        hybrid_count = sum(1 for a in alerts if a['detection_method'] == 'hybrid')
        
        return jsonify({
            'success': True,
            'total_alerts': len(alerts),
            'saved_alerts': saved_count,
            'rule_alerts': rule_count,
            'ml_alerts': ml_count,
            'hybrid_alerts': hybrid_count,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@app.route('/api/stats')
def api_stats():
    """
    API pour les statistiques (pour les graphiques)
    """
    conn = get_db_connection()
    stats = {}
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Alertes par jour (7 derniers jours)
            cursor.execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(timestamp)
                ORDER BY date
            """)
            stats['daily'] = cursor.fetchall()
            
            # Distribution par méthode
            cursor.execute("""
                SELECT detection_method, COUNT(*) as count
                FROM alerts
                GROUP BY detection_method
            """)
            stats['methods'] = cursor.fetchall()
            
            # Distribution par risque
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM alerts
                GROUP BY risk_level
            """)
            stats['risks'] = cursor.fetchall()

            # Distribution par type d'attaque (Top 10)
            cursor.execute("""
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['attack_distribution'] = cursor.fetchall()
            
            cursor.close()
        except Error as e:
            stats['error'] = str(e)
        finally:
            conn.close()
    
    return jsonify(stats)


@app.route('/api/model-info')
def api_model_info():
    """
    API pour les informations du modèle
    """
    det = init_detector()
    
    info = {
        'model_type': Config.MODEL_TYPE,
        'is_trained': det.ml_detector.is_trained,
        'confidence_threshold': Config.ML_CONFIDENCE_THRESHOLD
    }
    
    # Ajouter l'importance des features si disponible
    if det.ml_detector.is_trained:
        importance = det.ml_detector.get_feature_importance()
        if importance is not None:
            info['top_features'] = importance.head(10).to_dict('records')
    
    return jsonify(info)


@app.route('/train', methods=['POST'])
def train_model():
    """
    Réentraîne le modèle ML
    """
    global detector
    
    try:
        if not os.path.exists(Config.TRAINING_DATA):
            return jsonify({
                'success': False,
                'error': f"Fichier d'entraînement non trouvé: {Config.TRAINING_DATA}"
            })
        
        # Réinitialiser le détecteur
        detector = HybridDetector(Config())
        detector.initialize(force_train=True)
        
        return jsonify({
            'success': True,
            'message': 'Modèle réentraîné avec succès'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@app.route('/clear-alerts', methods=['POST'])
def clear_alerts():
    """
    Supprime toutes les alertes
    """
    conn = get_db_connection()
    
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            conn.commit()
            deleted = cursor.rowcount
            cursor.close()
            
            return jsonify({
                'success': True,
                'deleted': deleted
            })
        except Error as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
        finally:
            conn.close()
    
    return jsonify({
        'success': False,
        'error': 'Impossible de se connecter à la base de données'
    })


@app.route('/export-alerts')
def export_alerts():
    """
    Exporte les alertes en CSV
    """
    conn = get_db_connection()
    
    if conn:
        try:
            df = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
            csv_path = os.path.join(Config.BASE_DIR, 'alerts_export.csv')
            df.to_csv(csv_path, index=False)
            
            return jsonify({
                'success': True,
                'file': csv_path,
                'count': len(df)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
        finally:
            conn.close()
    
    return jsonify({
        'success': False,
        'error': 'Impossible de se connecter à la base de données'
    })


# ==================== ERREURS ====================

@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'))


@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except TemplateNotFound:
        return '404 Not Found', 404


@app.errorhandler(500)
def internal_server_error(e):
    try:
        return render_template('500.html'), 500
    except TemplateNotFound:
        return '500 Internal Server Error', 500


# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 60)
    print("DÉMARRAGE DE L'APPLICATION IDS HYBRIDE")
    print("=" * 60)
    print(f"Mode debug: {Config.DEBUG}")
    print(f"Base de données: {Config.MYSQL_DB}")
    print(f"Port: 5000")
    print("=" * 60)
    
    app.run(
        debug=Config.DEBUG,
        host='0.0.0.0',
        port=5000
    )
