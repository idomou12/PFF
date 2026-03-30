// Actions globales du dashboard
function runAnalysis() {
    const btn = document.getElementById('analyzeBtn');
    const spinner = document.getElementById('analyzeSpinner');
    const originalText = btn.innerHTML;

    btn.disabled = true;
    spinner.style.display = 'inline-block';
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyse en cours...';

    fetch('/analyze', {method: 'POST'})
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Analyse terminée!\n\nTotal alertes: ${data.total_alerts}\nRule-Based: ${data.rule_alerts}\nML: ${data.ml_alerts}\nHybride: ${data.hybrid_alerts}`);
                location.reload();
            } else {
                alert('Erreur: ' + data.error);
            }
        })
        .catch(error => {
            alert('Erreur: ' + error);
        })
        .finally(() => {
            btn.disabled = false;
            spinner.style.display = 'none';
            btn.innerHTML = originalText;
        });
}

function trainModel() {
    if (confirm('Voulez-vous réentraîner le modèle ML? Cela peut prendre quelques minutes.')) {
        fetch('/train', {method: 'POST'})
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Modèle réentraîné avec succès!');
                } else {
                    alert('Erreur: ' + data.error);
                }
            });
    }
}

function clearAlerts() {
    if (confirm('Voulez-vous effacer toutes les alertes?')) {
        fetch('/clear-alerts', {method: 'POST'})
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(`${data.deleted} alertes supprimées.`);
                    location.reload();
                } else {
                    alert('Erreur: ' + data.error);
                }
            });
    }
}

function exportAlerts() {
    fetch('/export-alerts')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`${data.count} alertes exportées vers:\n${data.file}`);
            } else {
                alert('Erreur: ' + data.error);
            }
        });
}
