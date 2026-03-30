let methodChartInstance = null;
let riskChartInstance = null;
let attackChartInstance = null;

function setDashboardStatus(message, statusClass = 'info') {
    const statusEl = document.getElementById('dashboardStatus');
    if (!statusEl) return;

    statusEl.classList.remove('alert-info', 'alert-success', 'alert-danger', 'alert-warning');
    statusEl.classList.add('alert-' + statusClass);
    statusEl.textContent = message;
}

function destroyExistingCharts() {
    if (methodChartInstance) {
        methodChartInstance.destroy();
        methodChartInstance = null;
    }
    if (riskChartInstance) {
        riskChartInstance.destroy();
        riskChartInstance = null;
    }
    if (attackChartInstance) {
        attackChartInstance.destroy();
        attackChartInstance = null;
    }
}

function renderDashboardCharts(data) {
    const methodNoData = document.getElementById('methodNoData');
    const riskNoData = document.getElementById('riskNoData');
    const attackNoData = document.getElementById('attackNoData');

    destroyExistingCharts();

    if (data.method_stats && data.method_stats.length) {
        methodNoData.style.display = 'none';
        const methodCtx = document.getElementById('methodChart').getContext('2d');
        methodChartInstance = new Chart(methodCtx, {
            type: 'doughnut',
            data: {
                labels: data.method_stats.map(m => m.detection_method.toUpperCase()),
                datasets: [{
                    data: data.method_stats.map(m => m.count),
                    backgroundColor: ['#6f42c1', '#17a2b8', '#dc3545'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });
    } else {
        methodNoData.style.display = 'block';
    }

    if (data.risk_stats && data.risk_stats.length) {
        riskNoData.style.display = 'none';
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        riskChartInstance = new Chart(riskCtx, {
            type: 'bar',
            data: {
                labels: data.risk_stats.map(r => r.risk_level.toUpperCase()),
                datasets: [{
                    label: "Nombre d'alertes",
                    data: data.risk_stats.map(r => r.count),
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true } }
            }
        });
    } else {
        riskNoData.style.display = 'block';
    }

    if (data.attack_distribution && data.attack_distribution.length) {
        attackNoData.style.display = 'none';
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        attackChartInstance = new Chart(attackCtx, {
            type: 'bar',
            data: {
                labels: data.attack_distribution.map(a => a.alert_type.substring(0, 20)),
                datasets: [{
                    label: 'Occurrences',
                    data: data.attack_distribution.map(a => a.count),
                    backgroundColor: '#1F4E79',
                    borderWidth: 0
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true } }
            }
        });
    } else {
        attackNoData.style.display = 'block';
    }
}

// Initialisation appelée depuis le template
function initDashboardCharts() {
    setDashboardStatus('Chargement des statistiques...', 'info');

    fetch('/api/stats')
        .then(response => {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }

            const dashboardStats = {
                method_stats: data.method_stats || data.methods || (window.dashboardData && window.dashboardData.method_stats) || [],
                risk_stats: data.risk_stats || data.risks || (window.dashboardData && window.dashboardData.risk_stats) || [],
                attack_distribution: data.attack_distribution || (window.dashboardData && window.dashboardData.attack_distribution) || []
            };

            renderDashboardCharts(dashboardStats);
            setDashboardStatus('Statistiques à jour (' + new Date().toLocaleTimeString() + ')', 'success');
        })
        .catch(error => {
            console.error('Erreur fetch /api/stats:', error);
            setDashboardStatus('Échec du chargement des statistiques : ' + error.message, 'danger');

            if (window.dashboardData) {
                setDashboardStatus('Utilisation des données en cache du template', 'warning');
                renderDashboardCharts(window.dashboardData);
            }
        });
}


function initDashboard() {
    // Initialiser les graphiques
    initDashboardCharts();

    // Ajouter l'événement du bouton Analyse
    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', runAnalysis);
    }
}

// Appeler initDashboard quand la page est prête
document.addEventListener('DOMContentLoaded', initDashboard);


function runAnalysis() {
    const btn = document.getElementById('analyzeBtn');
    const spinner = document.getElementById('analyzeSpinner');

    setDashboardStatus('Analyse en cours...', 'info');

    btn.disabled = true;
    spinner.style.display = 'inline-block';

    fetch('/analyze', {
        method: 'POST'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            setDashboardStatus(
                `Analyse terminée ✔️ (${data.total_alerts} alertes)`,
                'success'
            );

            //  إعادة تحميل الإحصائيات
            initDashboardCharts();

            // تحديث الصفحة  
            setTimeout(() => location.reload(), 1500);

        } else {
            throw new Error(data.error);
        }

        btn.disabled = false;
        spinner.style.display = 'none';
    })
    .catch(error => {
        console.error(error);
        setDashboardStatus('Erreur lors de l’analyse ❌: ' + error.message, 'danger');

        btn.disabled = false;
        spinner.style.display = 'none';
    });
}


// Rafraîchissement automatique toutes les 60 secondes
setInterval(initDashboardCharts, 60000);
