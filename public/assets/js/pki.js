// pki.js - Gestion complète PKI avec persistance JSON

// ---------- Configuration ----------
const API_BASE = window.APP_CONFIG?.api?.base || '';
const API_ENDPOINTS = window.APP_CONFIG?.api?.endpoints || {};
const ERROR_MESSAGES = window.ERROR_MESSAGES || {};

// ---------- État global de l'application ----------
let appState = {
    certificates: [],
    users: [],
    signatures: [],
    auditLog: [],
    hsmStatus: { 
        connected: false, 
        cardPresent: false,
        lastCheck: null,
        deviceInfo: null
    },
    currentTab: 'dashboard',
    isLoading: false,
    selectedFile: null,
    filters: {
        certificateStatus: 'all',
        certificateType: 'all',
        searchTerm: ''
    }
};

// ---------- Gestionnaire de certificats ----------
class PKICertificateManager {
    constructor() {
        this.baseURL = window.APP_CONFIG?.api?.base || '';
        this.endpoints = window.APP_CONFIG?.api?.endpoints || {};
    }

    // 🔄 Chargement des certificats
    async loadCertificates(filters = {}) {
        try {
            this.showLoadingState();
            
            const params = new URLSearchParams();
            if (filters.status && filters.status !== 'all') params.append('status', filters.status);
            if (filters.type && filters.type !== 'all') params.append('type', filters.type);
            if (filters.search) params.append('search', filters.search);

            const response = await this.apiFetch(`${this.endpoints.certificates}?${params}`);
            
            if (response.ok) {
                const data = await response.json();
                appState.certificates = Array.isArray(data) ? data : [];
                this.renderCertificatesTable(appState.certificates);
                this.updateCertificateSelects();
            } else {
                 appState.certificates = [];
                 this.renderCertificatesTable([]);
                 this.updateCertificateSelects();
                 throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Erreur chargement certificats:', error);
            this.showError('Erreur lors du chargement des certificats: ' + error.message);
            this.renderEmptyState();
        }
    }

    // 🎨 Rendu du tableau des certificats
    renderCertificatesTable(certificates) {
        const tbody = document.getElementById('certificatesTableBody');
        
        if (!certificates || certificates.length === 0) {
            tbody.innerHTML = this.getEmptyStateHTML();
            return;
        }

        // Appliquer les filtres
        const filteredCertificates = this.filterCertificates(certificates);
        
        tbody.innerHTML = filteredCertificates.map(cert => `
            <tr class="hover-row cert-status-${cert.status}">
                <td class="p-4">
                    <div class="font-medium text-slate-800">${this.escapeHTML(this.getSubjectCN(cert.subject))}</div>
                    <div class="text-sm text-slate-500">S/N: ${this.escapeHTML(cert.serial || cert.serialNumber)}</div>
                </td>
                <td class="p-4 text-slate-600">${this.escapeHTML(this.getSubjectCN(cert.issuer))}</td>
                <td class="p-4">
                    <div class="text-slate-600">${this.formatDate(cert.expires)}</div>
                    <div class="text-xs text-slate-400">${this.getDaysUntilExpiry(cert.expires)} jours restants</div>
                </td>
                <td class="p-4">
                    ${this.getCertificateTypeBadge(cert.type)}
                </td>
                <td class="p-4">
                    ${this.getStatusBadge(cert.status)}
                </td>
                <td class="p-4 text-center">
                    <div class="flex justify-center gap-2">
                        <button class="btn-icon text-blue-600 view-cert" data-id="${cert.id}" title="Voir les détails">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn-icon text-green-600 download-cert" data-id="${cert.id}" title="Télécharger">
                            <i class="fas fa-download"></i>
                        </button>
                        ${cert.status === 'valid' ? `
                            <button class="btn-icon text-amber-600 revoke-cert" data-id="${cert.id}" title="Révoquer">
                                <i class="fas fa-ban"></i>
                            </button>
                        ` : ''}
                    </div>
                </td>
            </tr>
        `).join('');

        this.bindCertificateActions();
    }

    // 🆕 Génération d'un nouveau certificat
    async generateCertificate(certificateData) {
        try {
            this.showProgressModal('Génération du certificat en cours...');
            
            const response = await this.apiFetch(this.endpoints.generateCertificate, {
                method: 'POST',
                body: JSON.stringify(certificateData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Erreur lors de la génération');
            }

            const data = await response.json();
            
            this.hideProgressModal();
            this.showSuccess('Certificat généré avec succès !');
            this.loadCertificates(); // Recharger la liste
            return data.certificate;
        } catch (error) {
            this.hideProgressModal();
            this.showError('Erreur lors de la génération: ' + error.message);
            throw error;
        }
    }

    // 🚫 Révocation d'un certificat
    async revokeCertificate(certificateId, reason = 'unspecified') {
        try {
            if (!confirm('Êtes-vous sûr de vouloir révoquer ce certificat ? Cette action est irréversible.')) {
                return;
            }

            this.showProgressModal('Révocation du certificat...');
            
            const endpoint = this.endpoints.revokeCertificate.replace('{id}', certificateId);
            const response = await this.apiFetch(endpoint, {
                method: 'POST',
                body: JSON.stringify({ reason })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Erreur lors de la révocation');
            }

            const data = await response.json();
            
            this.hideProgressModal();
            this.showSuccess('Certificat révoqué avec succès');
            this.loadCertificates(); // Recharger la liste
            return data.certificate;
        } catch (error) {
            this.hideProgressModal();
            this.showError('Erreur lors de la révocation: ' + error.message);
        }
    }

    // 📥 Téléchargement d'un certificat
    async downloadCertificate(certificateId) {
        try {
            this.showProgressModal('Préparation du téléchargement...');
            
            const response = await this.apiFetch(`${this.endpoints.certificates}/${certificateId}/download`);
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            
            const cert = appState.certificates.find(c => c.id === certificateId);
            const fileName = cert ? `certificate-${cert.serial}.pem` : `certificate-${certificateId}.pem`;
            
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            this.hideProgressModal();
            this.showSuccess('Certificat téléchargé avec succès');
        } catch (error) {
            this.hideProgressModal();
            this.showError('Erreur lors du téléchargement: ' + error.message);
        }
    }

    // 🔍 Filtrage des certificats
    filterCertificates(certificates) {
        const { certificateStatus, certificateType, searchTerm } = appState.filters;
        
        return certificates.filter(cert => {
            if (certificateStatus !== 'all' && cert.status !== certificateStatus) {
                return false;
            }
            if (certificateType !== 'all' && cert.type !== certificateType) {
                return false;
            }
            if (searchTerm) {
                const term = searchTerm.toLowerCase();
                return (
                    (cert.subject || '').toLowerCase().includes(term) ||
                    (cert.issuer || '').toLowerCase().includes(term) ||
                    (cert.serial || '').toLowerCase().includes(term) ||
                    (cert.email || '').toLowerCase().includes(term)
                );
            }
            return true;
        });
    }

    // 🎯 Gestion des événements
    bindEvents() {
        document.getElementById('certFilterStatus')?.addEventListener('change', () => this.applyFilters());
        document.getElementById('certFilterType')?.addEventListener('change', () => this.applyFilters());
        document.getElementById('certSearch')?.addEventListener('input', this.debounce(() => this.applyFilters(), 300));
        document.getElementById('btnGenerateCert')?.addEventListener('click', () => this.openCertificateGenerationModal());
    }

    bindCertificateActions() {
        document.getElementById('certificatesTableBody').addEventListener('click', (e) => {
            const viewBtn = e.target.closest('.view-cert');
            const downloadBtn = e.target.closest('.download-cert');
            const revokeBtn = e.target.closest('.revoke-cert');
            
            if (viewBtn) this.viewCertificateDetails(viewBtn.dataset.id);
            if (downloadBtn) this.downloadCertificate(downloadBtn.dataset.id);
            if (revokeBtn) this.revokeCertificate(revokeBtn.dataset.id);
        });
    }

    applyFilters() {
        appState.filters.certificateStatus = document.getElementById('certFilterStatus').value;
        appState.filters.certificateType = document.getElementById('certFilterType').value;
        appState.filters.searchTerm = document.getElementById('certSearch').value;
        this.renderCertificatesTable(appState.certificates);
    }
    
    // ⚡ Utilitaires
    getCertificateTypeBadge(type) {
        const config = window.CERTIFICATE_TYPES[type] || { label: type, color: 'gray' };
        return `<span class="badge bg-${config.color}-100 text-${config.color}-800">${config.label}</span>`;
    }

    getStatusBadge(status) {
        const config = window.CERTIFICATE_STATUS[status] || { label: status, color: 'gray', icon: 'fa-question' };
        return `
            <span class="badge bg-${config.color}-100 text-${config.color}-800">
                <i class="fas ${config.icon}"></i>
                ${config.label}
            </span>
        `;
    }

    getSubjectCN(subject) {
        if (!subject || typeof subject !== 'string') return 'N/A';
        const match = subject.match(/CN=([^,]+)/i);
        return match ? match[1].trim() : subject.split(',')[0]?.trim() || 'N/A';
    }

    formatDate(dateString) {
        if (!dateString || dateString === 'N/A') return '--';
        try {
            return new Date(dateString).toLocaleDateString('fr-FR', {
                year: 'numeric', month: 'short', day: 'numeric'
            });
        } catch (error) { return '--'; }
    }

    getDaysUntilExpiry(expiryDate) {
        if (!expiryDate) return 0;
        try {
            const diff = new Date(expiryDate) - new Date();
            return Math.ceil(diff / (1000 * 60 * 60 * 24));
        } catch (error) { return 0; }
    }

    escapeHTML(str) {
        const p = document.createElement('p');
        p.textContent = str;
        return p.innerHTML;
    }

    debounce(func, wait) {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    showLoadingState() {
        const tbody = document.getElementById('certificatesTableBody');
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center p-6 text-slate-400 loading-state"><i class="fas fa-spinner fa-spin mr-2"></i> Chargement...</td></tr>`;
    }

    renderEmptyState() {
        const tbody = document.getElementById('certificatesTableBody');
        if (tbody) tbody.innerHTML = this.getEmptyStateHTML();
    }

    getEmptyStateHTML() {
        return `<tr><td colspan="6" class="text-center p-8 text-slate-400"><i class="fas fa-certificate text-4xl mb-3 opacity-50"></i><p class="font-medium">Aucun certificat trouvé</p></td></tr>`;
    }

    showError(message) {
        this.showToast(message, 'error');
    }

    showProgressModal(message) {
        document.getElementById('progressTitle').textContent = message;
        document.getElementById('progressLog').innerHTML = `<div class="log-info">${new Date().toLocaleTimeString()}: ${message}</div>`;
        document.getElementById('progressBar').style.width = '50%';
        openModal('progressModal');
    }

    hideProgressModal() {
        closeModal('progressModal');
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showToast(message, type = 'info') {
        showToast(message, type);
    }

    updateCertificateSelects() {
        const selects = [document.getElementById('certToRevoke'), document.getElementById('signingCertSelect'), document.getElementById('tsaCert')];
        selects.forEach(select => {
            if (select) {
                const validCerts = appState.certificates.filter(c => c.status === 'valid');
                select.innerHTML = '<option value="">-- Sélectionner --</option>';
                validCerts.forEach(cert => {
                    select.innerHTML += `<option value="${cert.id}">${this.getSubjectCN(cert.subject)} (S/N: ${cert.serial.slice(0,8)}...)</option>`;
                });
            }
        });
    }

    openCertificateGenerationModal() {
        openModal('generateCertModal');
    }

    viewCertificateDetails(certId) {
        const cert = appState.certificates.find(c => c.id === certId);
        if (cert) {
            alert(`Affichage des détails pour: ${this.getSubjectCN(cert.subject)}`);
        }
    }

    async apiFetch(endpoint, options = {}) {
        return apiFetch(endpoint, options);
    }
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
    }
}
// ---------- Fonctions utilitaires (conservées de l'original) ----------

/** Affiche une notification toast */
function showToast(message, type = 'info', duration = 5000) {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.style.opacity = '0';
    toast.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${getToastIcon(type)} mr-2"></i>
            <span>${message}</span>
        </div>
        <button class="toast-close text-white opacity-70 hover:opacity-100 ml-4">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    toast.querySelector('.toast-close').onclick = () => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    };
    
    container.appendChild(toast);
    
    setTimeout(() => toast.style.opacity = '1', 10);
    
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
    
    return toast;
}

/** Retourne l'icône appropriée pour le type de toast */
function getToastIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-triangle',
        warning: 'fa-exclamation-circle',
        info: 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

/** Wrapper robuste pour les appels API */
async function apiFetch(endpoint, options = {}) {
    const url = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const timeout = options.timeout || 30000;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        clearTimeout(timeoutId);
        
        if (options.returnRawResponse) return response;
        
        if (!response.ok) {
            let errorMessage = `Erreur HTTP ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {
                // Ignorer si la réponse n'est pas du JSON
            }
            throw new Error(errorMessage);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        } else {
            return await response.text();
        }
        
    } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
            throw new Error('La requête a pris trop de temps. Veuillez réessayer.');
        } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
            throw new Error(ERROR_MESSAGES.NETWORK_ERROR || 'Erreur de connexion réseau. Vérifiez votre connexion internet.');
        } else {
            throw error;
        }
    }
}

/** Simule un délai (pour le développement) */
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------- Gestion des onglets ----------

function activateTab(tabId) {
    if (appState.isLoading) return;
    
    // Masquer tous les contenus d'onglets
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Afficher l'onglet sélectionné
    const activeTab = document.getElementById(tabId);
    if (activeTab) {
        activeTab.classList.add('active');
        appState.currentTab = tabId;
    }
    
    // Mettre à jour la navigation
    document.querySelectorAll('nav a').forEach(link => {
        link.classList.remove('active-link');
        if (link.dataset.tab === tabId) {
            link.classList.add('active-link');
        }
    });
    
    // Mettre à jour le titre de la page
    updatePageTitle(tabId);
    
    // Charger les données spécifiques à l'onglet
    loadTabData(tabId);
}

function updatePageTitle(tabId) {
    const titles = {
        dashboard: 'Tableau de Bord PKI',
        certificates: 'Gestion des Certificats',
        signing: 'Signature et Horodatage',
        users: 'Gestion des Utilisateurs',
        tsa: 'Autorité d\'Horodatage',
        crl: 'Listes de Révocation',
        audit: 'Journal d\'Audit',
        settings: 'Paramètres PKI'
    };
    
    const titleElement = document.getElementById('pageTitle');
    if (titleElement) {
        titleElement.textContent = titles[tabId] || 'PKI Manager';
    }
}

function loadTabData(tabId) {
    switch (tabId) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'certificates':
            window.certificateManager.loadCertificates();
            break;
        case 'signing':
            loadSigningData();
            break;
        case 'users':
            loadUsers();
            break;
        case 'crl':
            loadCRLData();
            break;
        case 'audit':
            loadAuditLog();
            break;
        case 'settings':
            loadSettings();
            break;
        default:
            break;
    }
}

// ---------- Gestion du statut HSM ----------

async function checkHSMStatus() {
    const indicators = {
        indicator: document.getElementById('hsmStatusIndicator'),
        text: document.getElementById('hsmStatusText'),
        detail: document.getElementById('hsmStatusDetail'),
        status: document.getElementById('hsmStatus'),
        details: document.getElementById('hsmDetails')
    };
    
    if (!Object.values(indicators).every(el => el)) {
        console.warn('Éléments HSM non trouvés');
        return;
    }
    
    indicators.status.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    indicators.details.textContent = 'Vérification...';
    
    try {
        // Essayer différents endpoints HSM
        const endpoints = [
            '/api/pkcs11/status',
            '/api/hid/status',
            '/api/hsm/status'
        ];
        
        let data = null;
        for (const endpoint of endpoints) {
            try {
                const response = await fetch(endpoint, { signal: AbortSignal.timeout(5000) });
                if (response.ok) {
                    data = await response.json();
                    break;
                }
            } catch (e) {
                continue;
            }
        }
        
        if (!data) {
            data = await getMockHSMStatus();
        }
        
        const connected = data.connected || data.isConnected || data.status === 'connected';
        const cardPresent = data.cardPresent || data.isCardPresent || data.cardStatus === 'present';
        
        appState.hsmStatus = {
            connected,
            cardPresent,
            lastCheck: new Date().toISOString(),
            deviceInfo: data.device || data.info
        };
        
        if (connected && cardPresent) {
            updateHSMIndicator(indicators, 'green', 'Connecté', 'Prêt pour les opérations', 'Actif', 'Carte détectée');
        } else if (connected) {
            updateHSMIndicator(indicators, 'yellow', 'En attente', 'Insérez une carte', 'En attente', 'Carte requise');
        } else {
            updateHSMIndicator(indicators, 'red', 'Déconnecté', 'Aucun lecteur détecté', 'Inactif', 'Vérifiez la connexion');
        }
        
    } catch (error) {
        console.error('Erreur statut HSM:', error);
        updateHSMIndicator(indicators, 'red', 'Erreur', 'Connexion impossible', 'Erreur', 'API indisponible');
    }
}

async function getMockHSMStatus() {
    await delay(500);
    
    const statuses = ['connected', 'disconnected'];
    const cardStatuses = ['present', 'absent'];
    
    const randomStatus = statuses[Math.floor(Math.random() * statuses.length)];
    const randomCardStatus = cardStatuses[Math.floor(Math.random() * cardStatuses.length)];
    
    return {
        connected: randomStatus === 'connected',
        cardPresent: randomCardStatus === 'present',
        device: {
            name: 'SmartCard-HSM (Simulation)',
            manufacturer: 'CardContact',
            version: '3.5'
        },
        timestamp: new Date().toISOString()
    };
}

function updateHSMIndicator(indicators, color, text, detail, status, details) {
    const colorClass = `bg-${color}-500`;
    indicators.indicator.className = `w-3 h-3 rounded-full ${colorClass}`;
    indicators.text.textContent = text;
    indicators.detail.textContent = detail;
    indicators.status.textContent = status;
    indicators.details.textContent = details;
}

// ---------- Dashboard ----------

async function loadDashboardData() {
    try {
        let data;
        try {
            data = await apiFetch(API_ENDPOINTS.dashboard || '/api/pki/dashboard/stats');
        } catch (error) {
            console.warn('API dashboard non disponible, utilisation de données mockées');
            data = await getMockDashboardData();
        }
        
        updateDashboardStats(data);
        updateExpiringCertificates();
        
    } catch (error) {
        console.error('Erreur chargement dashboard:', error);
        updateDashboardStats(getDefaultStats());
    }
}

async function getMockDashboardData() {
    await delay(800);
    
    return {
        activeCertificates: appState.certificates.filter(c => c.status === 'valid').length,
        expiringSoon: appState.certificates.filter(c => {
            const days = getDaysUntilExpiry(c.expires);
            return c.status === 'valid' && days <= 30 && days > 0;
        }).length,
        signaturesThisMonth: Math.floor(Math.random() * 50) + 10,
        signaturesToday: Math.floor(Math.random() * 5) + 1,
        timestampsCount: Math.floor(Math.random() * 100) + 20,
        lastUpdate: new Date().toISOString()
    };
}

function getDefaultStats() {
    return {
        activeCertificates: 0,
        expiringSoon: 0,
        signaturesThisMonth: 0,
        signaturesToday: 0,
        timestampsCount: 0
    };
}

function updateDashboardStats(stats) {
    const elements = {
        activeCerts: document.getElementById('activeCertsCount'),
        certExpiry: document.getElementById('certExpiryStats'),
        signaturesCount: document.getElementById('signaturesCount'),
        signaturesTrend: document.getElementById('signaturesTrend'),
        timestampsCount: document.getElementById('timestampsCount'),
        timestampsTrend: document.getElementById('timestampsTrend')
    };
    
    if (elements.activeCerts) elements.activeCerts.textContent = stats.activeCertificates || 0;
    if (elements.certExpiry) elements.certExpiry.textContent = `${stats.expiringSoon || 0} expirent bientôt`;
    if (elements.signaturesCount) elements.signaturesCount.textContent = stats.signaturesThisMonth || 0;
    if (elements.signaturesTrend) elements.signaturesTrend.textContent = `${stats.signaturesToday || 0} aujourd'hui`;
    if (elements.timestampsCount) elements.timestampsCount.textContent = stats.timestampsCount || 0;
    if (elements.timestampsTrend) elements.timestampsTrend.textContent = `${Math.floor((stats.timestampsCount || 0) / 30)} cette semaine`;
}

function updateExpiringCertificates() {
    const tbody = document.getElementById('expiringCertsBody');
    if (!tbody) return;
    
    const expiringCerts = appState.certificates
        .filter(cert => {
            const days = getDaysUntilExpiry(cert.expires);
            return cert.status === 'valid' && days <= 90 && days > 0;
        })
        .sort((a, b) => new Date(a.expires) - new Date(b.expires))
        .slice(0, 5);
    
    if (expiringCerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center py-6 text-slate-500">
                    <i class="fas fa-check-circle text-green-500 mr-2"></i>
                    Aucun certificat n'expire bientôt
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = expiringCerts.map(cert => {
        const days = getDaysUntilExpiry(cert.expires);
        return `
            <tr class="hover:bg-slate-50">
                <td class="p-3">${getSubjectCN(cert.subject)}</td>
                <td class="p-3">${formatDate(cert.expires, 'short')}</td>
                <td class="p-3 text-right font-medium ${days <= 7 ? 'text-red-600' : days <= 30 ? 'text-amber-600' : 'text-green-600'}">
                    ${days} jours
                </td>
            </tr>
        `;
    }).join('');
}

// ---------- Gestion des fichiers ----------

function setupFileDropZone() {
    const dropZone = document.getElementById('documentDropZone');
    const fileInput = document.getElementById('documentInput');
    const browseLink = document.getElementById('browseLink');
    
    if (!dropZone || !fileInput) return;
    
    dropZone.addEventListener('click', (e) => {
        if (!e.target.closest('#browseLink')) {
            fileInput.click();
        }
    });
    
    if (browseLink) {
        browseLink.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }
    
    fileInput.addEventListener('change', handleFileSelect);
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-blue-400', 'bg-blue-50');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-blue-400', 'bg-blue-50');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-blue-400', 'bg-blue-50');
        
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });
}

function handleFileSelect(e) {
    if (e.target.files.length) {
        handleFile(e.target.files[0]);
    }
}

function handleFile(file) {
    if (!file) return;
    
    const maxSize = window.APP_CONFIG?.ui?.maxFileSize || 10 * 1024 * 1024;
    if (file.size > maxSize) {
        showToast(ERROR_MESSAGES.FILE_TOO_LARGE || 'Fichier trop volumineux', 'error');
        return;
    }
    
    const allowedTypes = ['.pdf', '.doc', '.docx', '.xml', '.txt', '.odt'];
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        showToast(ERROR_MESSAGES.UNSUPPORTED_FILE_TYPE || 'Type de fichier non supporté', 'error');
        return;
    }
    
    appState.selectedFile = file;
    
    const selectedDocument = document.getElementById('selectedDocument');
    const documentName = document.getElementById('documentName');
    const documentSize = document.getElementById('documentSize');
    const signButton = document.getElementById('btnSignDocument');
    
    if (documentName) documentName.textContent = file.name;
    if (documentSize) documentSize.textContent = formatFileSize(file.size);
    if (selectedDocument) selectedDocument.classList.remove('hidden');
    if (signButton) signButton.disabled = false;
    
    showToast(`Fichier "${file.name}" sélectionné avec succès`, 'success');
}

// ---------- Fonctions utilitaires supplémentaires ----------

function getSubjectCN(subject) {
    if (!subject || typeof subject !== 'string') return 'N/A';
    const match = subject.match(/CN=([^,]+)/i);
    return match ? match[1].trim() : subject.split(',')[0]?.trim() || 'N/A';
}

function formatDate(dateString, format = 'full') {
    if (!dateString || dateString === 'N/A') return '--';
    
    try {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return '--';
        
        if (format === 'short') {
            return date.toLocaleDateString('fr-FR', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric'
            });
        }
        
        return date.toLocaleDateString('fr-FR', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (error) {
        console.warn('Erreur de formatage de date:', error);
        return '--';
    }
}

function getDaysUntilExpiry(expiryDate) {
    if (!expiryDate) return 0;
    
    try {
        const expiry = new Date(expiryDate);
        const now = new Date();
        const diffTime = expiry - now;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays > 0 ? diffDays : 0;
    } catch (error) {
        return 0;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ---------- Initialisation des écouteurs d'événements ----------

function setupEventListeners() {
    // Navigation par onglets
    document.addEventListener('click', (e) => {
        if (e.target.closest('nav a')) {
            e.preventDefault();
            const tabId = e.target.closest('a').dataset.tab;
            if (tabId) activateTab(tabId);
        }
    });
    
    // Menu mobile
    const mobileToggle = document.getElementById('mobileMenuToggle');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    
    if (mobileToggle && sidebar) {
        mobileToggle.addEventListener('click', () => sidebar.classList.add('open'));
    }
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => sidebar.classList.remove('open'));
    }
    
    // Fermeture des modales
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-overlay')) {
            const modalId = e.target.id;
            if(modalId) closeModal(modalId);
        }
    });
    
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.getAttribute('data-modal');
            closeModal(modalId);
        });
    });
    
    // Rafraîchissement HSM
    const refreshHSM = document.getElementById('refreshHSM');
    if (refreshHSM) {
        refreshHSM.addEventListener('click', checkHSMStatus);
    }
    
    // Rafraîchissement dashboard
    const refreshDashboard = document.getElementById('refreshDashboard');
    if (refreshDashboard) {
        refreshDashboard.addEventListener('click', loadDashboardData);
    }
    
    // Configuration de la zone de dépôt de fichiers
    setupFileDropZone();

    // IMPLEMENTATION: Logique du formulaire de génération de certificat
    const generateCertForm = document.getElementById('generateCertForm');
    if (generateCertForm) {
        generateCertForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(generateCertForm);
            
            const subjectParts = [];
            if (formData.get('commonName')) subjectParts.push(`CN=${formData.get('commonName')}`);
            if (formData.get('organization')) subjectParts.push(`O=${formData.get('organization')}`);
            if (formData.get('orgUnit')) subjectParts.push(`OU=${formData.get('orgUnit')}`);
            if (formData.get('locality')) subjectParts.push(`L=${formData.get('locality')}`);
            if (formData.get('state')) subjectParts.push(`ST=${formData.get('state')}`);
            if (formData.get('country')) subjectParts.push(`C=${formData.get('country')}`);
            
            const certificateData = {
                subject: subjectParts.join(', '),
                type: formData.get('certType'),
                validityDays: parseInt(formData.get('validityDays'), 10),
                keySize: parseInt(formData.get('keySize'), 10),
                email: formData.get('email')
            };

            try {
                await window.certificateManager.generateCertificate(certificateData);
                closeModal('generateCertModal');
                generateCertForm.reset();
            } catch (error) {
                console.error("Échec de la génération du certificat:", error);
                // L'erreur est déjà affichée par le gestionnaire
            }
        });
    }
}

// ---------- Fonctions de chargement des onglets ----------

async function loadSigningData() {
    showToast('Chargement des données de signature...', 'info');
}

async function loadUsers() {
    showToast('Chargement des utilisateurs...', 'info');
}

async function loadCRLData() {
    showToast('Chargement des données CRL...', 'info');
}

async function loadAuditLog() {
    showToast('Chargement du journal d\'audit...', 'info');
}

async function loadSettings() {
    showToast('Chargement des paramètres...', 'info');
}

// ---------- Initialisation de l'application ----------

async function initializeApplication() {
    console.log('🚀 Initialisation de l\'application PKI...');
    
    try {
        // Initialiser le gestionnaire de certificats
        window.certificateManager = new PKICertificateManager();
        
        // Configurer les écouteurs d'événements
        setupEventListeners();
        window.certificateManager.bindEvents();
        
        // Vérifier le statut HSM
        await checkHSMStatus();
        
        // Charger les données initiales
        await window.certificateManager.loadCertificates(); // Charger les certificats en premier
        await loadDashboardData();
        
        // Activer l'onglet par défaut
        activateTab('dashboard');
        
        // Configurer le rafraîchissement automatique
        if (window.APP_CONFIG?.ui?.autoRefresh) {
            const interval = window.APP_CONFIG.ui.refreshInterval || 30000;
            setInterval(() => {
                checkHSMStatus();
                if (appState.currentTab === 'dashboard') loadDashboardData();
                if (appState.currentTab === 'certificates') window.certificateManager.loadCertificates();
            }, interval);
        }
        
        showToast('✅ Application PKI initialisée avec succès', 'success');
        
    } catch (error) {
        console.error('❌ Erreur lors de l\'initialisation:', error);
        showToast('❌ Erreur lors du démarrage de l\'application', 'error');
    }
}

// Démarrer l'application quand le DOM est prêt
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApplication);
} else {
    initializeApplication();
}

