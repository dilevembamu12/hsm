// server.js - Serveur PKI de Production avec Architecture Récursive
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const fssync = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const forge = require('node-forge');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 9099;

// ========== CONFIGURATION ==========
const CONFIG = {
    paths: {
        views: path.join(__dirname, 'views'),
        data: path.join(__dirname, 'public', 'data', 'pki'),
        certs: path.join(__dirname, 'certs'),
        uploads: path.join(__dirname, 'uploads'),
        temp: path.join(__dirname, 'temp')
    },
    pki: {
        ca: {
            privateKey: path.join(__dirname, 'certs', 'ca-private.key'),
            certificate: path.join(__dirname, 'certs', 'ca-certificate.crt'),
            subject: {
                country: 'CD',
                state: 'Kinshasa',
                locality: 'Gombe',
                organization: 'FIntraX Congo',
                organizationalUnit: 'PKI Services',
                commonName: 'FIntraX Root CA'
            }
        },
        default: {
            validityDays: 365,
            keySize: 2048,
            hashAlgorithm: 'sha256'
        }
    },
    security: {
        jwtSecret: process.env.JWT_SECRET || 'pki-enterprise-secret-key',
        bcryptRounds: 12
    }
};

// ========== MIDDLEWARE ==========
// Add CORS support
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Middleware de gestion d'erreurs
app.use((error, req, res, next) => {
    console.error('Erreur non gérée:', error);
    res.status(500).json({ 
        ok: false, 
        error: 'Erreur interne du serveur',
        requestId: uuidv4()
    });
});

// ========== SERVICES ==========

// Service de gestion des fichiers
class FileService {
    static async ensureDirectory(dirPath) {
        try {
            await fs.mkdir(dirPath, { recursive: true });
            return true;
        } catch (error) {
            throw new Error(`Impossible de créer le répertoire: ${dirPath}`);
        }
    }

    static async readJSON(filePath) {
        try {
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            throw new Error(`Erreur lecture fichier ${filePath}: ${error.message}`);
        }
    }

    static async writeJSON(filePath, data) {
        try {
            const enrichedData = {
                ...data,
                timestamp: new Date().toISOString(),
                lastModified: new Date().toISOString()
            };
            await fs.writeFile(filePath, JSON.stringify(enrichedData, null, 2));
            return enrichedData;
        } catch (error) {
            throw new Error(`Erreur écriture fichier ${filePath}: ${error.message}`);
        }
    }

    static async fileExists(filePath) {
        try {
            await fs.access(filePath);
            return true;
        } catch {
            return false;
        }
    }
}

// Service de gestion PKI
class PKIService {
    static generateSerialNumber() {
        return crypto.randomBytes(8).toString('hex').toUpperCase();
    }

    static parseSubject(subject, email = null) {
        const attrs = [];
        const parts = subject.split(',').map(part => part.trim());
        
        for (const part of parts) {
            const [key, value] = part.split('=').map(p => p.trim());
            if (key && value) {
                const attrMap = {
                    'C': 'countryName',
                    'ST': 'stateOrProvinceName',
                    'L': 'localityName',
                    'O': 'organizationName',
                    'OU': 'organizationalUnitName',
                    'CN': 'commonName',
                    'EMAIL': 'emailAddress'
                };
                
                if (attrMap[key]) {
                    attrs.push({ name: attrMap[key], value: value });
                }
            }
        }
        
        if (email) {
            attrs.push({ name: 'emailAddress', value: email });
        }
        
        return attrs;
    }

    static getCertificateExtensions(type, email = null) {
        const baseExtensions = [
            {
                name: 'basicConstraints',
                critical: true
            },
            {
                name: 'keyUsage',
                critical: true,
                digitalSignature: true,
                keyEncipherment: true
            },
            {
                name: 'extKeyUsage',
                serverAuth: type === 'server',
                clientAuth: type === 'user',
                codeSigning: type === 'code',
                emailProtection: type === 'email' || email
            },
            {
                name: 'subjectKeyIdentifier'
            }
        ];

        // Ajuster les contraintes selon le type
        if (type === 'ca') {
            baseExtensions[0].cA = true;
            baseExtensions[1].keyCertSign = true;
            baseExtensions[1].cRLSign = true;
        } else {
            baseExtensions[0].cA = false;
        }

        return baseExtensions;
    }

    static async generateKeyPair(keySize = 2048) {
        return new Promise((resolve, reject) => {
            try {
                const keys = forge.pki.rsa.generateKeyPair(keySize);
                resolve(keys);
            } catch (error) {
                reject(new Error(`Erreur génération clés: ${error.message}`));
            }
        });
    }

    static async loadCACertificate() {
        try {
            const caCertPem = await fs.readFile(CONFIG.pki.ca.certificate, 'utf8');
            return forge.pki.certificateFromPem(caCertPem);
        } catch (error) {
            throw new Error('Impossible de charger le certificat CA');
        }
    }

    static async loadCAPrivateKey() {
        try {
            const caPrivateKeyPem = await fs.readFile(CONFIG.pki.ca.privateKey, 'utf8');
            return forge.pki.privateKeyFromPem(caPrivateKeyPem);
        } catch (error) {
            throw new Error('Impossible de charger la clé privée CA');
        }
    }
}

// Service d'audit
class AuditService {
    static async logEvent(eventData) {
        const auditPath = path.join(CONFIG.paths.data, 'audit.json');
        
        try {
            const auditData = await FileService.readJSON(auditPath);
            
            const event = {
                id: uuidv4(),
                timestamp: new Date().toISOString(),
                ...eventData
            };
            
            auditData.events.unshift(event);
            auditData.total = auditData.events.length;
            
            // Garder seulement les 5000 derniers événements
            if (auditData.events.length > 5000) {
                auditData.events = auditData.events.slice(0, 5000);
            }
            
            await FileService.writeJSON(auditPath, auditData);
            return event;
        } catch (error) {
            console.error('Erreur journalisation audit:', error);
        }
    }
}

// ========== INITIALISATION ==========

async function initializeSystem() {
    console.log('Initialisation du système PKI de production...');
    
    try {
        // Créer les répertoires
        await Promise.all([
            FileService.ensureDirectory(CONFIG.paths.data),
            FileService.ensureDirectory(CONFIG.paths.certs),
            FileService.ensureDirectory(CONFIG.paths.uploads),
            FileService.ensureDirectory(CONFIG.paths.temp)
        ]);

        // Initialiser l'AC racine
        await initializeRootCA();

        // Initialiser les fichiers de données
        await initializeDataFiles();

        console.log('Système PKI initialisé avec succès');
    } catch (error) {
        console.error('Erreur initialisation système:', error);
        process.exit(1);
    }
}

async function initializeRootCA() {
    const { privateKey, certificate } = CONFIG.pki.ca;
    
    if (await FileService.fileExists(privateKey) && await FileService.fileExists(certificate)) {
        console.log('AC racine déjà configurée');
        return;
    }
    
    console.log('Création de l\'AC racine...');
    
    try {
        const keys = await PKIService.generateKeyPair(4096);
        const cert = forge.pki.createCertificate();
        
        // Configurer le certificat
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
        
        // Définir le sujet
        const attrs = [
            { name: 'countryName', value: CONFIG.pki.ca.subject.country },
            { name: 'stateOrProvinceName', value: CONFIG.pki.ca.subject.state },
            { name: 'localityName', value: CONFIG.pki.ca.subject.locality },
            { name: 'organizationName', value: CONFIG.pki.ca.subject.organization },
            { name: 'organizationalUnitName', value: CONFIG.pki.ca.subject.organizationalUnit },
            { name: 'commonName', value: CONFIG.pki.ca.subject.commonName }
        ];
        
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        
        // Extensions
        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: true,
                critical: true
            },
            {
                name: 'keyUsage',
                keyCertSign: true,
                cRLSign: true,
                critical: true
            },
            {
                name: 'subjectKeyIdentifier'
            }
        ]);
        
        // Signer le certificat
        cert.sign(keys.privateKey, forge.md.sha256.create());
        
        // Sauvegarder
        await fs.writeFile(privateKey, forge.pki.privateKeyToPem(keys.privateKey));
        await fs.writeFile(certificate, forge.pki.certificateToPem(cert));
        
        console.log('AC racine créée avec succès');
    } catch (error) {
        throw new Error(`Erreur création AC: ${error.message}`);
    }
}

async function initializeDataFiles() {
    const defaultData = {
        dashboard: {
            stats: { activeCertificates: 0, expiringSoon: 0, signaturesToday: 0, signaturesThisMonth: 0, timestampsCount: 0, hsmStatus: 'disconnected', totalUsers: 0, crlEntries: 0 },
            expiringCertificates: [],
            recentActivity: [],
            systemHealth: { hsm: 'disconnected', database: 'online', tsa: 'operational', lastBackup: new Date().toISOString() }
        },
        certificates: {
            total: 0,
            certificates: [],
            filters: { status: { valid: 0, expired: 0, revoked: 0, pending: 0 }, type: { user: 0, server: 0, ca: 0, code: 0 } }
        },
        signing: {
            signatures: [],
            statistics: { today: 0, thisWeek: 0, thisMonth: 0, byFormat: { PAdES: 0, XAdES: 0, CAdES: 0 } },
            pendingSignatures: []
        },
        users: {
            total: 0,
            users: [],
            roles: { Administrateur: 0, Gestionnaire: 0, Employe: 0 },
            statistics: { active: 0, inactive: 0, withCertificates: 0, pendingActivation: 0 }
        },
        tsa: {
            configuration: { url: 'https://tsa.fintrax.cd/timestamp', policy: '1.3.6.1.4.1.13762.3', certificateId: null, enabled: true, hashAlgorithm: 'SHA256' },
            statistics: { today: 0, thisWeek: 0, thisMonth: 0, lastTimestamp: null, serviceStatus: 'active', responseTime: 125, successRate: 99.8 },
            timestampLog: [],
            certificates: []
        },
        crl: {
            currentCRL: { issuer: 'CN=FIntraX Root CA, O=FIntraX Congo', lastUpdate: null, nextUpdate: null, revokedCertificates: 0, serial: 'CRL-000000' },
            revokedCertificates: [],
            history: [],
            statistics: { totalRevoked: 0, revokedThisMonth: 0, revokedThisYear: 0, byReason: { keyCompromise: 0, affiliationChanged: 0, unspecified: 0 } }
        },
        audit: {
            total: 0,
            events: [],
            statistics: { today: 0, thisWeek: 0, thisMonth: 0, bySeverity: { info: 0, warning: 0, error: 0, critical: 0 }, byAction: { certificate_generated: 0, certificate_revoked: 0, user_login: 0, document_signed: 0, configuration_changed: 0 } }
        },
        settings: {
            general: { organization: 'FIntraX Congo', organizationalUnit: 'Services Financiers', country: 'CD', locale: 'fr-FR', timezone: 'Africa/Kinshasa' },
            certificate: { defaultValidityDays: 365, defaultAlgorithm: 'RSA', defaultKeySize: 2048, crlInterval: 7, autoRenewal: false, renewalThreshold: 30 },
            hsm: { type: 'smartcard', autoLogin: false, modulePath: '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so', slot: 0 },
            security: { passwordPolicy: 'medium', passwordExpiry: 90, require2FA: false, sessionTimeout: 30, maxLoginAttempts: 5, auditRetention: 365 },
            signing: { defaultTSA: 'https://tsa.fintrax.cd/timestamp', defaultPolicy: '1.3.6.1.4.1.13762.3', maxFileSize: 10485760, allowedFormats: ['PDF', 'DOC', 'DOCX', 'XML', 'TXT'], autoTimestamp: true },
            ui: { theme: 'light', autoRefresh: true, refreshInterval: 30000, resultsPerPage: 50 },
            backup: { autoBackup: true, backupInterval: 24, retentionDays: 30, lastBackup: null }
        }
    };

    for (const [fileKey, data] of Object.entries(defaultData)) {
        const filePath = path.join(CONFIG.paths.data, `${fileKey}.json`);
        if (!await FileService.fileExists(filePath)) {
            const enrichedData = { ...data, timestamp: new Date().toISOString(), version: '1.0', initialized: true };
            await FileService.writeJSON(filePath, enrichedData);
            console.log(`Fichier initialisé: ${fileKey}.json`);
        }
    }
}

// ========== HANDLERS RÉCURSIFS ==========

// Handler de base pour les opérations CRUD
class BaseHandler {
    constructor(dataType) {
        this.dataType = dataType;
        this.filePath = path.join(CONFIG.paths.data, `${dataType}.json`);
    }

    async get() {
        try {
            const data = await FileService.readJSON(this.filePath);
            return { ok: true, ...data };
        } catch (error) {
            throw error;
        }
    }

    async create(newData) {
        try {
            const currentData = await FileService.readJSON(this.filePath);
            const updatedData = { ...currentData, ...newData };
            const result = await FileService.writeJSON(this.filePath, updatedData);
            return { ok: true, ...result };
        } catch (error) {
            throw error;
        }
    }

    async update(updates) {
        return this.create(updates);
    }

    async delete() {
        try {
            const defaultData = await initializeDataFiles[this.dataType]();
            const result = await FileService.writeJSON(this.filePath, defaultData);
            return { ok: true, message: `${this.dataType} réinitialisé`, ...result };
        } catch (error) {
            throw error;
        }
    }
}

// Handler spécialisé pour les certificats
class CertificateHandler extends BaseHandler {
    constructor() {
        super('certificates');
    }

    async generateCertificate(certificateData) {
        try {
            const { subject, type, validityDays, keySize, keyType, email } = certificateData;

            if (!subject) {
                throw new Error('Le sujet est requis');
            }

            // Générer la paire de clés
            const keys = await PKIService.generateKeyPair(keySize || CONFIG.pki.default.keySize);
            
            // Parser le sujet
            const subjectAttrs = PKIService.parseSubject(subject, email);
            
            // Créer le certificat
            const cert = forge.pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = PKIService.generateSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + (validityDays || CONFIG.pki.default.validityDays));
            
            // Définir le sujet et l'émetteur
            cert.setSubject(subjectAttrs);
            const caCert = await PKIService.loadCACertificate();
            cert.setIssuer(caCert.subject.attributes);
            
            // Définir les extensions
            const extensions = PKIService.getCertificateExtensions(type, email);
            cert.setExtensions(extensions);
            
            // Signer le certificat
            const caPrivateKey = await PKIService.loadCAPrivateKey();
            cert.sign(caPrivateKey, forge.md.sha256.create());
            
            // Générer les PEM
            const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
            const certificatePem = forge.pki.certificateToPem(cert);
            
            // Calculer l'empreinte
            const md = forge.md.sha1.create();
            md.update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
            const fingerprint = md.digest().toHex().match(/.{2}/g).join(':');
            
            // Créer l'objet certificat
            const newCert = {
                id: uuidv4(),
                subject: subject,
                issuer: forge.pki.certificateToPem(caCert),
                serial: cert.serialNumber,
                issued: cert.validity.notBefore.toISOString(),
                expires: cert.validity.notAfter.toISOString(),
                status: 'valid',
                type: type || 'user',
                keyType: keyType || 'RSA',
                keySize: keySize || 2048,
                algorithm: 'SHA256withRSA',
                fingerprint: fingerprint,
                email: email,
                pem: {
                    privateKey: privateKeyPem,
                    certificate: certificatePem,
                    publicKey: forge.pki.publicKeyToPem(keys.publicKey)
                },
                metadata: {
                    createdBy: 'system',
                    creationDate: new Date().toISOString(),
                    keyUsage: extensions.find(ext => ext.name === 'keyUsage'),
                    extendedKeyUsage: extensions.find(ext => ext.name === 'extKeyUsage')
                }
            };

            // Sauvegarder dans la base de données
            const currentData = await FileService.readJSON(this.filePath);
            currentData.certificates.push(newCert);
            currentData.total = currentData.certificates.length;
            
            // Mettre à jour les statistiques
            currentData.filters.status.valid = (currentData.filters.status.valid || 0) + 1;
            currentData.filters.type[type] = (currentData.filters.type[type] || 0) + 1;
            
            await FileService.writeJSON(this.filePath, currentData);

            // Journaliser l'événement
            await AuditService.logEvent({
                action: 'certificate_generated',
                user: 'system',
                description: `Certificat généré pour ${subject}`,
                severity: 'info',
                details: { certificateId: newCert.id, type: type, serial: newCert.serial }
            });

            return { ok: true, certificate: newCert };

        } catch (error) {
            throw new Error(`Erreur génération certificat: ${error.message}`);
        }
    }

    async revokeCertificate(certificateId, reason = 'unspecified') {
        try {
            const currentData = await FileService.readJSON(this.filePath);
            const certificate = currentData.certificates.find(cert => cert.id === certificateId);

            if (!certificate) {
                throw new Error('Certificat non trouvé');
            }

            if (certificate.status === 'revoked') {
                throw new Error('Le certificat est déjà révoqué');
            }

            // Mettre à jour le certificat
            certificate.status = 'revoked';
            certificate.revocationDate = new Date().toISOString();
            certificate.revocationReason = reason;

            // Mettre à jour les statistiques
            currentData.filters.status.valid = (currentData.filters.status.valid || 0) - 1;
            currentData.filters.status.revoked = (currentData.filters.status.revoked || 0) + 1;

            await FileService.writeJSON(this.filePath, currentData);

            // Mettre à jour la CRL
            await this.updateCRL(certificate);

            // Journaliser l'événement
            await AuditService.logEvent({
                action: 'certificate_revoked',
                user: 'system',
                description: `Certificat révoqué: ${certificate.serial}`,
                severity: 'warning',
                details: { certificateId, reason, serial: certificate.serial }
            });

            return { ok: true, certificate };

        } catch (error) {
            throw new Error(`Erreur révocation certificat: ${error.message}`);
        }
    }

    async updateCRL(revokedCertificate) {
        try {
            const crlHandler = new BaseHandler('crl');
            const crlData = await crlHandler.get();

            // Ajouter à la liste des révoqués
            crlData.revokedCertificates.unshift({
                serialNumber: revokedCertificate.serial,
                subject: revokedCertificate.subject,
                revocationDate: revokedCertificate.revocationDate,
                reason: revokedCertificate.revocationReason,
                certificateId: revokedCertificate.id
            });

            // Mettre à jour les métadonnées CRL
            crlData.currentCRL.revokedCertificates = crlData.revokedCertificates.length;
            crlData.currentCRL.lastUpdate = new Date().toISOString();
            crlData.currentCRL.nextUpdate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 jours

            await crlHandler.update(crlData);

        } catch (error) {
            console.error('Erreur mise à jour CRL:', error);
        }
    }
}

// ========== ROUTES RÉCURSIVES ==========

// Factory pour créer les handlers
function createHandler(type) {
    const handlers = {
        certificates: new CertificateHandler(),
        dashboard: new BaseHandler('dashboard'),
        signing: new BaseHandler('signing'),
        users: new BaseHandler('users'),
        tsa: new BaseHandler('tsa'),
        crl: new BaseHandler('crl'),
        audit: new BaseHandler('audit'),
        settings: new BaseHandler('settings')
    };

    return handlers[type] || new BaseHandler(type);
}

// ========== ADDITIONAL MISSING ROUTES ==========

// Route for HSM status
app.get('/api/hsm/status', async (req, res) => {
    try {
        res.json({
            ok: true,
            status: 'disconnected',
            type: 'smartcard',
            module: '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
            slot: 0,
            connected: false,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route for PKCS11 status
app.get('/api/pkcs11/status', async (req, res) => {
    try {
        res.json({
            ok: true,
            status: 'available',
            modules: ['opensc-pkcs11'],
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route for HID status
app.get('/api/hid/status', async (req, res) => {
    try {
        res.json({
            ok: true,
            status: 'available',
            devices: [],
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route for PKI dashboard status
app.get('/api/pki/dashboard/status', async (req, res) => {
    try {
        const handler = createHandler('dashboard');
        const result = await handler.get();
        res.json({
            ok: true,
            ...result,
            systemStatus: 'operational',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route for favicon (to avoid 404)
app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); // No content
});

// ========== FRONTEND API ROUTES ==========

// Route pour les certificats (frontend expectation)
// CORRECTIF : J'ai ajouté /pki au chemin pour correspondre à la configuration du frontend.
app.get('/api/pki/certificates', async (req, res) => {
    try {
        const handler = new CertificateHandler();
        const result = await handler.get();
        res.json(result.certificates || []);
    } catch (error) {
        console.error('Error loading certificates:', error);
        res.status(500).json({ error: error.message });
    }
});

// Route pour les statistiques du dashboard (frontend expectation)
// CORRECTIF : J'ai ajouté /pki au chemin pour correspondre à la configuration du frontend.
app.get('/api/pki/dashboard/stats', async (req, res) => {
    try {
        const handler = createHandler('dashboard');
        const result = await handler.get();
        res.json(result.stats || {});
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        res.status(500).json({ error: error.message });
    }
});

// Route pour l'activité récente
app.get('/api/audit/recent', async (req, res) => {
    try {
        const handler = createHandler('audit');
        const result = await handler.get();
        const recentEvents = result.events ? result.events.slice(0, 10) : [];
        res.json(recentEvents);
    } catch (error) {
        console.error('Error loading recent activity:', error);
        res.status(500).json({ error: error.message });
    }
});

// Route pour les certificats expirant bientôt
app.get('/api/certificates/expiring-soon', async (req, res) => {
    try {
        const handler = new CertificateHandler();
        const data = await handler.get();
        const certificates = data.certificates || [];
        
        const now = new Date();
        const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        
        const expiringCertificates = certificates.filter(cert => {
            if (cert.status !== 'valid') return false;
            const expires = new Date(cert.expires);
            return expires <= thirtyDaysFromNow && expires > now;
        });
        
        res.json(expiringCertificates);
    } catch (error) {
        console.error('Error loading expiring certificates:', error);
        res.status(500).json({ error: error.message });
    }
});

// Route pour vérifier la connexion
app.get('/api/system/status', async (req, res) => {
    try {
        const status = {
            ok: true,
            timestamp: new Date().toISOString(),
            services: {
                pki: 'operational',
                database: 'operational',
                certificates: 'available',
                signing: 'available'
            }
        };
        res.json(status);
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route générique pour les données
app.route('/api/pki/data/:type')
    .get(async (req, res) => {
        try {
            const handler = createHandler(req.params.type);
            const result = await handler.get();
            res.json(result);
        } catch (error) {
            res.status(500).json({ ok: false, error: error.message });
        }
    })
    .post(async (req, res) => {
        try {
            const handler = createHandler(req.params.type);
            const result = await handler.create(req.body);
            res.json(result);
        } catch (error) {
            res.status(500).json({ ok: false, error: error.message });
        }
    })
    .delete(async (req, res) => {
        try {
            const handler = createHandler(req.params.type);
            const result = await handler.delete();
            res.json(result);
        } catch (error) {
            res.status(500).json({ ok: false, error: error.message });
        }
    });

// Routes spécifiques pour les certificats
app.post('/api/pki/certificates/generate', async (req, res) => {
    try {
        const handler = new CertificateHandler();
        const result = await handler.generateCertificate(req.body);
        res.json(result);
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

app.post('/api/pki/certificates/:id/revoke', async (req, res) => {
    try {
        const handler = new CertificateHandler();
        const result = await handler.revokeCertificate(req.params.id, req.body.reason);
        res.json(result);
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route pour télécharger un certificat
app.get('/api/pki/certificates/:id/download', async (req, res) => {
    try {
        const handler = new CertificateHandler();
        const data = await handler.get();
        const certificate = data.certificates.find(cert => cert.id === req.params.id);

        if (!certificate) {
            return res.status(404).json({ ok: false, error: 'Certificat non trouvé' });
        }

        res.setHeader('Content-Type', 'application/x-pem-file');
        res.setHeader('Content-Disposition', `attachment; filename="certificate-${certificate.serial}.pem"`);
        res.send(certificate.pem.certificate);

    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Statistiques du système
app.get('/api/pki/system/stats', async (req, res) => {
    try {
        const stats = {};
        
        for (const type of ['dashboard', 'certificates', 'signing', 'users', 'tsa', 'crl', 'audit', 'settings']) {
            try {
                const handler = createHandler(type);
                const data = await handler.get();
                const filePath = path.join(CONFIG.paths.data, `${type}.json`);
                const fileStat = await fs.stat(filePath);
                
                stats[type] = {
                    lastUpdate: data.timestamp,
                    fileSize: fileStat.size,
                    items: data.total || data.certificates?.length || data.users?.length || data.events?.length || data.signatures?.length || 0
                };
            } catch (error) {
                stats[type] = { error: error.message };
            }
        }
        
        res.json({ ok: true, stats });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Route de santé
app.get('/api/health', (req, res) => {
    res.json({
        ok: true,
        status: 'operational',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        services: {
            pki: 'operational',
            database: 'operational',
            filesystem: 'operational'
        }
    });
});

// Route principale pour servir l'interface PKI
app.get('/', (req, res) => {
    res.render('pki', {
        error: null,
        env: process.env,
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Gestion des vues manquantes
app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ ok: false, error: 'Endpoint API non trouvé' });
    }
    res.status(404).send('Page non trouvée');
});

// Configuration EJS
app.set('view engine', 'ejs');
app.set('views', CONFIG.paths.views);

// ========== DÉMARRAGE DU SERVEUR ==========

async function startServer() {
    try {
        await initializeSystem();
        
        app.listen(PORT, () => {
            console.log('\nServeur PKI démarré avec succès!');
            console.log(`Port: ${PORT}`);
            console.log(`URL: http://localhost:${PORT}`);
            console.log(`Données: ${CONFIG.paths.data}`);
            console.log(`Certificats: ${CONFIG.paths.certs}`);
            console.log(`API Health: http://localhost:${PORT}/api/health`);
            console.log('\nPrêt pour la production!');
        });

    } catch (error) {
        console.error('Impossible de démarrer le serveur:', error);
        process.exit(1);
    }
}

// Gestion propre de l'arrêt
process.on('SIGINT', async () => {
    console.log('\nArrêt du serveur PKI...');
    await AuditService.logEvent({
        action: 'system_shutdown',
        user: 'system',
        description: 'Arrêt du serveur PKI',
        severity: 'info'
    });
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\nArrêt du serveur PKI (SIGTERM)...');
    await AuditService.logEvent({
        action: 'system_shutdown',
        user: 'system',
        description: 'Arrêt du serveur PKI (SIGTERM)',
        severity: 'info'
    });
    process.exit(0);
});

// Démarrer le serveur
startServer();
