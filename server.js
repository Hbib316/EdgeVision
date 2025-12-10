// server.js - Serveur Node.js pour ESP32-CAM avec MQTT, MongoDB et Interface Web
const mqtt = require('mqtt');
const { MongoClient } = require('mongodb');
const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const fs = require('fs');
require('dotenv').config();

// ============================================
// CONFIGURATION (variables d'environnement uniquement)
// ============================================
const MQTT_BROKER = process.env.MQTT_BROKER;
const MQTT_OPTIONS = {
    username: process.env.MQTT_USERNAME,
    password: process.env.MQTT_PASSWORD,
    protocol: 'mqtts'
};
const TOPIC_DETECTION = process.env.MQTT_TOPIC_DETECTION || 'esp32cam/detection';
const TOPIC_STATUS = process.env.MQTT_TOPIC_STATUS || 'esp32cam/status';

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB_NAME;
const COLLECTION_DETECTIONS = 'detections';
const COLLECTION_STATUS = 'device_status';

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret-change-in-production';
// Frontend URL used for CORS. Set to '*' to allow all origins (use carefully).
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

// ============================================
// VÉRIFICATION DES VARIABLES D'ENVIRONNEMENT
// ============================================
function validateEnvironmentVariables() {
    const requiredVars = [
        'MQTT_BROKER',
        'MQTT_USERNAME',
        'MQTT_PASSWORD',
        'MONGODB_URI',
        'MONGODB_DB_NAME'
    ];
    
    const missingVars = requiredVars.filter(varName => !process.env[varName]);
    
    if (missingVars.length > 0) {
        console.error('❌ Variables d\'environnement manquantes:');
        missingVars.forEach(varName => console.error(`   - ${varName}`));
        console.error('\n🔧 Veuillez créer un fichier .env avec les variables suivantes:');
        console.error('MQTT_BROKER=your_mqtt_broker_url');
        console.error('MQTT_USERNAME=your_mqtt_username');
        console.error('MQTT_PASSWORD=your_mqtt_password');
        console.error('MONGODB_URI=your_mongodb_connection_string');
        console.error('MONGODB_DB_NAME=your_database_name');
        console.error('PORT=3000 (optionnel)');
        console.error('SESSION_SECRET=your-session-secret (optionnel)');
        console.error('MQTT_TOPIC_DETECTION=esp32cam/detection (optionnel)');
        console.error('MQTT_TOPIC_STATUS=esp32cam/status (optionnel)');
        process.exit(1);
    }
    
    console.log('✅ Toutes les variables d\'environnement sont présentes');
}

// ============================================
// VARIABLES GLOBALES
// ============================================
let db;
let detectionsCollection;
let statusCollection;
let mqttClient;
const app = express();

// When running behind a proxy (like Render), trust the first proxy so
// secure cookies and `req.protocol` are handled correctly.
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

// ============================================
// INITIALISATION EXPRESS
// ============================================
app.use(cors({
    // Allow a configurable frontend origin (use FRONTEND_URL='*' to allow all origins)
    origin: FRONTEND_URL === '*' ? true : FRONTEND_URL,
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        // Use secure cookies in production (app runs over HTTPS on Render)
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 heures
    }
}));

// ============================================
// MIDDLEWARE D'AUTHENTIFICATION
// ============================================
// Middleware pour vérifier l'authentification uniquement pour les API
function requireAuthApi(req, res, next) {
    // Routes API publiques
    const publicApiRoutes = [
        '/health',
        '/api/auth/login',
        '/api/health',
        '/api/auth/check'
    ];
    
    if (publicApiRoutes.includes(req.path)) {
        return next();
    }
    
    // Routes API - vérifier l'authentification
    if (req.session.user) {
        return next();
    }
    
    // Pour les routes API, retourner une erreur 401
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({
            success: false,
            error: 'Authentification requise'
        });
    }
    
    next();
}

// Middleware pour vérifier l'authentification pour les pages web
function requireAuthWeb(req, res, next) {
    // Routes web publiques
    const publicWebRoutes = ['/login', '/auth/login'];
    
    if (publicWebRoutes.includes(req.path)) {
        return next();
    }
    
    // Routes web - rediriger vers login si non authentifié
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    next();
}

// ============================================
// ROUTES WEB
// ============================================

// Page de login
app.get('/login', (req, res) => {
    // Si déjà connecté, rediriger vers le dashboard
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Page dashboard
app.get('/dashboard', requireAuthWeb, (req, res) => {
    console.log('📁 Tentative de chargement dashboard.html');
    console.log('📁 Chemin:', path.join(__dirname, 'dashboard.html'));
    
    // Vérifier si le fichier existe
    if (fs.existsSync(path.join(__dirname, 'dashboard.html'))) {
        console.log('✅ Fichier dashboard.html trouvé');
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        console.error('❌ Fichier dashboard.html NON trouvé');
        res.status(404).send(`
            <h1>Erreur 404 - Fichier non trouvé</h1>
            <p>Le fichier dashboard.html n'existe pas dans le répertoire: ${__dirname}</p>
            <p>Vérifiez que le fichier est présent.</p>
            <a href="/login">Retour à la connexion</a>
        `);
    }
});

// Route d'authentification
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('🔐 Tentative de connexion pour:', username);
        
        // Vérification simple (à remplacer par une vraie vérification dans MongoDB)
        if (username === 'admin' && password === 'admin123') {
            req.session.user = {
                id: 'admin',
                username: 'admin',
                role: 'admin',
                loginTime: new Date()
            };

            // Ensure the session is saved before sending the response so the
            // Set-Cookie header reaches the browser and subsequent requests
            // include the session cookie.
            req.session.save((err) => {
                if (err) {
                    console.error('❌ Erreur sauvegarde session:', err);
                    return res.status(500).json({ success: false, error: 'Erreur session' });
                }

                console.log('✅ Connexion réussie pour:', username);
                res.json({
                    success: true,
                    message: 'Connexion réussie',
                    user: {
                        username: 'admin',
                        role: 'admin'
                    }
                });
            });
        } else {
            console.log('❌ Connexion échouée pour:', username);
            res.status(401).json({
                success: false,
                error: 'Identifiants incorrects'
            });
        }
    } catch (error) {
        console.error('❌ Erreur lors de la connexion:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur lors de la connexion'
        });
    }
});

// Route de déconnexion
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Erreur lors de la déconnexion:', err);
            return res.status(500).json({
                success: false,
                error: 'Erreur lors de la déconnexion'
            });
        }
        
        console.log('✅ Déconnexion réussie');
        res.json({
            success: true,
            message: 'Déconnexion réussie'
        });
    });
});

// Route de vérification de session
app.get('/api/auth/check', (req, res) => {
    if (req.session.user) {
        console.log('✅ Session vérifiée pour:', req.session.user.username);
        res.json({
            success: true,
            authenticated: true,
            user: {
                username: req.session.user.username,
                role: req.session.user.role
            }
        });
    } else {
        console.log('⚠️ Session non authentifiée');
        res.json({
            success: true,
            authenticated: false
        });
    }
});

// Redirection racine
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// ============================================
// APPLIQUER L'AUTHENTIFICATION AUX ROUTES
// ============================================
// Appliquer l'authentification aux routes API (sauf les routes publiques)
app.use('/api', requireAuthApi);

// ============================================
// CONNEXION MONGODB
// ============================================
async function connectMongoDB() {
    try {
        console.log('📦 Connexion à MongoDB Atlas...');
        console.log(`📊 Base de données: ${DB_NAME}`);
        
        // Options de connexion avec gestion SSL/TLS améliorée
        const mongoOptions = {
            tls: true,
            tlsAllowInvalidCertificates: false,
            tlsAllowInvalidHostnames: false,
            serverSelectionTimeoutMS: 30000,
            connectTimeoutMS: 30000,
            socketTimeoutMS: 30000,
        };
        
        const client = await MongoClient.connect(MONGODB_URI, mongoOptions);
        
        db = client.db(DB_NAME);
        detectionsCollection = db.collection(COLLECTION_DETECTIONS);
        statusCollection = db.collection(COLLECTION_STATUS);
        
        // Créer des index
        await detectionsCollection.createIndex({ timestamp: -1 });
        await detectionsCollection.createIndex({ detected: 1 });
        await detectionsCollection.createIndex({ label: 1 });
        await detectionsCollection.createIndex({ saved_at: -1 });
        
        console.log('✅ MongoDB connecté avec succès!');
        
        const stats = await db.command({ ping: 1 });
        if (stats.ok === 1) {
            console.log('📊 Connexion MongoDB vérifiée');
        }
    } catch (error) {
        console.error('❌ Erreur MongoDB:', error.message);
        console.error('\n🔍 Vérifications à faire:');
        console.error('   1. Votre IP est-elle autorisée dans MongoDB Atlas Network Access?');
        console.error('   2. Le nom d\'utilisateur et mot de passe sont-ils corrects?');
        console.error('   3. La chaîne de connexion est-elle au format: mongodb+srv://user:pass@cluster.xxx.mongodb.net/?retryWrites=true&w=majority');
        console.error('   4. Avez-vous Node.js version 14 ou supérieure?');
        process.exit(1);
    }
}

// ============================================
// CONNEXION MQTT
// ============================================
function connectMQTT() {
    console.log('🔌 Connexion au broker MQTT...');
    console.log(`📡 Broker: ${MQTT_BROKER}`);
    
    mqttClient = mqtt.connect(MQTT_BROKER, MQTT_OPTIONS);
    
    mqttClient.on('connect', () => {
        console.log('✅ MQTT connecté!');
        mqttClient.subscribe([TOPIC_DETECTION, TOPIC_STATUS], (err) => {
            if (err) {
                console.error('❌ Erreur abonnement:', err);
            } else {
                console.log('📡 Abonné aux topics:', TOPIC_DETECTION, TOPIC_STATUS);
            }
        });
    });
    
    mqttClient.on('message', async (topic, message) => {
        try {
            const data = JSON.parse(message.toString());
            
            if (topic === TOPIC_DETECTION) {
                await handleDetection(data);
            } else if (topic === TOPIC_STATUS) {
                await handleStatus(data);
            }
        } catch (error) {
            console.error('❌ Erreur traitement message:', error);
        }
    });
    
    mqttClient.on('error', (error) => {
        console.error('❌ Erreur MQTT:', error);
    });
    
    mqttClient.on('close', () => {
        console.log('⚠️ Connexion MQTT fermée');
    });
}

// ============================================
// GESTION DES DÉTECTIONS
// ============================================
async function handleDetection(data) {
    try {
        const detection = {
            ...data,
            timestamp: new Date(),
            saved_at: new Date()
        };
        
        const result = await detectionsCollection.insertOne(detection);
        
        if (data.detected) {
            console.log(`✅ Détection sauvegardée: ${data.label} (${(data.proba * 100).toFixed(1)}%)`);
        }
        
    } catch (error) {
        console.error('❌ Erreur sauvegarde détection:', error);
    }
}

// ============================================
// GESTION DU STATUT
// ============================================
async function handleStatus(data) {
    try {
        const status = {
            ...data,
            timestamp: new Date(),
            last_updated: new Date()
        };
        
        await statusCollection.updateOne(
            { device: data.device || 'ESP32-CAM' },
            { $set: status },
            { upsert: true }
        );
        
        console.log(`📊 Statut mis à jour: ${data.status}`);
        
    } catch (error) {
        console.error('❌ Erreur sauvegarde statut:', error);
    }
}

// ============================================
// ROUTES API
// ============================================

// Route: Obtenir les dernières détections
app.get('/api/detections', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const skip = parseInt(req.query.skip) || 0;
        const label = req.query.label;
        const detected = req.query.detected;
        
        let query = {};
        
        if (label && label !== 'all') {
            query.label = label;
        }
        
        if (detected) {
            query.detected = detected === 'true';
        }
        
        const detections = await detectionsCollection
            .find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
        
        const total = await detectionsCollection.countDocuments(query);
        
        res.json({
            success: true,
            count: detections.length,
            total: total,
            data: detections
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Obtenir les détections avec objet
app.get('/api/detections/detected', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const skip = parseInt(req.query.skip) || 0;
        const label = req.query.label;
        
        let query = { detected: true };
        
        if (label && label !== 'all') {
            query.label = label;
        }
        
        const detections = await detectionsCollection
            .find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
        
        const total = await detectionsCollection.countDocuments(query);
        
        res.json({
            success: true,
            count: detections.length,
            total: total,
            data: detections
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Obtenir les labels distincts
app.get('/api/labels', async (req, res) => {
    try {
        const labels = await detectionsCollection.distinct('label', { label: { $ne: '' } });
        
        res.json({
            success: true,
            count: labels.length,
            data: labels
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Détections filtrées par label
app.get('/api/detections/by-label/:label', async (req, res) => {
    try {
        const label = req.params.label;
        const limit = parseInt(req.query.limit) || 50;
        const skip = parseInt(req.query.skip) || 0;
        
        const query = { label: label };
        
        const detections = await detectionsCollection
            .find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
        
        const total = await detectionsCollection.countDocuments(query);
        
        res.json({
            success: true,
            count: detections.length,
            total: total,
            data: detections
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Détections par période
app.get('/api/detections/period', async (req, res) => {
    try {
        const { startDate, endDate, label } = req.query;
        let query = {};
        
        if (startDate && endDate) {
            query.timestamp = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }
        
        if (label && label !== 'all') {
            query.label = label;
        }
        
        const limit = parseInt(req.query.limit) || 100;
        const skip = parseInt(req.query.skip) || 0;
        
        const detections = await detectionsCollection
            .find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
        
        const total = await detectionsCollection.countDocuments(query);
        
        res.json({
            success: true,
            count: detections.length,
            total: total,
            data: detections
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Statistiques
app.get('/api/stats', async (req, res) => {
    try {
        const totalDetections = await detectionsCollection.countDocuments({});
        const objectsDetected = await detectionsCollection.countDocuments({ detected: true });
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayDetections = await detectionsCollection.countDocuments({
            timestamp: { $gte: today }
        });
        
        const topObjects = await detectionsCollection.aggregate([
            { $match: { detected: true, label: { $ne: '' } } },
            { $group: { 
                _id: '$label', 
                count: { $sum: 1 }, 
                last_detection: { $max: '$timestamp' }
            }},
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]).toArray();
        
        res.json({
            success: true,
            stats: {
                total_detections: totalDetections,
                objects_detected: objectsDetected,
                today_detections: todayDetections,
                detection_rate: totalDetections > 0 ? ((objectsDetected / totalDetections) * 100).toFixed(2) + '%' : '0%',
                top_objects: topObjects
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Statistiques détaillées par label
app.get('/api/stats/labels', async (req, res) => {
    try {
        const labelStats = await detectionsCollection.aggregate([
            { $match: { detected: true, label: { $ne: '' } } },
            { $group: {
                _id: '$label',
                total: { $sum: 1 },
                avg_x: { $avg: '$x' },
                avg_y: { $avg: '$y' },
                avg_width: { $avg: '$width' },
                avg_height: { $avg: '$height' },
                first_detection: { $min: '$timestamp' },
                last_detection: { $max: '$timestamp' }
            }},
            { $sort: { total: -1 } }
        ]).toArray();
        
        res.json({
            success: true,
            data: labelStats
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Statut du dispositif
app.get('/api/status', async (req, res) => {
    try {
        const status = await statusCollection.findOne({}, { sort: { last_updated: -1 } });
        
        // Vérifier si le statut est à jour (moins de 5 minutes)
        let isOnline = false;
        if (status && status.last_updated) {
            const lastUpdate = new Date(status.last_updated);
            const now = new Date();
            const minutesDiff = (now - lastUpdate) / (1000 * 60);
            isOnline = minutesDiff < 5;
        }
        
        res.json({
            success: true,
            data: {
                ...status,
                is_online: isOnline,
                last_seen: status ? status.last_updated : null
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Supprimer des détections (admin uniquement)
app.delete('/api/detections', async (req, res) => {
    try {
        // Vérifier si l'utilisateur est admin
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Permission refusée'
            });
        }
        
        const { startDate, endDate, label } = req.body;
        
        let query = {};
        
        if (startDate && endDate) {
            query.timestamp = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }
        
        if (label && label !== 'all') {
            query.label = label;
        }
        
        const result = await detectionsCollection.deleteMany(query);
        
        res.json({
            success: true,
            deletedCount: result.deletedCount,
            message: `${result.deletedCount} détections supprimées`
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Obtenir la dernière détection
app.get('/api/detections/latest', async (req, res) => {
    try {
        const detection = await detectionsCollection
            .findOne({ detected: true }, { sort: { timestamp: -1 } });
        
        res.json({
            success: true,
            data: detection
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Recherche de détections
app.get('/api/detections/search', async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        
        let query = {};
        
        if (q) {
            query.label = { $regex: q, $options: 'i' };
        }
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const detections = await detectionsCollection
            .find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .toArray();
        
        const total = await detectionsCollection.countDocuments(query);
        
        res.json({
            success: true,
            data: detections,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: total,
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Informations système
app.get('/api/system/info', async (req, res) => {
    try {
        const dbStats = await db.stats();
        const collections = await db.listCollections().toArray();
        
        const collectionInfo = await Promise.all(
            collections.map(async (col) => {
                const collection = db.collection(col.name);
                const count = await collection.countDocuments();
                return {
                    name: col.name,
                    count: count
                };
            })
        );
        
        res.json({
            success: true,
            data: {
                mongodb: {
                    database: DB_NAME,
                    collections: collectionInfo,
                    stats: {
                        objects: dbStats.objects,
                        avgObjSize: dbStats.avgObjSize,
                        dataSize: dbStats.dataSize,
                        storageSize: dbStats.storageSize
                    }
                },
                mqtt: {
                    connected: mqttClient?.connected || false,
                    broker: MQTT_BROKER
                },
                server: {
                    uptime: process.uptime(),
                    memory: process.memoryUsage(),
                    node_version: process.version
                }
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Route: Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date(),
        services: {
            mqtt: mqttClient?.connected ? 'connected' : 'disconnected',
            mongodb: db ? 'connected' : 'disconnected',
            api: 'running'
        },
        version: '1.0.0'
    });
});

// Route API health
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        authenticated: !!req.session.user,
        services: {
            mqtt: mqttClient?.connected ? 'connected' : 'disconnected',
            mongodb: db ? 'connected' : 'disconnected'
        }
    });
});

// ============================================
// SERVIR LES FICHIERS STATIQUES
// ============================================
app.use(express.static(__dirname, {
    extensions: ['html', 'htm', 'css', 'js', 'png', 'jpg', 'gif'],
    setHeaders: (res, path) => {
        // Définir les en-têtes CORS pour les fichiers statiques
        res.setHeader('Access-Control-Allow-Origin', FRONTEND_URL === '*' ? '*' : FRONTEND_URL);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
}));

// ============================================
// GESTION DES ERREURS
// ============================================

// Gestion des 404
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        error: 'Route non trouvée: ' + req.path
    });
});

// Gestion des erreurs globales
app.use((err, req, res, next) => {
    console.error('❌ Erreur serveur:', err);
    
    res.status(err.status || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' 
            ? 'Erreur interne du serveur' 
            : err.message
    });
});

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================
async function startServer() {
    try {
        console.log('🚀 Démarrage du serveur ESP32-CAM MQTT MongoDB...');
        console.log(`🌐 Port: ${PORT}`);
        console.log(`🔒 Mode: ${process.env.NODE_ENV || 'development'}`);
        
        // Vérifier les variables d'environnement
        validateEnvironmentVariables();
        
        // Connexion MongoDB
        await connectMongoDB();
        
        // Connexion MQTT
        connectMQTT();
        
        // Démarrage du serveur Express (bind to 0.0.0.0 for hosting providers)
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`✅ Serveur API démarré sur port ${PORT}`);
            console.log('\n📋 Points d\'accès disponibles:');
            console.log(`   WEB  /login              - Page de connexion`);
            console.log(`   WEB  /dashboard          - Tableau de bord (authentification requise)`);
            console.log(`   API   /api/auth/login    - Connexion API`);
            console.log(`   API   /api/detections    - Liste des détections`);
            console.log(`   API   /api/labels        - Labels disponibles`);
            console.log(`   API   /api/stats         - Statistiques`);
            console.log(`   API   /api/status        - Statut ESP32-CAM`);
            console.log(`   API   /health            - Health check`);
            console.log('\n🔧 Configuration:');
            console.log(`   MQTT Broker: ${MQTT_BROKER}`);
            console.log(`   MQTT Topics: ${TOPIC_DETECTION}, ${TOPIC_STATUS}`);
            console.log(`   MongoDB Database: ${DB_NAME}`);
            console.log(`   Authentification: Sessions avec express-session`);
            console.log(`\n👤 Identifiants de test:`);
            console.log(`   Username: admin`);
            console.log(`   Password: admin123`);
        });
    } catch (error) {
        console.error('❌ Erreur démarrage serveur:', error);
        process.exit(1);
    }
}

// ============================================
// GESTION DE L'ARRÊT PROPRE
// ============================================
process.on('SIGINT', async () => {
    console.log('\n👋 Arrêt du serveur...');
    
    try {
        if (mqttClient) {
            console.log('🔌 Fermeture connexion MQTT...');
            mqttClient.end();
        }
        
        if (db) {
            console.log('📦 Fermeture connexion MongoDB...');
            await db.client.close();
        }
        
        console.log('✅ Serveur arrêté proprement');
        process.exit(0);
    } catch (error) {
        console.error('❌ Erreur lors de l\'arrêt:', error);
        process.exit(1);
    }
});

process.on('SIGTERM', async () => {
    console.log('\n⚠️ Signal SIGTERM reçu, arrêt du serveur...');
    
    if (mqttClient) mqttClient.end();
    if (db) await db.client.close();
    
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Exception non capturée:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Rejet non géré:', reason);
});

// ============================================
// DÉMARRAGE
// ============================================
startServer();