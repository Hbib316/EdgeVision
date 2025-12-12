// server-opti.js - Serveur avec authentification
const mqtt = require('mqtt');
const { MongoClient } = require('mongodb');
const express = require('express');
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Configuration
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const MQTT_BROKER = process.env.MQTT_BROKER;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB_NAME;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Variables globales
let db, mqttClient;
const activeClients = new Set();

// Initialisation Express
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Middleware d'authentification JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide' });
        }
        req.user = user;
        next();
    });
}

// Middleware d'authentification WebSocket
function authenticateWebSocket(request) {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const token = url.searchParams.get('token');
    
    if (!token) {
        return null;
    }
    
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Initialiser la base de données avec un utilisateur par défaut
async function initializeDatabase() {
    // Vérifier si la collection users existe
    const collections = await db.listCollections().toArray();
    const usersCollectionExists = collections.some(col => col.name === 'users');
    
    if (!usersCollectionExists) {
        await db.createCollection('users');
        await db.collection('users').createIndex({ username: 1 }, { unique: true });
        
        // Créer un utilisateur admin par défaut
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await db.collection('users').insertOne({
            username: 'admin',
            password: hashedPassword,
            role: 'admin',
            createdAt: new Date(),
            lastLogin: null
        });
        
        console.log('✅ Utilisateur admin créé (admin / admin123)');
    }
}

// Connexion MongoDB avec cache
async function connectMongoDB() {
    const client = await MongoClient.connect(MONGODB_URI, {
        maxPoolSize: 5,
        minPoolSize: 1,
        maxIdleTimeMS: 30000
    });
    db = client.db(DB_NAME);
    
    // Création d'index optimisés
    await db.collection('detections').createIndexes([
        { key: { timestamp: -1 } },
        { key: { detected: 1, timestamp: -1 } },
        { key: { label: 1 } }
    ]);
    
    // Initialiser la base de données
    await initializeDatabase();
    
    console.log('✅ MongoDB connecté avec cache');
}

// Fonction pour normaliser le timestamp
function normalizeTimestamp(timestamp) {
    if (!timestamp) {
        return new Date();
    }
    
    // Si c'est un nombre
    if (typeof timestamp === 'number') {
        // Si c'est un petit nombre (< 10^10), c'est probablement millis() Arduino
        // millis() Arduino retourne typiquement < 50 jours (4.3e9 ms)
        if (timestamp < 10000000000) {
            // Convertir: timestamp serveur - millis Arduino + timestamp Arduino
            // Simplification: utiliser timestamp serveur
            return new Date();
        } else {
            // Si c'est un grand nombre, c'est probablement un timestamp Unix en ms
            return new Date(timestamp);
        }
    }
    
    // Si c'est une chaîne, essayer de la parser
    if (typeof timestamp === 'string') {
        const date = new Date(timestamp);
        if (!isNaN(date.getTime())) {
            return date;
        }
    }
    
    // Par défaut, utiliser l'heure actuelle
    return new Date();
}

// Connexion MQTT
function connectMQTT() {
    mqttClient = mqtt.connect(MQTT_BROKER, {
        username: process.env.MQTT_USERNAME,
        password: process.env.MQTT_PASSWORD
    });

    mqttClient.on('connect', () => {
        console.log('✅ MQTT connecté');
        mqttClient.subscribe('esp32cam/detection');
    });

    mqttClient.on('message', async (topic, message) => {
        try {
            const data = JSON.parse(message.toString());
            
            // Normaliser le timestamp
            data.timestamp = normalizeTimestamp(data.timestamp);
            
            // Ajouter l'adresse IP si disponible
            if (mqttClient.options && mqttClient.options.hostname) {
                data.source = mqttClient.options.hostname;
            }
            
            // Insertion rapide dans MongoDB
            await db.collection('detections').insertOne(data);
            
            // Broadcast en temps réel via WebSocket
            broadcastToClients({
                type: 'detection',
                data: data
            });
            
            // Log minimal pour performance
            if (data.detected) {
                console.log(`🎯 ${data.label || 'Objet'} (${data.x},${data.y}) à ${data.timestamp.toLocaleTimeString()}`);
            } else {
                console.log(`⭕ Aucun objet à ${data.timestamp.toLocaleTimeString()}`);
            }
        } catch (error) {
            console.error('❌ Erreur MQTT:', error.message);
            console.error('Message reçu:', message.toString());
        }
    });
}

// WebSocket pour temps réel
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, request) => {
    const user = authenticateWebSocket(request);
    
    if (!user) {
        ws.close(1008, 'Non autorisé');
        return;
    }
    
    activeClients.add(ws);
    
    ws.on('close', () => {
        activeClients.delete(ws);
    });
});

function broadcastToClients(data) {
    const message = JSON.stringify(data);
    activeClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Routes d'authentification
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });
        }
        
        // Rechercher l'utilisateur
        const user = await db.collection('users').findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Identifiants incorrects' });
        }
        
        // Vérifier le mot de passe
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Identifiants incorrects' });
        }
        
        // Mettre à jour la dernière connexion
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );
        
        // Générer le token JWT
        const token = jwt.sign(
            { 
                userId: user._id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );
        
        res.json({
            token,
            user: {
                username: user.username,
                role: user.role
            }
        });
        
    } catch (error) {
        console.error('Erreur de connexion:', error);
        res.status(500).json({ error: 'Erreur interne du serveur' });
    }
});

// Routes API protégées
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const detected = await db.collection('detections').countDocuments({ detected: true });
        
        res.json({
            detected,
            timestamp: new Date()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/labels', authenticateToken, async (req, res) => {
    try {
        const labelStats = await db.collection('detections')
            .aggregate([
                { $match: { detected: true, label: { $exists: true, $ne: null } } },
                { $group: { _id: "$label", count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ])
            .toArray();
        
        res.json(labelStats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/detections', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const detections = await db.collection('detections')
            .find({ detected: true })
            .sort({ timestamp: -1 })
            .limit(limit)
            .toArray();
        
        res.json(detections);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/clear', authenticateToken, async (req, res) => {
    try {
        const result = await db.collection('detections').deleteMany({});
        res.json({ deleted: result.deletedCount });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Routes publiques pour les pages HTML
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Health check (publique)
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        mqtt: mqttClient?.connected ? 'connected' : 'disconnected',
        mongodb: !!db,
        clients: activeClients.size,
        version: '2.0',
        authenticated: req.user ? true : false,
        serverTime: new Date().toISOString()
    });
});

// Démarrer le serveur
async function startServer() {
    try {
        await connectMongoDB();
        connectMQTT();
        
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Serveur démarré sur port ${PORT}`);
            console.log(`🔐 Page de connexion: http://localhost:${PORT}`);
            console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard.html`);
            console.log(`🔑 Identifiants par défaut: admin / admin123`);
            console.log(`⏰ Heure serveur: ${new Date().toLocaleString()}`);
        });
        
        // Intégrer WebSocket au serveur HTTP
        server.on('upgrade', (request, socket, head) => {
            wss.handleUpgrade(request, socket, head, (ws) => {
                wss.emit('connection', ws, request);
            });
        });
        
        // Gestion des erreurs non capturées
        process.on('uncaughtException', (error) => {
            console.error('❌ Erreur non capturée:', error);
        });
        
        process.on('unhandledRejection', (error) => {
            console.error('❌ Rejet non géré:', error);
        });
        
    } catch (error) {
        console.error('❌ Erreur démarrage:', error);
        process.exit(1);
    }
}

startServer();