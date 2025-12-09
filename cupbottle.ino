#include <EDGE_inferencing.h>
#include <eloquent_esp32cam.h>
#include <eloquent_esp32cam/edgeimpulse/fomo.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

using eloq::camera;
using eloq::ei::fomo;

// WiFi credentials
const char* ssid = "cyberguards";
const char* password = "1234567890";

// MQTT HiveMQ Cloud credentials
const char* mqtt_server = "029c7e99bf2d4fbba3302015c8340195.s1.eu.hivemq.cloud";
const int mqtt_port = 8883;
const char* mqtt_username = "haboub";
const char* mqtt_password = "Haboub23";

// MQTT Topics
const char* topic_detection = "esp32cam/detection";
const char* topic_status = "esp32cam/status";

WiFiClientSecure espClient;
PubSubClient client(espClient);

unsigned long lastReconnectAttempt = 0;
unsigned long lastStatusUpdate = 0;
const long statusInterval = 5000; // Send status every 5 seconds

void setup_wifi() {
    delay(10);
    Serial.println();
    Serial.print("Connexion WiFi à ");
    Serial.println(ssid);

    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }

    Serial.println("");
    Serial.println("WiFi connecté");
    Serial.print("Adresse IP: ");
    Serial.println(WiFi.localIP());
}

void reconnect() {
    if (millis() - lastReconnectAttempt > 5000) {
        lastReconnectAttempt = millis();
        
        Serial.print("Tentative de connexion MQTT...");
        
        // Generate unique client ID
        String clientId = "ESP32CAM_";
        clientId += String(random(0xffff), HEX);
        
        if (client.connect(clientId.c_str(), mqtt_username, mqtt_password)) {
            Serial.println("connecté");
            
            // Publish status
            StaticJsonDocument<200> statusDoc;
            statusDoc["device"] = "ESP32-CAM";
            statusDoc["status"] = "online";
            statusDoc["ip"] = WiFi.localIP().toString();
            
            char statusBuffer[200];
            serializeJson(statusDoc, statusBuffer);
            client.publish(topic_status, statusBuffer, true);
            
        } else {
            Serial.print("échec, rc=");
            Serial.print(client.state());
            Serial.println(" nouvelle tentative dans 5s");
        }
    }
}

void setup() {
    delay(3000);
    Serial.begin(115200);
    Serial.println("__EDGE IMPULSE FOMO + MQTT__");
    Serial.println("Initialisation...");

    // Camera settings
    camera.pinout.aithinker();
    camera.brownout.disable();
    camera.resolution.yolo();
    camera.pixformat.rgb565();

    // Initialize camera
    while (!camera.begin().isOk()) {
        Serial.println("Erreur Camera!");
        Serial.println(camera.exception.toString());
        delay(1000);
    }

    Serial.println("Camera OK");

    // Connect to WiFi
    setup_wifi();

    // Setup MQTT
    espClient.setInsecure(); // For testing - use proper certificate in production
    client.setServer(mqtt_server, mqtt_port);
    client.setBufferSize(512);

    Serial.println("Système prêt!");
    Serial.println("====================================");
}

void loop() {
    // Maintain MQTT connection
    if (!client.connected()) {
        reconnect();
    }
    client.loop();

    // Send periodic status
    if (millis() - lastStatusUpdate > statusInterval) {
        lastStatusUpdate = millis();
        
        StaticJsonDocument<200> statusDoc;
        statusDoc["device"] = "ESP32-CAM";
        statusDoc["status"] = "running";
        statusDoc["uptime"] = millis() / 1000;
        statusDoc["freeHeap"] = ESP.getFreeHeap();
        
        char statusBuffer[200];
        serializeJson(statusDoc, statusBuffer);
        client.publish(topic_status, statusBuffer);
    }

    // Capture picture
    if (!camera.capture().isOk()) {
        Serial.println("Capture échouée!");
        return;
    }

    // Run FOMO inference
    if (!fomo.run().isOk()) {
        Serial.println("Erreur d'inférence!");
        return;
    }

    // Prepare JSON data
    StaticJsonDocument<400> doc;
    doc["count"] = fomo.count();
    doc["time"] = fomo.benchmark.millis();
    doc["timestamp"] = millis();

    if (fomo.foundAnyObject()) {
        doc["detected"] = true;
        doc["label"] = fomo.first.label;
        doc["x"] = fomo.first.x;
        doc["y"] = fomo.first.y;
        doc["width"] = fomo.first.width;
        doc["height"] = fomo.first.height;
        doc["proba"] = fomo.first.proba;
        
        Serial.printf("Détecté: %s (%.2f) à (%d,%d)\n", 
                     fomo.first.label, fomo.first.proba, 
                     fomo.first.x, fomo.first.y);
    } else {
        doc["detected"] = false;
        doc["label"] = "";
        doc["x"] = 0;
        doc["y"] = 0;
        doc["width"] = 0;
        doc["height"] = 0;
        doc["proba"] = 0;
    }

    // Serialize and publish
    char jsonBuffer[400];
    serializeJson(doc, jsonBuffer);
    
    if (client.publish(topic_detection, jsonBuffer)) {
        Serial.println("Données publiées sur MQTT");
    } else {
        Serial.println("Échec publication MQTT");
    }

    delay(100);
}