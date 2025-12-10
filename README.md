
### Components:

1. **ESP32-CAM**: Captures images and runs FOMO object detection
2. **MQTT Broker**: HiveMQ Cloud for secure message routing
3. **Node.js Server**: Handles MQTT subscriptions, MongoDB storage, API endpoints
4. **MongoDB Atlas**: Cloud database for detection storage
5. **Web Dashboard**: User interface for monitoring and management

## 🔧 Hardware Requirements

- **ESP32-CAM** (AI-Thinker or compatible)
- **5V Power Supply** (recommended for stable operation)

## 💻 Software Requirements

### For ESP32-CAM:
- Arduino IDE (1.8.x or 2.x)
- ESP32 Board Support
- Required Libraries:
  - `eloquent_esp32cam` (≥2.4.0)
  - `Edge Impulse Arduino SDK`
  - `ArduinoJson` (≥6.x)
  - `PubSubClient` (≥2.8)

### For Server:
- Node.js (≥14.0.0)
- npm (≥6.0.0)

### Accounts Needed:
- MongoDB Atlas account (free tier available)
- HiveMQ Cloud account (free tier available)

## 📊 Dashboard Features

### Main Dashboard
- Real-time detection counter
- Total detections statistics
- Active labels count
- System status indicators
- Recent detections table
- Filter options

### Live Detections
- Real-time MQTT feed
- Object detection cards
- Confidence scores
- Position coordinates

### History
- Complete detection archive
- Date range filtering
- Label filtering
- Bulk delete operations
- Export capabilities
- Pagination

### Labels
- Statistics by object type
- Detection frequency
- First/last detection dates
- Usage percentages

### System
- MQTT connection status
- MongoDB status
- ESP32-CAM status
- System logs
- Uptime information

## 🔐 Security Considerations

1. **Change Default Credentials**: Update admin username/password
2. **Secure Session Secret**: Use strong random string
3. **HTTPS Only**: Deploy with SSL/TLS
4. **MongoDB Security**: Use strong passwords, enable IP whitelist
5. **MQTT Security**: Use TLS/SSL, strong credentials
6. **Input Validation**: All user inputs are sanitized
7. **CORS Configuration**: Restrict to specific origins in production

## 👥 Authors

- **Hbib316** - Initial work - [GitHub](https://github.com/Hbib316)

## 🙏 Acknowledgments

- [Edge Impulse](https://edgeimpulse.com) for FOMO model
- [Eloquent Arduino](https://github.com/eloquentarduino/eloquentarduino-esp32cam) for ESP32-CAM library
- [HiveMQ](https://www.hivemq.com) for MQTT broker
- [MongoDB](https://www.mongodb.com) for database
- Arduino and ESP32 communities

---

**Made with ❤️ using ESP32-CAM, Edge Impulse, MQTT, and MongoDB**
