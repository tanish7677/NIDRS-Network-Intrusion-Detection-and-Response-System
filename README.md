# 🛡️ NIDRS — AI-Powered Network Intrusion Detection & Response System

**NIDRS (Network Intrusion Detection & Response System)** is an AI-powered cybersecurity prototype designed to detect known network attacks, identify anomalous live network behaviour, enrich security alerts, and provide recommended response strategies through a centralized dashboard.

The system combines **supervised and unsupervised machine learning**, live packet capture, threat-intelligence enrichment, risk assessment, incident tracking, email notifications, and automated PDF reporting into an end-to-end intrusion detection and response workflow.

---

## 🚀 Key Features

- 🤖 **Machine Learning-based Intrusion Detection**
- 🌲 **Random Forest** for known attack classification
- 🌳 **Isolation Forest** for live anomaly detection
- 📡 **Live packet capture using Scapy**
- 🔄 **Network flow formation and feature extraction**
- 🧠 **NSL-KDD based attack classification**
- 🛡️ **Threat intelligence enrichment**
- 🌍 **GeoIP-based location information**
- 🎯 **MITRE ATT&CK technique mapping**
- ⚠️ **Severity and risk assessment**
- 🔧 **Recommended response strategies**
- 📊 **Interactive Streamlit security dashboard**
- 🗄️ **SQLite-based alert and incident storage**
- 📧 **Email notifications for security alerts**
- 📄 **Automatic PDF incident reports**
- 📈 **Security analytics and alert history**

---

## 🧠 System Architecture

```text
                Network Traffic
                       │
                       ▼
              ┌─────────────────┐
              │ Packet Capture  │
              │     Scapy       │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Flow Formation  │
              │ & Feature       │
              │ Extraction      │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ AI Detection    │
              │                 │
              │ Random Forest   │
              │ Isolation Forest│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Alert Enrichment│
              │                 │
              │ Threat Intel    │
              │ GeoIP           │
              │ MITRE ATT&CK    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Response Engine │
              │                 │
              │ Risk Assessment │
              │ Recommended     │
              │ Response        │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Streamlit     │
              │   Dashboard     │
              └───────┬─────────┘
                      │
             ┌────────┴────────┐
             ▼                 ▼
        Email Alerts      PDF Reports
```

---

## 🤖 Machine Learning

### Random Forest

Random Forest is used as the **supervised machine learning model** for classifying known network activities using the **NSL-KDD dataset**.

The system classifies network activity into:

- Normal
- DoS — Denial of Service
- Probe
- R2L — Remote to Local
- U2R — User to Root

The training pipeline uses preprocessing and SMOTE-based oversampling to address class imbalance.

### Isolation Forest

Isolation Forest is used for **unsupervised anomaly detection** on live network traffic.

Live packets are captured using Scapy and grouped into network flows. Flow-level behavioural features are then calculated and passed through the trained Isolation Forest model.

The live detector uses six flow features:

- Packet Count
- Total Bytes
- Duration
- Packets per Second
- Bytes per Second
- Average Packet Size

The model returns:

```text
 1  → Normal
-1  → Anomalous
```

An anomalous flow is then stored as a **Live Anomaly** alert.

> **Note:** An anomaly indicates unusual network behaviour; it does not automatically prove that the traffic is malicious.

---

## 📊 Dashboard

NIDRS provides a Streamlit-based dashboard for centralized security monitoring.

The dashboard includes:

- Dashboard overview
- Dataset attack analysis
- Live anomaly monitoring
- Response Center
- Response History
- Security analytics
- Alert timeline
- Attack distribution
- Severity distribution
- Source and destination IP analysis
- System architecture
- Logs
- Settings

The dashboard is designed to give a security analyst a centralized view of detected network activity and recommended responses.

---

## 🛡️ Alert Enrichment

Detected alerts can be enriched with additional security context such as:

- **AbuseIPDB** threat intelligence
- **GeoIP** location information
- **MITRE ATT&CK** techniques

This helps provide more context around a detected security event.

---

## ⚙️ Response Engine

NIDRS goes beyond simply generating an intrusion alert.

The response engine associates detected events with a risk level and provides a recommended response strategy.

Example response categories include:

- Monitor
- Investigate
- Mitigate / Block

The objective is to help an analyst understand **what action can be considered after an alert is detected**.

---

## 📈 Dataset

The supervised detection component uses the **NSL-KDD dataset**.

Dataset characteristics used in the project:

- **125,973 samples**
- **41 input features**
- **5 activity classes**

The model evaluation uses a **stratified 80:20 holdout approach**.

The project achieved approximately **99.9% accuracy** on the reported evaluation.

---

## 🔄 Overall Workflow

```text
Network Traffic
      ↓
Packet Capture
      ↓
Flow Formation
      ↓
Feature Extraction
      ↓
┌─────────────────────────────┐
│ AI Detection                │
│                             │
│ Random Forest → Known Attacks│
│ Isolation Forest → Anomalies│
└─────────────┬───────────────┘
              ↓
       Alert Generation
              ↓
      Alert Enrichment
              ↓
       Risk Assessment
              ↓
     Response Recommendation
              ↓
      Streamlit Dashboard
          ↙        ↘
       Email      PDF Report
```

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Machine Learning | Scikit-learn |
| Supervised Model | Random Forest |
| Anomaly Detection | Isolation Forest |
| Packet Capture | Scapy |
| Data Processing | Pandas, NumPy |
| Database | SQLite |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Incident Reports | ReportLab |
| Threat Intelligence | AbuseIPDB |
| Threat Mapping | MITRE ATT&CK |
| Location Intelligence | GeoIP |

---

## 📁 Project Structure

```text
NIDRS/
│
├── ai/
│   ├── ...
│
├── capture/
│   ├── ...
│
├── dashboard/
│   ├── app.py
│   └── ...
│
├── database/
│   └── alerts.db
│
├── models/
│   ├── ...
│
├── response/
│   ├── ...
│
├── reports/
│   └── ...
│
├── requirements.txt
└── README.md
```

> The exact directory structure may vary depending on the current project version.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/tanish7677/NIDRS-Network-Intrusion-Detection-and-Response-System.git
```

### 2. Move into the project directory

```bash
cd NIDRS-Network-Intrusion-Detection-and-Response-System
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

**Windows:**

```powershell
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Streamlit dashboard

```bash
streamlit run dashboard/app.py
```

---

## 📧 Email Configuration

For email notification functionality, configure the required environment variables instead of storing credentials directly in the source code.

Example:

```text
NIDRS_SENDER_EMAIL
NIDRS_APP_PASSWORD
NIDRS_RECEIVER_EMAIL
```

For Gmail, an **App Password** should be used with an account where two-step verification is enabled.

⚠️ **Never commit passwords, API keys, app passwords, or other secrets to GitHub.**

---

## 🔐 Security Considerations

This project is intended as a **research, educational, and prototype cybersecurity system**.

Before production deployment, additional work would be required for:

- Secure credential management
- Strong authentication and authorization
- High-volume traffic handling
- Distributed deployment
- Model monitoring and retraining
- False-positive reduction
- Secure response automation
- Production-grade logging
- Network segmentation
- Fail-safe response mechanisms

---

## 🎯 Industry Relevance

NIDRS demonstrates an end-to-end workflow relevant to:

- Security Operations Centers (SOC)
- Enterprise network monitoring
- Network intrusion detection
- Security analytics
- Incident response
- Threat intelligence
- Cybersecurity research and education

The system can serve as a lightweight prototype for understanding how detection, enrichment, analysis, and response can be integrated into a single security monitoring workflow.

---

## 🚧 Current Limitations

- The current system is a prototype and is not intended to replace enterprise-grade IDS/IPS or SIEM platforms.
- Live anomaly detection depends on the quality and representativeness of the trained model.
- Isolation Forest identifies anomalous behaviour; anomaly does not necessarily mean confirmed malicious activity.
- Response recommendations are rule-based and should be validated by a security analyst before production use.
- Production deployment would require additional scalability and security hardening.

---

## 🔮 Future Improvements

Possible future enhancements include:

- Real-time continuous monitoring
- Automated firewall integration
- Advanced SOAR capabilities
- Better anomaly severity scoring
- Deep learning-based detection
- Explainable AI
- Distributed deployment
- Real-time WebSocket alerts
- Role-based access control
- Cloud deployment
- Model retraining pipeline
- Improved false-positive handling

---

## 👨‍💻 Team

### Tanish Kumar
**Machine Learning • Data Preprocessing • Threat Detection**

### Ekagra Tiwari
**Dashboard • Database Integration • Alert System**

---

## 📜 Project

**NIDRS — AI-Powered Network Intrusion Detection & Response System**

Developed as a cybersecurity and machine learning project.

**Department of Electronic Science**  
**Acharya Narendra Dev College, University of Delhi**

---

## ⭐ Acknowledgements

- NSL-KDD dataset
- Scikit-learn
- Scapy
- Streamlit
- Plotly
- AbuseIPDB
- MITRE ATT&CK
- GeoIP
- Open-source cybersecurity and machine learning community

---

## ⚠️ Disclaimer

This project is developed for **educational, research, and demonstration purposes**.

Do not use the packet-capture, monitoring, or response functionality on networks or systems without proper authorization.

---

## 📌 Repository

**GitHub:**  
https://github.com/tanish7677/NIDRS-Network-Intrusion-Detection-and-Response-System
