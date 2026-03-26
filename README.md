# 🔍 Web Forensics Detector

An AI-powered web security tool for detecting and analyzing web attacks in real-time, including SQL Injection, XSS, Path Traversal, Command Injection, DoS, and DDoS attacks.

---

## 📌 Overview

Web Forensics Detector is a machine learning-based system trained on real HTTP traffic data (CSIC 2010 dataset) combined with synthetic attack payloads. It analyzes Apache/Nginx access logs and individual HTTP requests to identify malicious activity and generate forensic reports.

---

## 🚀 Features

- **Real-time HTTP Request Analysis** — Classify any HTTP request as normal or malicious
- **Apache/Nginx Log File Analysis** — Paste any access log and get an instant forensic report
- **Attack Type Detection** — Identifies SQL Injection, XSS, Path Traversal, Command Injection, Sensitive File Access, and Null Byte Injection
- **DoS/DDoS Detection** — Detects Denial of Service, Distributed DoS, and HTTP Flood attacks
- **IP Tracking** — Tracks and ranks attacker IPs
- **Live Attack Report** — Real-time log of all detected attacks during server runtime

---

## 🧠 Model

| Property | Value |
|----------|-------|
| Algorithm | XGBoost Classifier |
| Training Data | CSIC 2010 + Synthetic Payloads |
| Total Samples | ~93,000 HTTP requests |
| Accuracy | 92% |
| AUC-ROC | 0.986 |
| F1-Score (CV) | 0.9435 ± 0.0002 |
| Recall (Attacks) | 97% |

### Features Used
- URI length, GET/POST length, combined length
- SQL/XSS/Traversal/Command Injection pattern detection
- Special character count, percent encoding, null byte presence
- Parameter count, request method, URI depth

---

## 🛡️ Attack Types Detected

| Attack | Example |
|--------|---------|
| SQL Injection | `?id=1' OR 1=1--` |
| XSS | `?q=<script>alert(1)</script>` |
| Path Traversal | `/files/../../../../etc/passwd` |
| Command Injection | `?cmd=;ls -la` |
| Sensitive File Access | `/.env`, `/backup.sql`, `/.htaccess` |
| DoS | Single IP > 50 requests/minute |
| DDoS | 20+ unique IPs in same minute |
| HTTP Flood | 70%+ requests targeting same URI |

---

## 📁 Project Structure
```
AISec/
├── app.py                  # Flask API + Web Interface
├── train_model_v2.py       # Model Training Script
├── generate_data.py        # Synthetic Data Generator
├── web_forensics_model.pkl # Trained XGBoost Model
├── label_encoder.pkl       # Label Encoder
├── templates/
│   └── index.html          # Web Interface
└── data/
    └── Web-Application-Attack-Datasets-master/
        └── CSVData/
            └── csic_final.csv
```

---

## ⚙️ Installation
```bash
# Clone the repository
git clone https://github.com/ayadseghairi/web-forensics-detector.git
cd web-forensics-detector

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask xgboost scikit-learn pandas numpy matplotlib seaborn joblib
```

---

## 🏃 Usage

### Run the Web Interface
```bash
python app.py
```
Then open **http://localhost:5000**

### Retrain the Model
```bash
# Generate synthetic data
python generate_data.py

# Train
python train_model_v2.py
```

### API Endpoints

**Analyze a single request:**
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"uri": "/search.php", "get_query": "q=1 UNION SELECT * FROM users--", "method": "GET"}'
```

**Analyze a log file:**
```bash
curl -X POST http://localhost:5000/analyze/logfile \
  -H "Content-Type: application/json" \
  -d '{"content": "192.168.1.1 - - [26/Mar/2026:09:00:01] \"GET /index.php HTTP/1.1\" 200 1234"}'
```

**Get attack report:**
```bash
curl http://localhost:5000/report
```

---

## 📊 API Response Example
```json
{
  "prediction": "Anomalous",
  "confidence": 99.87,
  "is_attack": true,
  "attack_types": ["SQL Injection"],
  "probabilities": {
    "Anomalous": 99.87,
    "Valid": 0.13
  }
}
```

---

## 🗃️ Dataset

- **CSIC 2010** — 61,065 HTTP requests (36,000 normal + 25,065 attacks)
- **Synthetic Data** — 32,400 generated requests covering diverse attack patterns and normal PHP/HTML traffic

---

## 🔧 Tech Stack

- **Backend:** Python, Flask
- **ML:** XGBoost, Scikit-learn
- **Data:** Pandas, NumPy
- **Frontend:** HTML, CSS, JavaScript

---

## 📈 Results
```
              precision    recall  f1-score
   Anomalous       0.80      0.97      0.88
       Valid       0.99      0.90      0.94
    accuracy                           0.92

AUC-ROC: 0.9860
Cross-Validation F1: 0.9435 ± 0.0002
```

---

## 👤 Author

**Ayad Seghairi**
Computer Science Student — Abbas Laghrour University, Khenchela, Algeria

- GitHub: [@ayadseghairi](https://github.com/ayadseghairi)

---

## 📄 License
MIT License — feel free to use, modify, and distribute.
