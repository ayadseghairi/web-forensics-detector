from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re
from collections import Counter, defaultdict
from datetime import datetime

app = Flask(__name__)
model = joblib.load("web_forensics_model.pkl")
le    = joblib.load("label_encoder.pkl")

sql_pattern       = r"(?i)select|union|insert|drop|delete|update|exec|cast|convert|char|declare"
xss_pattern       = r"(?i)<script|onerror|onload|javascript:|alert\("
cmd_pattern = r"(?i)(;|\||`)\s*(ls|cat|whoami|rm|ping|curl|wget|id|pwd)"
traversal         = r"\.\./|\.\.\\|%2e%2e"
whitelist_pattern = r"(?i)^/(index|home|login|logout|register|dashboard|profile|settings|products|cart|checkout|about|contact|search|robots|sitemap|favicon)\.(php|html|htm|txt|xml|ico)$"

attack_log = []

# إعدادات كشف DoS/DDoS
DOS_THRESHOLD  = 50   # طلبات من IP واحد → DoS
DDOS_THRESHOLD = 20   # IPs مختلفة في نفس الدقيقة → DDoS
FLOOD_RATIO    = 0.7  # 70%+ من الطلبات في burst → Flood


def extract_features(uri="", post_data="", get_query="", method="GET", content_length=0):
    uri       = str(uri or "")
    post_data = str(post_data or "")
    get_query = str(get_query or "")
    combined  = uri + " " + get_query + " " + post_data
    return pd.DataFrame([{
        "uri_length":      len(uri),
        "get_length":      len(get_query),
        "post_length":     len(post_data),
        "combined_length": len(combined),
        "has_sql":         int(bool(re.search(sql_pattern, combined))),
        "has_xss":         int(bool(re.search(xss_pattern, combined))),
        "has_traversal":   int(bool(re.search(traversal, combined))),
        "has_cmd":         int(bool(re.search(cmd_pattern, combined))),
        "special_chars":   sum(c in "'\";--/*`|&" for c in combined),
        "param_count":     combined.count("&") + 1,
        "is_post":         int(str(method).upper() == "POST"),
        "content_length":  float(content_length or 0),
        "percent_encoded": combined.count("%"),
        "has_null_byte":   int("%00" in combined or "\\x00" in combined),
        "uri_depth":       uri.count("/"),
    }])


def has_payload(uri, get_query, post_data):
    combined = uri + " " + get_query + " " + post_data
    return bool(
        re.search(sql_pattern, combined) or
        re.search(xss_pattern, combined) or
        re.search(traversal, combined)   or
        re.search(cmd_pattern, combined)
    )


def detect_attack_type(uri, get_query, post_data):
    combined = uri + " " + get_query + " " + post_data
    types = []
    if re.search(sql_pattern, combined):
        types.append("SQL Injection")
    if re.search(xss_pattern, combined):
        types.append("XSS")
    if re.search(traversal, combined):
        types.append("Path Traversal")
    if re.search(cmd_pattern, combined):
        types.append("Command Injection")
    if re.search(r"(?i)%00|\\x00", combined):
        types.append("Null Byte Injection")
    if re.search(r"(?i)\.(bak|env|git|htaccess|config|sql|log|old|backup|swp|tmp)($|\?)", uri):
        types.append("Sensitive File Access")
    if re.search(r"(?i)/(etc/passwd|etc/shadow|proc/self|wp-config|phpinfo)", uri):
        types.append("Sensitive File Access")
    return types if types else ["Unknown"]


def apply_whitelist(label, uri, get_query, post_data):
    if has_payload(uri, get_query, post_data):
        return "Anomalous"
    if re.search(whitelist_pattern, uri) and not has_payload(uri, get_query, post_data):
        return "Valid"
    return label


def analyze_dos_ddos(results):
    ip_counts      = Counter(r["ip"] for r in results)
    ip_per_minute  = defaultdict(lambda: defaultdict(int))
    minute_ips     = defaultdict(set)

    for r in results:
        minute = r["time"][:16] if r["time"] else "unknown"
        ip_per_minute[r["ip"]][minute] += 1
        minute_ips[minute].add(r["ip"])

    dos_ips   = {}
    ddos_mins = {}
    alerts    = []

    # كشف DoS — IP واحد يرسل أكثر من DOS_THRESHOLD طلب
    for ip, count in ip_counts.items():
        if count >= DOS_THRESHOLD:
            dos_ips[ip] = count
            alerts.append({
                "type":    "DoS",
                "ip":      ip,
                "count":   count,
                "message": f"🚨 DoS مشتبه به — {ip} أرسل {count} طلب"
            })

    # كشف DDoS — IPs كثيرة في نفس الدقيقة
    for minute, ips in minute_ips.items():
        if len(ips) >= DDOS_THRESHOLD:
            ddos_mins[minute] = len(ips)
            alerts.append({
                "type":    "DDoS",
                "minute":  minute,
                "ip_count": len(ips),
                "message": f"🚨 DDoS مشتبه به — {len(ips)} IP مختلف في {minute}"
            })

    # كشف HTTP Flood — نفس الـ URI يُطلب بكثرة
    uri_counts  = Counter(r["uri"] for r in results)
    total       = len(results)
    for uri, count in uri_counts.most_common(5):
        if count / total >= FLOOD_RATIO:
            alerts.append({
                "type":    "HTTP Flood",
                "uri":     uri,
                "count":   count,
                "ratio":   round(count / total * 100, 1),
                "message": f"🚨 HTTP Flood — {uri} طُلب {count} مرة ({round(count/total*100,1)}%)"
            })

    # إحصائيات عامة
    total_ips      = len(ip_counts)
    max_per_ip     = ip_counts.most_common(1)[0][1] if ip_counts else 0
    avg_per_ip     = round(total / total_ips, 1) if total_ips else 0
    ip_diversity   = round(total_ips / total * 100, 1) if total else 0

    attack_type = "Normal"
    if ddos_mins:
        attack_type = "DDoS"
    elif dos_ips:
        attack_type = "DoS"
    elif any(a["type"] == "HTTP Flood" for a in alerts):
        attack_type = "HTTP Flood"

    return {
        "attack_type":   attack_type,
        "alerts":        alerts,
        "dos_ips":       [{"ip": ip, "count": c} for ip, c in dos_ips.items()],
        "ddos_minutes":  [{"minute": m, "ip_count": c} for m, c in ddos_mins.items()],
        "stats": {
            "total_requests": total,
            "unique_ips":     total_ips,
            "max_per_ip":     max_per_ip,
            "avg_per_ip":     avg_per_ip,
            "ip_diversity":   ip_diversity,
        }
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data           = request.get_json()
    uri            = data.get("uri", "")
    post_data      = data.get("post_data", "")
    get_query      = data.get("get_query", "")
    method         = data.get("method", "GET")
    content_length = data.get("content_length", 0)
    ip             = request.remote_addr

    features     = extract_features(uri, post_data, get_query, method, content_length)
    prediction   = model.predict(features)[0]
    probability  = model.predict_proba(features)[0].tolist()
    label        = le.inverse_transform([prediction])[0]
    label        = apply_whitelist(label, uri, get_query, post_data)
    confidence   = probability[prediction]
    attack_types = detect_attack_type(uri, get_query, post_data) if label == "Anomalous" else []

    if label == "Anomalous":
        attack_log.append({
            "time":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip":           ip,
            "method":       method,
            "uri":          uri,
            "get_query":    get_query,
            "post_data":    post_data,
            "attack_types": attack_types,
            "confidence":   round(confidence * 100, 2),
        })

    return jsonify({
        "prediction":    label,
        "confidence":    round(confidence * 100, 2),
        "is_attack":     bool(label == "Anomalous"),
        "attack_types":  attack_types,
        "probabilities": {
            "Anomalous": round(probability[0] * 100, 2),
            "Valid":     round(probability[1] * 100, 2),
        }
    })


@app.route("/analyze/logfile", methods=["POST"])
def analyze_logfile():
    log_text = request.get_json().get("content", "")
    results  = []

    for line in log_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        line         = re.sub(r"^\[Line \d+\]\s*", "", line)
        ip_match     = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        uri_match    = re.search(r'"(GET|POST|PUT|DELETE)\s+(\S+)\s+HTTP', line)
        time_match   = re.search(r"\[([^\]]+)\]", line)
        status_match = re.search(r'HTTP/\S+"\s+(\d+)', line)

        if not uri_match:
            continue

        method = uri_match.group(1)
        full   = uri_match.group(2).split(" ")[0]
        ip     = ip_match.group(1)    if ip_match     else "unknown"
        time   = time_match.group(1)  if time_match   else ""
        status = status_match.group(1) if status_match else ""

        if "?" in full:
            uri, get_query = full.split("?", 1)
            get_query = get_query.rstrip('"')
        else:
            uri, get_query = full, ""

        features    = extract_features(uri=uri, get_query=get_query, method=method)
        prediction  = model.predict(features)[0]
        probability = model.predict_proba(features)[0].tolist()
        label       = le.inverse_transform([prediction])[0]
        label       = apply_whitelist(label, uri, get_query, "")
        attack_types = detect_attack_type(uri, get_query, "") if label == "Anomalous" else []

        results.append({
            "ip":           ip,
            "time":         time,
            "method":       method,
            "uri":          uri,
            "get_query":    get_query,
            "status":       status,
            "prediction":   label,
            "attack_types": attack_types,
            "confidence":   round(probability[prediction] * 100, 2),
            "is_attack":    bool(label == "Anomalous"),
        })

    attacks      = [r for r in results if r["is_attack"]]
    ip_counter   = Counter(r["ip"] for r in attacks)
    type_counter = Counter(t for r in attacks for t in r["attack_types"])
    dos_analysis = analyze_dos_ddos(results)

    return jsonify({
        "total_requests": len(results),
        "total_attacks":  len(attacks),
        "total_safe":     len(results) - len(attacks),
        "attack_rate":    round(len(attacks) / len(results) * 100, 1) if results else 0,
        "top_attackers":  ip_counter.most_common(10),
        "attack_types":   type_counter.most_common(),
        "details":        attacks[:50],
        "dos_analysis":   dos_analysis,
    })


@app.route("/report")
def report():
    ip_counter   = Counter(r["ip"] for r in attack_log)
    type_counter = Counter(t for r in attack_log for t in r["attack_types"])
    return jsonify({
        "total_attacks":  len(attack_log),
        "top_attackers":  ip_counter.most_common(10),
        "attack_types":   type_counter.most_common(),
        "recent_attacks": attack_log[-20:][::-1],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)