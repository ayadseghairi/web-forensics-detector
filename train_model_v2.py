import pandas as pd
import numpy as np
import re
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.utils.class_weight import compute_sample_weight

sql_pattern = r"(?i)select|union|insert|drop|delete|update|exec|cast|convert|char|declare"
xss_pattern = r"(?i)<script|onerror|onload|javascript:|alert\("
cmd_pattern = r"(?i)(;|\||&|`)\s*(ls|cat|whoami|rm|ping|curl|wget|id|pwd)"
traversal   = r"\.\./|\.\.\\|%2e%2e"

def extract_features(uri, get_q, post_d, method, content_length=0):
    uri    = str(uri or "")
    get_q  = str(get_q or "")
    post_d = str(post_d or "")
    combined = uri + " " + get_q + " " + post_d
    return {
        "uri_length":      len(uri),
        "get_length":      len(get_q),
        "post_length":     len(post_d),
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
    }

# تحميل CSIC
print("تحميل CSIC...")
df1 = pd.read_csv("data/Web-Application-Attack-Datasets-master/CSVData/csic_final.csv")
df1["Content-Length"] = df1["Content-Length"].fillna(0)
df1["POST-Data"]      = df1["POST-Data"].fillna("")
df1["GET-Query"]      = df1["GET-Query"].fillna("")

rows1 = []
for _, r in df1.iterrows():
    f = extract_features(r["URI"], r["GET-Query"], r["POST-Data"], r["Method"], r["Content-Length"])
    f["label"] = r["Class"]
    rows1.append(f)
df_csic = pd.DataFrame(rows1)
print(f"CSIC: {df_csic.shape} | {df_csic['label'].value_counts().to_dict()}")

# تحميل Synthetic
print("تحميل Synthetic...")
df2 = pd.read_csv("data/synthetic_attacks.csv")
rows2 = []
for _, r in df2.iterrows():
    f = extract_features(r["uri"], r["get_query"], r["post_data"], r["method"])
    f["label"] = r["label"]
    rows2.append(f)
df_syn = pd.DataFrame(rows2)
print(f"Synthetic: {df_syn.shape} | {df_syn['label'].value_counts().to_dict()}")

# دمج بدون drop_duplicates
df = pd.concat([df_csic, df_syn], ignore_index=True)
print(f"بعد الدمج: {df.shape}")
print(f"التوزيع النهائي:\n{df['label'].value_counts()}")

le = LabelEncoder()
y  = le.fit_transform(df["label"])
X  = df.drop("label", axis=1)

print(f"\nClasses: {le.classes_}")
print(f"حجم X: {X.shape}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

scale = (y_train == 0).sum() / (y_train == 1).sum()
print(f"scale_pos_weight: {scale:.2f}")

model = XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train, y_train,
    sample_weight=compute_sample_weight("balanced", y_train),
    eval_set=[(X_test, y_test)],
    verbose=50
)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\n=== النتائج ===")
print(classification_report(y_test, y_pred, target_names=le.classes_))
print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring="f1", n_jobs=-1)
print(f"Cross-Validation F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.title("Confusion Matrix - XGBoost V2")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("confusion_matrix.png")

fpr, tpr, _ = roc_curve(y_test, y_prob)
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, color="darkorange", lw=2,
         label=f"AUC = {roc_auc_score(y_test, y_prob):.4f}")
plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - XGBoost V2")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig("roc_curve.png")

importance = pd.Series(model.feature_importances_, index=X.columns)
plt.figure(figsize=(10, 6))
importance.nlargest(10).sort_values().plot(kind="barh", color="steelblue")
plt.title("Top 10 Feature Importance")
plt.tight_layout()
plt.savefig("feature_importance.png")

joblib.dump(model, "web_forensics_model.pkl")
joblib.dump(le, "label_encoder.pkl")
print("\nتم حفظ النموذج: web_forensics_model.pkl")
