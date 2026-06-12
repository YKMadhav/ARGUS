import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib, os

FEATURES = ['duration', 'src_bytes', 'dst_bytes', 'count']

# ── Load NSL-KDD (train) ─────────────────────────────────────
print("📦 Loading NSL-KDD train...")
train_df = pd.read_csv('./data/nsl_kdd_dataset.csv')
train_df = train_df[FEATURES]

# ── Load KDDTest (test) ──────────────────────────────────────
print("📦 Loading KDDTest...")
test_df = pd.read_csv('./data/KDDTest.csv')
y_test  = test_df['attack_class'].apply(
    lambda x: 0 if str(x).strip().lower() == 'normal' else 1
).values
test_df = test_df[FEATURES]

# ── Load CICIDS2017 (extra training data) ────────────────────
print("📦 Loading CICIDS2017...")
cic_df = pd.read_csv('./data/cicids2017_cleaned.csv')
cic_df = cic_df.rename(columns={
    'Flow Duration'              : 'duration',
    'Total Length of Fwd Packets': 'src_bytes',
    'Subflow Fwd Bytes'          : 'dst_bytes',
    'Total Fwd Packets'          : 'count'
})[FEATURES]

# ── Merge train sets ─────────────────────────────────────────
X_train = pd.concat([train_df, cic_df], ignore_index=True)
X_train = X_train.fillna(0)
X_test  = test_df.fillna(0)

print(f"✅ Train size: {X_train.shape} | Test size: {X_test.shape}")

# ── Scale ────────────────────────────────────────────────────
print("\n⚖️  Scaling...")
scaler         = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ── Train ────────────────────────────────────────────────────
print("\n🧠 Training Isolation Forest...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_scaled)
print("✅ Model trained")

# ── Evaluate ─────────────────────────────────────────────────
print("\n📈 Evaluating...")
y_pred = (model.predict(X_test_scaled) == -1).astype(int)
print(classification_report(y_test, y_pred,
      target_names=['Normal', 'Attack']))

# ── Save ─────────────────────────────────────────────────────
os.makedirs('./models', exist_ok=True)
joblib.dump(model,    './models/isolation_forest.pkl')
joblib.dump(scaler,   './models/scaler.pkl')
joblib.dump(FEATURES, './models/features.pkl')
print("✅ All models saved → ./models/")
print("\n🎉 Done! Run sudo python live_detect.py next.")
