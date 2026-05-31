import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("=" * 55)
print("  Phishing URL Detector - Model Training")
print("=" * 55)

# Load real UCI phishing dataset
import pandas as pd

print("\n[1/4] Loading real UCI dataset...")
df = pd.read_csv("phishing.csv")
print(df.columns)

if 'Index' in df.columns:
    df = df.drop('Index', axis=1)

X = df.drop('class', axis=1).values[:, :15]
y = df['class'].values

print(f" Dataset size: {len(X)} samples")

# Split data
print("\n[2/4] Splitting into train/test sets (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    Train: {len(X_train)} | Test: {len(X_test)}")

# Train model
print("\n[3/4] Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)
print("    Training complete!")


# Evaluate and save
print("\n[4/4] Evaluating model...")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n    Accuracy: {acc * 100:.2f}%")
print("\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Phishing", "Legitimate"]))

# Save model
with open("model/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("=" * 55)
print(f"  Accuracy: {acc * 100:.1f}%")
print("=" * 55)
