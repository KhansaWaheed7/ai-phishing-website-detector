import pickle
import os
from flask import Flask, render_template, request, jsonify
from features import extract_features, FEATURE_NAMES

app = Flask(__name__)

# Load the trained model
MODEL_PATH = "model/phishing_model.pkl"

if not os.path.exists(MODEL_PATH):
    print("\n[ERROR] Model not found!")
    print("  Please run first: python train_model.py\n")
    exit(1)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("[OK] Model loaded successfully.")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"error": "Invalid request"}), 400
            
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Extract features
        feature_values = extract_features(url)

        # Predict
        prediction = model.predict([feature_values])[0]
        probabilities = model.predict_proba([feature_values])[0]

        is_phishing = bool(prediction == -1)

        if is_phishing:
            confidence = probabilities[0] * 100
        else:
            confidence = probabilities[1] * 100

        feature_breakdown = []
        for name, val in zip(FEATURE_NAMES, feature_values):
            feature_breakdown.append({
                "name": name,
                "value": val,
                "status": "safe" if val == 1 else ("warning" if val == 0 else "danger")
            })

        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "label": "PHISHING" if is_phishing else "LEGITIMATE",
            "confidence": round(confidence, 1),
            "features": feature_breakdown,
            "risk_score": round((1 - probabilities[1]) * 100, 1)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  Phishing URL Detector Running")
    print("  Open browser: http://127.0.0.1:5000")
    print("=" * 50 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
