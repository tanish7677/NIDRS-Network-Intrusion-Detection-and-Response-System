import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("live_flows.csv")

print("\n==============================")
print("NIDRS LIVE MODEL TRAINING")
print("==============================")

print("Total Live Flows:", len(df))

features = [
    "packet_count",
    "total_bytes",
    "duration",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size"
]

X = df[features].copy()

print("Input Features:", X.shape[1])

print("\nFeature Summary:")
print(X.describe())

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

print("\nTraining Isolation Forest...")

model.fit(X_scaled)

print("Training Complete")

predictions = model.predict(X_scaled)

df["anomaly_prediction"] = predictions

df["status"] = df["anomaly_prediction"].map({
    1: "Normal",
    -1: "Anomalous"
})

print("\nDetection Result:")
print(df["status"].value_counts())

anomalies = df[
    df["status"] == "Anomalous"
]

print("\nDetected Anomalous Flows:")

print(
    anomalies[
        [
            "src_ip",
            "dst_ip",
            "protocol",
            "packet_count",
            "total_bytes",
            "duration",
            "packets_per_second",
            "bytes_per_second",
            "average_packet_size"
        ]
    ]
)

joblib.dump(
    model,
    "live_anomaly_model.pkl"
)

joblib.dump(
    scaler,
    "live_scaler.pkl"
)

joblib.dump(
    features,
    "live_features.pkl"
)

df.to_csv(
    "live_flows_with_predictions.csv",
    index=False
)

print("\nModel Saved Successfully")

print("live_anomaly_model.pkl")
print("live_scaler.pkl")
print("live_features.pkl")
print("live_flows_with_predictions.csv")

print("==============================")