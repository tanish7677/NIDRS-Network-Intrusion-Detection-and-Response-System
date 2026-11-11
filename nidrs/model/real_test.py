import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

model = joblib.load("random_forest_model.pkl")

df = pd.read_csv("KDDTest+.txt", header=None)

df[41] = df[41].apply(lambda x: "normal" if x == "normal" else "attack")

# FIX: reuse the SAVED encoders instead of fitting new ones on the test
# file. Measured impact for this model was small (~0.3% accuracy) but
# it is not guaranteed to always be small, and it's the correct approach
# for consistent, reproducible results.
protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

df[1] = protocol_encoder.transform(df[1])
df[2] = service_encoder.transform(df[2])
df[3] = flag_encoder.transform(df[3])

label_encoder = LabelEncoder()
df[41] = label_encoder.fit_transform(df[41])

# FIX: drop BOTH label (41) and difficulty (42) — matches the retrained
# 41-feature model. Previously this only dropped 41, leaving 42 features,
# which happened to "work" only because the old model was also
# (incorrectly) trained on 42 features.
X = df.drop(columns=[41, 42])
y = df[41]

y_pred = model.predict(X)

accuracy = accuracy_score(y, y_pred)

print("Test Accuracy:", accuracy)

attack_count = (y_pred == 0).sum()
normal_count = (y_pred == 1).sum()

print("Attack Predictions:", attack_count)
print("Normal Predictions:", normal_count)
