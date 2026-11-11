import joblib
import pandas as pd
import sqlite3
from datetime import datetime

# FIX: same issue as predict.py — replaced the hardcoded 42-value array
# (which only matched the old, leaky 42-feature model) with a real row
# from the dataset, encoded using the saved encoders.

model = joblib.load("random_forest_model.pkl")

protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

df = pd.read_csv("KDDTest+.txt", header=None)

sample = df.iloc[[0]].copy()

sample[1] = protocol_encoder.transform(sample[1])
sample[2] = service_encoder.transform(sample[2])
sample[3] = flag_encoder.transform(sample[3])

X_sample = sample.drop(columns=[41, 42])

prediction = model.predict(X_sample)

# model.classes_ == ['attack', 'normal'] (alphabetical), so class 0 = attack
if prediction[0] == 0:

    conn = sqlite3.connect("../database/alerts.db")

    cursor = conn.cursor()

    detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        INSERT INTO alerts(
        attack_type,
        severity,
        detected_at,
        status
        )
        VALUES(
        'Unknown Attack', 'High', ?, 'New'
        )
        """,
        (detected_at,)
    )

    conn.commit()

    conn.close()

    print("Attack Alert Generated")

else:

    print("Normal Traffic")
