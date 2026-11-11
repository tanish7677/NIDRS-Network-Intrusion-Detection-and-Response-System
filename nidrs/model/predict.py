import joblib
import pandas as pd

# FIX: the old hardcoded 42-value sample_packet matched the OLD leaky
# 42-feature model by coincidence, but had no real meaning (it wasn't a
# real network flow, and one extra value was silently standing in for
# the "difficulty" column). Now that random_forest_model.pkl is
# retrained on the correct 41 features, we instead take a REAL row from
# the test dataset and encode it with the same saved encoders used at
# training time — this is what a real inference call should look like.

model = joblib.load("random_forest_model.pkl")
print("Model Loaded Successfully")

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
print(prediction)

# model.classes_ == ['attack', 'normal'] (alphabetical), so class 0 = attack
if prediction[0] == 0:
    print("Attack Detected")
else:
    print("Normal Traffic")
