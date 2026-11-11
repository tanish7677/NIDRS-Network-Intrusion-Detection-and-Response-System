import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

df = pd.read_csv("KDDTrain+.txt", header=None)

df[41] = df[41].apply(lambda x: "normal" if x == "normal" else "attack")

# FIX: reuse the SAME protocol/service/flag encoders as the multiclass
# pipeline (multiclass_model.py) instead of fitting fresh ones here.
# These columns (protocol_type/service/flag) are the exact same raw
# features regardless of whether the target is binary or multiclass, so
# sharing one encoder set keeps every script in the project consistent
# and means any future inference script can reuse them safely.
protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

df[1] = protocol_encoder.transform(df[1])
df[2] = service_encoder.transform(df[2])
df[3] = flag_encoder.transform(df[3])

label_encoder = LabelEncoder()
df[41] = label_encoder.fit_transform(df[41])

# FIX: previously only dropped column 41 (label), leaving column 42
# ("difficulty") in X. Difficulty is NSL-KDD metadata describing how
# hard a record was for earlier models to classify — it's not a real
# network feature, and training on it is data leakage that artificially
# inflates apparent accuracy. Dropping both 41 and 42 now matches
# multiclass_model.py's (correct) approach.
X = df.drop(columns=[41, 42])
y = df[41]

print("X Shape:", X.shape)
print("Y Shape:", y.shape)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Data:", X_train.shape)
print("Testing Data:", X_test.shape)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Model Training Completed")

y_pred = model.predict(X_test)

print("First 20 Predictions:")
print(y_pred[:20])

print("Label Classes (0=attack, 1=normal):")
print(label_encoder.classes_)

joblib.dump(model, "random_forest_model.pkl")

print("Model Saved Successfully")

accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(cm)

print("Classification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_
    )
)
