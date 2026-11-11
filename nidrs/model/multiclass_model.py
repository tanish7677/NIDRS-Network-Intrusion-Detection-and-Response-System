import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib


# ==========================================
# LOAD NSL-KDD DATASET
# ==========================================

df = pd.read_csv(
    "KDDTrain+.txt",
    header=None
)

print("\nDataset Shape:", df.shape)


# ==========================================
# ATTACK CATEGORY FUNCTION
# ==========================================

def attack_category(label):

    if label == "normal":
        return "Normal"

    dos = [
        "neptune",
        "smurf",
        "back",
        "teardrop",
        "pod",
        "land",
        "apache2",
        "processtable",
        "mailbomb",
        "udpstorm"
    ]

    probe = [
        "satan",
        "ipsweep",
        "portsweep",
        "nmap",
        "mscan",
        "saint"
    ]

    r2l = [
        "guess_passwd",
        "warezclient",
        "warezmaster",
        "ftp_write",
        "multihop",
        "imap",
        "phf",
        "spy",
        "sendmail",
        "named",
        "snmpgetattack",
        "snmpguess",
        "xlock",
        "xsnoop",
        "worm"
    ]

    u2r = [
        "buffer_overflow",
        "rootkit",
        "perl",
        "loadmodule",
        "httptunnel",
        "ps",
        "sqlattack",
        "xterm"
    ]

    if label in dos:
        return "DoS"

    elif label in probe:
        return "Probe"

    elif label in r2l:
        return "R2L"

    elif label in u2r:
        return "U2R"

    return "Unknown"


# ==========================================
# CONVERT ATTACK LABELS
# ==========================================

df[41] = df[41].apply(
    attack_category
)


print("\nAttack Distribution:")

print(
    df[41].value_counts()
)


# ==========================================
# REMOVE UNKNOWN ATTACKS
# ==========================================

df = df[
    df[41] != "Unknown"
].copy()


# ==========================================
# ENCODE CATEGORICAL FEATURES
# ==========================================

protocol_encoder = LabelEncoder()

service_encoder = LabelEncoder()

flag_encoder = LabelEncoder()


df[1] = protocol_encoder.fit_transform(
    df[1]
)

df[2] = service_encoder.fit_transform(
    df[2]
)

df[3] = flag_encoder.fit_transform(
    df[3]
)


# ==========================================
# ENCODE ATTACK LABEL
# ==========================================

label_encoder = LabelEncoder()


df[41] = label_encoder.fit_transform(
    df[41]
)


print(
    "\nModel Classes:",
    label_encoder.classes_
)


# ==========================================
# CREATE X AND Y
# ==========================================

X = df.drop(
    columns=[41, 42]
)

y = df[41]


print(
    "\nInput Feature Count:",
    X.shape[1]
)


# ==========================================
# TRAIN TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


print(
    "Training Shape:",
    X_train.shape
)

print(
    "Testing Shape:",
    X_test.shape
)


# ==========================================
# CLASS IMBALANCE - SMOTE
# ==========================================
# NSL-KDD is heavily imbalanced: U2R/R2L have only a few hundred rows
# (U2R: 52 in total) vs tens of thousands of Normal/DoS rows, so a plain
# RandomForest under-predicts the rare classes.
#
# FIX: SMOTE (Synthetic Minority Over-sampling Technique) is now ALWAYS
# applied to the TRAINING split. It uses imbalanced-learn when installed
# and a built-in SMOTE implementation (smote_utils.py) otherwise, so the
# shipped model can no longer silently fall back to class weights.
# X_test / y_test are never resampled, so evaluation stays honest.

from smote_utils import apply_smote

print("\nClass distribution BEFORE SMOTE:")
print(y_train.value_counts())

X_train, y_train, smote_backend = apply_smote(
    X_train,
    y_train,
    k_neighbors=3,
    random_state=42
)

print(f"\nSMOTE applied using: {smote_backend}")
print("Class distribution AFTER SMOTE:")
print(y_train.value_counts())


# ==========================================
# RANDOM FOREST MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


print(
    "\nTraining Random Forest Model..."
)


model.fit(
    X_train,
    y_train
)


print(
    "Training Complete"
)


# ==========================================
# MODEL PREDICTION
# ==========================================

y_pred = model.predict(
    X_test
)


# ==========================================
# MODEL EVALUATION
# ==========================================

accuracy = accuracy_score(
    y_test,
    y_pred
)


print(
    "\nAccuracy:",
    accuracy
)


print(
    "\nClassification Report:"
)


print(
    classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    )
)


# ==========================================
# SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "multiclass_model.pkl"
)


joblib.dump(
    label_encoder,
    "multiclass_label_encoder.pkl"
)


joblib.dump(
    protocol_encoder,
    "protocol_encoder.pkl"
)


joblib.dump(
    service_encoder,
    "service_encoder.pkl"
)


joblib.dump(
    flag_encoder,
    "flag_encoder.pkl"
)


print(
    "\nModel Saved Successfully"
)


print(
    "multiclass_model.pkl"
)

print(
    "multiclass_label_encoder.pkl"
)

print(
    "protocol_encoder.pkl"
)

print(
    "service_encoder.pkl"
)

print(
    "flag_encoder.pkl"
)