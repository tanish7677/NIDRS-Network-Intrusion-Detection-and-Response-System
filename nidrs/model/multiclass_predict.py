import joblib

model=joblib.load("multiclass_model.pkl")
encoder=joblib.load("multiclass_label_encoder.pkl")

print(encoder.classes_)