import joblib


model = joblib.load(
    "multiclass_model.pkl"
)


print("\n==============================")
print("NIDRS MODEL INFORMATION")
print("==============================")

print(
    "Model Type:",
    type(model).__name__
)

print(
    "Expected Input Features:",
    model.n_features_in_
)

print(
    "Number of Classes:",
    model.n_classes_
)

print(
    "Model Classes:",
    model.classes_
)

print(
    "Number of Trees:",
    len(model.estimators_)
)

print("==============================")