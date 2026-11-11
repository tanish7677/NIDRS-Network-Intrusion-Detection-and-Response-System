import pandas as pd
from sklearn.preprocessing import LabelEncoder
df = pd.read_csv("KDDTrain+.txt", header=None)
df[41] = df[41].apply(
    lambda x: "normal" if x == "normal" else "attack"
)
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()
label_encoder = LabelEncoder()
df[1] = protocol_encoder.fit_transform(df[1])
df[2] = service_encoder.fit_transform(df[2])
df[3] = flag_encoder.fit_transform(df[3])
df[41] = label_encoder.fit_transform(df[41])
print(df.head())
print(df[1].unique())
print(df[41].unique())