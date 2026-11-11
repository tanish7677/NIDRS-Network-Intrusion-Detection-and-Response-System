import pandas as pd
df = pd.read_csv("KDDTrain+.txt", header=None)
print(df.shape)
print(df.head())
print(df.info())
print(df[41].value_counts())
print(df.isnull().sum())
print(df.duplicated().sum())
print(df[1].unique())  # protocol_type
print(df[2].nunique()) # number of services
print(df[3].unique())  # flag