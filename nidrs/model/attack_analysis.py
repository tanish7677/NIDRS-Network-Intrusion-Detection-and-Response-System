import pandas as pd

df=pd.read_csv("KDDTrain+.txt",header=None)

print(df[41].value_counts())