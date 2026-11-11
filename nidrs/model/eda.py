import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_csv("KDDTrain+.txt", header=None)
df[41] = df[41].apply(
    lambda x: "normal" if x == "normal" else "attack"
)
print(df[41].value_counts())
df[41].value_counts().plot(kind="bar")
plt.title("Normal vs Attack Distribution")
plt.xlabel("Class")
plt.ylabel("Count")
plt.show()
