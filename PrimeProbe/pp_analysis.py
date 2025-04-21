import pandas as pd
data = pd.read_csv("prime_probe_results.csv")
print(f"Set0 max: {data['Set0'].max()} cycles")
print(f"Set16 hits: {len(data[data['Set16'] > 200])} samples")
print(f"Set32 max: {data['Set32'].max()} cycles")