import matplotlib.pyplot as plt
import pandas as pd

# Load CSV
data = pd.read_csv("prime_probe_results.csv")

# Plot access times for selected sets
sets_to_plot = ["Set0", "Set16", "Set32"]
plt.figure(figsize=(12, 6))
for set_name in sets_to_plot:
    plt.plot(data["Sample"], data[set_name], label=set_name, alpha=0.7)

plt.axhline(y=200, color='r', linestyle='--', label='Threshold (200 cycles)')
plt.xlabel("Sample")
plt.ylabel("Access Time (cycles)")
plt.title("Prime+Probe Cache Access Times")
plt.legend()
plt.grid(True)
plt.savefig("prime_probe_plot.png")
plt.show()