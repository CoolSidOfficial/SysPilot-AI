import json
import os

from process_explorer.explorer import enumerate_processes

os.makedirs("output", exist_ok=True)

processes = enumerate_processes()

print(f"Found {len(processes)} processes")

with open("output/report.json", "w") as f:
    json.dump(
        [p.to_dict() for p in processes],
        f,
        indent=4,
    )