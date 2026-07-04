import json

from collectors import system
from collectors import cpu
from collectors import memory


report = {
    "system": system.collect(),
    "cpu": cpu.collect(),
    "memory": memory.collect(),
}


with open("report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print(" report.json created")