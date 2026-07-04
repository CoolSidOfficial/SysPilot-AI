from collectors import system
from collectors import memory
from collectors import cpu

report = {
    "system": system.collect(),
    "cpu": cpu.collect(),
    "memory": memory.collect()
}
