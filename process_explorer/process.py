from dataclasses import dataclass, asdict

@dataclass
class Process:
    pid: int
    parent_pid: int
    name: str
    path: str | None = None

    def to_dict(self):
        return asdict(self)