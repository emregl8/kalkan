from dataclasses import dataclass
from enum import Enum, auto


class ModuleStatus(Enum):
    APPLIED = auto()
    PARTIAL = auto()
    NOT_APPLIED = auto()
    ERROR = auto()


@dataclass
class ScanResult:
    status: ModuleStatus
    detail: str

    @property
    def badge_class(self) -> str:
        return {
            ModuleStatus.APPLIED: "badge-active",
            ModuleStatus.PARTIAL: "badge-partial",
            ModuleStatus.NOT_APPLIED: "badge-missing",
            ModuleStatus.ERROR: "badge-missing",
        }[self.status]

    @property
    def label(self) -> str:
        return {
            ModuleStatus.APPLIED: "Active",
            ModuleStatus.PARTIAL: "Partial",
            ModuleStatus.NOT_APPLIED: "Not Applied",
            ModuleStatus.ERROR: "Error",
        }[self.status]


@dataclass
class ApplyResult:
    success: bool
    detail: str
