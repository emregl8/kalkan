from abc import ABC, abstractmethod
from core.models import ScanResult, ApplyResult


class SecurityModule(ABC):
    display_name: str = ""
    description: str = ""
    icon_name: str = ""

    @abstractmethod
    def scan(self) -> ScanResult:
        ...

    @abstractmethod
    def apply(self) -> ApplyResult:
        ...

    @abstractmethod
    def verify(self) -> ScanResult:
        ...

    def detail_info(self) -> str | None:
        return None

    def sub_items_label(self) -> str:
        return ""

    def sub_items_flow(self) -> bool:
        return False

    def custom_profiles(self) -> list[str]:
        return []

    def profile_enforced(self, name: str) -> bool:
        return False

    def set_profile_selected(self, name: str, selected: bool) -> None:
        pass
