from abc import ABC, abstractmethod

class MediaStatusListener(ABC):
    def load_media_failed(self, item: int, error_code: int) -> None: ...
    @abstractmethod
    def new_media_status(self, status: MediaStatus) -> None: ...

class MediaStatus:
    title: str
