from .media import MediaStatusListener

class MediaController:
    def register_status_listener(self, listener: MediaStatusListener) -> None: ...
