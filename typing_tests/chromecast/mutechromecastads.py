from pychromecast import Chromecast
from pychromecast.controllers.media import MediaStatusListener, MediaStatus
from os import environ


class Listener(MediaStatusListener):
    def __init__(self, chromecast: Chromecast):
        self.chromecast: Chromecast = chromecast
        self.muted: bool = False

    def new_media_status(self, status: MediaStatus) -> None:
        print(status.title, flush=True)
        ad = status.title == "Advertisement"
        if ad and not self.muted:
            self.chromecast.set_volume_muted(True)
            self.muted = True
        elif not ad and self.muted:
            self.muted = False
            self.chromecast.set_volume_muted(False)


def main():
    chromecast = Chromecast(environ["IP"])

    chromecast.start()
    chromecast.wait()

    chromecast.media_controller.register_status_listener(Listener(chromecast))
    chromecast.join()


if __name__ == "__main__":
    main()
