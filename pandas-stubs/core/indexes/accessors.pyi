from pandas import Series
from typing import Generic
from mte.typevar import K

class CombinedDatetimelikeProperties(Generic[K]):
    @property
    def day(self) -> Series[K, int]: ...
    @property
    def month(self) -> Series[K, int]: ...
    @property
    def year(self) -> Series[K, int]: ...
