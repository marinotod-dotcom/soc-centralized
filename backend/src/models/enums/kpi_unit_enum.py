from enum import Enum


class KPIUnit(str, Enum):
    PERCENT = "%"
    COUNT = "count"
    RATIO = "ratio"
    SECONDS = "seconds"
