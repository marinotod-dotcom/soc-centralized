from enum import Enum


class KPICategory(Enum):
    LOGS = "logs"
    VULNERABILITIES = "vulnerabilities"
    CIS = "cis_benchmarks"
    FIM = "fim"
    MALWARE = "malware"
    COMPLIANCE = "compliance"
