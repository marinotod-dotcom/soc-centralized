from enum import Enum


class KPIPattern(Enum):
    CRITICAL_PATTERNS_LINUX = [
        "*/etc/passwd",
        "*/etc/shadow",
        "*/etc/sudoers*",
        "*/etc/ssh/sshd_config",
        "*authorized_keys*",
        "*/bin/*",
        "*/sbin/*",
        "*/usr/bin/*",
        "*/usr/sbin/*",
        "*/etc/pam.d*",
        "*/etc/ld.so*",
    ]
    CRITICAL_PATTERNS_WINDOWS = [
        "*Security\\\\SAM*",
        "*System32\\\\config*",
        "*SYSVOL*",
        "*Winlogon*",
        "*NETLOGON*",
        "*Security\\\\Cache*",
        "*Security\\\\Policy*",
        "*\\\\Run*",
        "*\\\\RunOnce*",
    ]
    HIGH_PATTERNS = [
        "*/etc/crontab*",
        "*/etc/cron.*",
        "*/var/spool/cron*",
        "*/etc/systemd/system*",
        "*/etc/init.d*",
        "*/lib/*",
        "*/lib64/*",
        "*SECURITY\\\\*",
        "*System32\\\\drivers*",
        "*\\\\Startup\\\\*",
    ]
    AUTH_WIN_PATTERN = "SAM|SECURITY\\\\|Winlogon|\\\\Run\\\\|\\\\RunOnce"
    AUTH_LINUX_PATTERN = (
        "/etc/passwd|/etc/shadow|/etc/sudoers|authorized_keys|/etc/pam\\.d"
    )
