from dataclasses import dataclass

@dataclass
class SMTPConfig:
    server: str
    port: int
    username: str
    password: str
    sender: str
