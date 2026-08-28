import smtplib
from pathlib import Path
from email.message import EmailMessage

from src.models.smtp_config import SMTPConfig


class MailService:

    def __init__(self, config: SMTPConfig):
        self.config = config

    def send_email(
        self,
        recipients: list[str],
        subject: str,
        body: str,
        attachment: Path | None = None,
    ) -> None:

        msg = EmailMessage()

        msg["Subject"] = subject
        msg["From"] = self.config.sender
        msg["To"] = ", ".join(recipients)

        msg.set_content(body)

        if attachment:
            with open(attachment, "rb") as f:
                msg.add_attachment(
                    f.read(),
                    maintype="application",
                    subtype="pdf",
                    filename=attachment.name,
                )

        with smtplib.SMTP(self.config.server, self.config.port) as smtp:

            smtp.starttls()

            smtp.login(self.config.username, self.config.password)

            smtp.send_message(msg)
