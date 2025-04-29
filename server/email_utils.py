import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL")

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def load_template(filename: str, link: str) -> str:
    """Load and format HTML email template with the provided link."""
    path = os.path.join(TEMPLATE_DIR, filename)
    with open(path, "r", encoding="utf-8") as file:
        return file.read().replace("{{LINK}}", link)


def send_email(to_email: str, subject: str, html_body: str):
    """Send an email with HTML content."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content("Please view this message in an HTML-compatible email client.")
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)
        raise


def send_verification_email(to_email: str, token: str):
    verify_link = f"{FRONTEND_URL}/verify-email?token={token}"
    html_content = load_template("verify_email.html", verify_link)
    send_email(to_email, "Verify Your Account", html_content)


def send_reset_password_email(to_email: str, token: str):
    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"
    html_content = load_template("reset_password.html", reset_link)
    send_email(to_email, "Reset Your Password", html_content)
