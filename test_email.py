import os
import smtplib
import ssl
from dotenv import load_dotenv

load_dotenv(override=True)

email = os.getenv("OTP_SENDER_EMAIL")
password = os.getenv("OTP_EMAIL_APP_PASSWORD", "").replace(" ", "")

print("Email configured:", bool(email))
print("Password configured:", bool(password))

try:
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=30,
        context=context
    ) as server:

        server.set_debuglevel(1)

        print("Connecting successful")
        server.login(email, password)

        print("GMAIL AUTHENTICATION SUCCESSFUL")

except Exception as e:
    print("ERROR:", type(e).__name__)
    print("DETAILS:", str(e))