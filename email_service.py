import os
import re
import ssl
import smtplib
import socket

from email.message import EmailMessage
from dotenv import load_dotenv


# --------------------------------
# LOAD ENVIRONMENT VARIABLES
# --------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(dotenv_path=ENV_PATH, override=True)


# --------------------------------
# EMAIL VALIDATION
# --------------------------------

def validate_email(email):

    if not isinstance(email, str):
        return False

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.fullmatch(pattern, email))


# --------------------------------
# CREATE EMAIL MESSAGE
# --------------------------------

def create_email_message(recipient_email, otp):

    message = EmailMessage()

    message["Subject"] = "Your SecureLearn OTP Verification Code"
    message["From"] = os.getenv("OTP_SENDER_EMAIL")
    message["To"] = recipient_email

    message.set_content(
        f"""Hello,

Your SecureLearn OTP verification code is: {otp}

This code expires in 5 minutes.

Please do not share this code with anyone.

Thank you,
SecureLearn Cybersecurity Learning Portal
"""
    )

    return message


# --------------------------------
# SEND USING PORT 587
# --------------------------------

def send_using_tls(sender_email, app_password, message):

    print("Trying Gmail SMTP Port 587...", flush=True)

    context = ssl.create_default_context()

    with smtplib.SMTP(
        "smtp.gmail.com",
        587,
        timeout=30
    ) as server:

        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

        print("Authenticating Gmail using TLS...", flush=True)

        server.login(sender_email, app_password)

        server.send_message(message)

    return True


# --------------------------------
# SEND USING PORT 465
# --------------------------------

def send_using_ssl(sender_email, app_password, message):

    print("Trying Gmail SMTP Port 465...", flush=True)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=30,
        context=context
    ) as server:

        print("Authenticating Gmail using SSL...", flush=True)

        server.login(sender_email, app_password)

        server.send_message(message)

    return True


# --------------------------------
# MAIN OTP EMAIL FUNCTION
# --------------------------------

def send_otp_email(recipient_email, otp):

    if not validate_email(recipient_email):

        print("ERROR: Invalid recipient email.")

        return False

    if (
        not isinstance(otp, str)
        or len(otp) != 6
        or not otp.isdigit()
    ):

        print("ERROR: Invalid OTP format.")

        return False

    sender_email = os.getenv("OTP_SENDER_EMAIL")
    app_password = os.getenv("OTP_EMAIL_APP_PASSWORD")

    if not sender_email or not app_password:

        print("ERROR: Gmail credentials missing in .env")

        return False

    if not validate_email(sender_email):

        print("ERROR: Invalid sender Gmail address.")

        return False

    app_password = app_password.replace(" ", "")

    message = create_email_message(
        recipient_email,
        otp
    )

    # --------------------------------
    # TRY PORT 587
    # --------------------------------

    try:

        send_using_tls(
            sender_email,
            app_password,
            message
        )

        print("SUCCESS: OTP sent using Port 587.")

        return True

    except (smtplib.SMTPException, OSError) as error:

        print("Port 587 failed.")
        print("Error:", type(error).__name__)

    # --------------------------------
    # TRY PORT 465
    # --------------------------------

    try:

        send_using_ssl(
            sender_email,
            app_password,
            message
        )

        print("SUCCESS: OTP sent using Port 465.")

        return True

    except (smtplib.SMTPException, OSError) as error:

        print("Port 465 failed.")
        print("Error:", type(error).__name__)

    except Exception as error:

        print("Unexpected Port 465 error:")
        print(type(error).__name__)

    print("ERROR: Unable to send OTP through Gmail SMTP.")

    return False