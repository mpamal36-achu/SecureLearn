
import os
import re
import requests

from dotenv import load_dotenv


# --------------------------------
# LOAD ENVIRONMENT VARIABLES
# --------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(dotenv_path=ENV_PATH)


# --------------------------------
# BREVO API SETTINGS
# --------------------------------

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


# --------------------------------
# VALIDATE EMAIL
# --------------------------------

def validate_email(email):

    if not isinstance(email, str):
        return False

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.fullmatch(pattern, email))


# --------------------------------
# SEND OTP USING BREVO HTTPS API
# --------------------------------

def send_otp_email(recipient_email, otp):

    if not validate_email(recipient_email):
        print("ERROR: Invalid recipient email.")
        return False

    otp = str(otp)

    if len(otp) != 6 or not otp.isdigit():
        print("ERROR: Invalid OTP format.")
        return False

    api_key = os.getenv("BREVO_API_KEY")
    sender_email = os.getenv("BREVO_SENDER_EMAIL")

    if not api_key or not sender_email:
        print("ERROR: Brevo email settings missing.")
        return False

    if not validate_email(sender_email):
        print("ERROR: Invalid Brevo sender email.")
        return False

    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    message = f"""Hello,

Your SecureLearn OTP verification code is: {otp}

This code expires in 5 minutes.

Please do not share this code with anyone.

Thank you,
SecureLearn Cybersecurity Learning Portal
"""

    payload = {
        "sender": {
            "name": "SecureLearn",
            "email": sender_email
        },
        "to": [
            {
                "email": recipient_email
            }
        ],
        "subject": "Your SecureLearn OTP Verification Code",
        "textContent": message
    }

    try:
        response = requests.post(
            BREVO_API_URL,
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.status_code == 201:
            print("SUCCESS: Brevo accepted OTP email.")
            return True

        print(
            "ERROR: Brevo API returned status",
            response.status_code
        )
        return False

    except requests.RequestException as error:
        print(
            "ERROR: Brevo connection failed:",
            type(error).__name__
        )
        return False
