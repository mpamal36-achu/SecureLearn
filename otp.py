
import secrets
import hashlib
import time

import psycopg

from database import get_db_connection


# --------------------------------
# OTP SETTINGS
# --------------------------------

OTP_EXPIRY = 300
MAX_ATTEMPTS = 5
HASH_ITERATIONS = 200000


# --------------------------------
# GENERATE OTP
# --------------------------------

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


# --------------------------------
# HASH OTP
# --------------------------------

def hash_otp(otp, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        str(otp).encode("utf-8"),
        salt.encode("utf-8"),
        HASH_ITERATIONS
    ).hex()


# --------------------------------
# SAVE OTP TO POSTGRESQL
# --------------------------------

def save_otp(email, otp):
    salt = secrets.token_hex(16)
    otp_hash = hash_otp(otp, salt)
    expiry_time = time.time() + OTP_EXPIRY

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:

            cursor.execute("""
                DELETE FROM otp_verifications
                WHERE expires_at <= %s
            """, (time.time(),))

            cursor.execute("""
                INSERT INTO otp_verifications
                (
                    email,
                    otp_salt,
                    otp_hash,
                    expires_at,
                    attempts,
                    used
                )
                VALUES (%s, %s, %s, %s, 0, 0)
                ON CONFLICT (email)
                DO UPDATE SET
                    otp_salt = EXCLUDED.otp_salt,
                    otp_hash = EXCLUDED.otp_hash,
                    expires_at = EXCLUDED.expires_at,
                    attempts = 0,
                    used = 0
            """, (
                email,
                salt,
                otp_hash,
                expiry_time
            ))

        connection.commit()
        return True

    except psycopg.Error as error:
        if connection:
            connection.rollback()

        print("OTP database error:", type(error).__name__)
        return False

    finally:
        if connection:
            connection.close()


# --------------------------------
# VERIFY OTP
# --------------------------------

def verify_otp(email, entered_otp):
    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:

            # Lock the OTP row during verification
            cursor.execute("""
                SELECT
                    otp_salt,
                    otp_hash,
                    expires_at,
                    attempts,
                    used
                FROM otp_verifications
                WHERE email = %s
                FOR UPDATE
            """, (email,))

            record = cursor.fetchone()

            if record is None:
                connection.commit()
                return "OTP not found"

            salt = record["otp_salt"]
            stored_hash = record["otp_hash"]
            expiry = record["expires_at"]
            attempts = record["attempts"]
            used = record["used"]

            if used:
                connection.commit()
                return "OTP already used"

            if time.time() > expiry:
                cursor.execute("""
                    DELETE FROM otp_verifications
                    WHERE email = %s
                """, (email,))

                connection.commit()
                return "OTP expired"

            if attempts >= MAX_ATTEMPTS:
                connection.commit()
                return "Maximum attempts reached"

            if (
                not isinstance(entered_otp, str)
                or len(entered_otp) != 6
                or not entered_otp.isdigit()
            ):
                cursor.execute("""
                    UPDATE otp_verifications
                    SET attempts = attempts + 1
                    WHERE email = %s
                """, (email,))

                connection.commit()
                return "Incorrect OTP"

            entered_hash = hash_otp(
                entered_otp,
                salt
            )

            if secrets.compare_digest(
                entered_hash,
                stored_hash
            ):
                cursor.execute("""
                    UPDATE otp_verifications
                    SET used = 1
                    WHERE email = %s
                """, (email,))

                connection.commit()
                return "OTP verified successfully!"

            cursor.execute("""
                UPDATE otp_verifications
                SET attempts = attempts + 1
                WHERE email = %s
            """, (email,))

        connection.commit()
        return "Incorrect OTP"

    except psycopg.Error as error:
        if connection:
            connection.rollback()

        print(
            "OTP verification database error:",
            type(error).__name__
        )

        return "OTP verification temporarily unavailable"

    finally:
        if connection:
            connection.close()
