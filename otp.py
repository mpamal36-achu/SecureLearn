
import secrets
import hashlib
import time
import sqlite3

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
        otp.encode("utf-8"),
        salt.encode("utf-8"),
        HASH_ITERATIONS
    ).hex()


# --------------------------------
# SAVE OTP TO SQLITE
# --------------------------------

def save_otp(email, otp):
    salt = secrets.token_hex(16)
    otp_hash = hash_otp(str(otp), salt)
    expiry_time = time.time() + OTP_EXPIRY

    connection = get_db_connection()

    try:
        connection.execute("""
            DELETE FROM otp_verifications
            WHERE expires_at <= ?
        """, (time.time(),))

        connection.execute("""
            INSERT INTO otp_verifications
            (email, otp_salt, otp_hash, expires_at, attempts, used)
            VALUES (?, ?, ?, ?, 0, 0)
            ON CONFLICT(email)
            DO UPDATE SET
                otp_salt = excluded.otp_salt,
                otp_hash = excluded.otp_hash,
                expires_at = excluded.expires_at,
                attempts = 0,
                used = 0
        """, (email, salt, otp_hash, expiry_time))

        connection.commit()
        return True

    except sqlite3.Error as error:
        connection.rollback()
        print("OTP database error:", error)
        return False

    finally:
        connection.close()


# --------------------------------
# VERIFY OTP
# --------------------------------

def verify_otp(email, entered_otp):
    connection = get_db_connection()

    try:
        connection.execute("BEGIN IMMEDIATE")

        record = connection.execute("""
            SELECT otp_salt, otp_hash, expires_at, attempts, used
            FROM otp_verifications
            WHERE email = ?
        """, (email,)).fetchone()

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
            connection.execute("""
                DELETE FROM otp_verifications
                WHERE email = ?
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
            connection.execute("""
                UPDATE otp_verifications
                SET attempts = attempts + 1
                WHERE email = ?
            """, (email,))

            connection.commit()
            return "Incorrect OTP"

        entered_hash = hash_otp(entered_otp, salt)

        if secrets.compare_digest(
            entered_hash,
            stored_hash
        ):
            connection.execute("""
                UPDATE otp_verifications
                SET used = 1
                WHERE email = ?
            """, (email,))

            connection.commit()
            return "OTP verified successfully!"

        connection.execute("""
            UPDATE otp_verifications
            SET attempts = attempts + 1
            WHERE email = ?
        """, (email,))

        connection.commit()
        return "Incorrect OTP"

    except sqlite3.Error as error:
        connection.rollback()
        print("OTP verification database error:", error)
        return "OTP verification temporarily unavailable"

    finally:
        connection.close()
