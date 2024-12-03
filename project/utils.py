from .config import PASSWORD_POLICY, PASSWORD_BLACKLIST
from flask import Request
import requests
from . import env

def is_bot(request):
    """
    Verify if the request is from a bot using reCAPTCHA
    """
    recaptcha_response = request.form.get('g-recaptcha-response')
    
    if not recaptcha_response:
        return True  # No CAPTCHA response means it's a bot/unverified
        
    verify_response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': env['RECAPTCHA_PRIVATE_KEY'],
            'response': recaptcha_response
        }
    )
    
    if verify_response.status_code != 200:
        return True
        
    result = verify_response.json()
    return not result['success']  # Return True if verification failed

def password_meets_security_requirements(password):
    """
    Check if password meets security requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False
    return True

def file_signature_valid(extension: str, file: bytes) -> bool:
    """
    Check a file is what it says it is. 
    
    Compares the `.extension` parameter against that file types' known file 
    header.

    List of valid extensions: 
    png, 
    apng*
    avif, 
    gif, 
    webp,
    jpg,
    jpeg,
    jfif*
    pjpeg*
    pjp*

    Extensions with an asterisk are not supported, but will match the pattern in the 
    event of extension spoofing 
    """
    if extension == "png" or extension == "apng":
        return file[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    elif extension == "avif":
        return file[:18] == bytes(
            [
                0x00,
                0x00,
                0x00,
                0x20,
                0x66,
                0x74,
                0x79,
                0x70,
                0x61,
                0x76,
                0x69,
                0x66,
                0x31,
                0x61,
                0x76,
                0x69,
                0x66,
                0x31,
            ]
        )
    elif extension == "gif":
        return file[:6] == bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]) or file[
            :6
        ] == bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61])
    elif extension == "webp":
        return file[:4] == bytes([0x52, 0x49, 0x46, 0x46]) and file[8:12] == bytes(
            [0x57, 0x45, 0x42, 0x50]
        )
    elif extension in ["jpg", "jpeg", "jfif", "pjpeg", "pjp"]:
        return (
            file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xDB])
            or file[:12]
            == bytes(
                [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]
            )
            or file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xEE])
            or (
                file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xE1])
                and file[6:12] == bytes([0x45, 0x78, 0x69, 0x66, 0x00, 0x00])
            )
        )
    elif extension == "webp":
        return (
            file[:4] == bytes([0x52, 0x49, 0x46, 0x46]) and 
            file[8:12] == bytes([0x57, 0x45, 0x42, 0x50]) 
        )

    return True
