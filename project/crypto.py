from cryptography.fernet import Fernet
from . import env
import base64

key = env['IMAGE_KEY'].strip("'")
cipher = Fernet(key.encode())