from cryptography.fernet import Fernet
from . import env
import base64

# Remove quotes from the key if present
key = env['IMAGE_KEY'].strip("'")
cipher = Fernet(key.encode())