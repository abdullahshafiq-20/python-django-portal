import random
import string

PASSWORD_POLICY = {
    # Minimum number of characters in a password
    'MINIMUM_LENGTH': 12,

    # Minimum number of alphanumeric characters
    # i.e. "'-!"£#$%&()*,./:;?@[]^_`{|}~+<=>"
    'MIN_NO_OF_ALPHA_CHARS': 2,

    # Minimum number of uppercase characters
    'MIN_NO_OF_UPPERCASE_CHARS': 2,

    # Minimum number of lowercase characters
    'MIN_NO_OF_LOWERCASE_CHARS': 2,

    # Minimum number of numeric characters
    'MIN_NO_OF_NUMERIC_CHARS': 2,
}

def generate_password(policy=PASSWORD_POLICY):
    """
    Generate a password that meets the specified password policy requirements.
    
    :param policy: Dictionary containing password policy requirements
    :return: Generated password that satisfies the policy
    """
    # Define character sets
    uppercase_chars = string.ascii_uppercase
    lowercase_chars = string.ascii_lowercase
    numeric_chars = string.digits
    special_chars = "'-!\"£#$%&()*,./:;?@[]^_`{|}~+<=>"
    
    # Generate required characters
    password_chars = (
        random.choices(uppercase_chars, k=policy['MIN_NO_OF_UPPERCASE_CHARS']) +
        random.choices(lowercase_chars, k=policy['MIN_NO_OF_LOWERCASE_CHARS']) +
        random.choices(numeric_chars, k=policy['MIN_NO_OF_NUMERIC_CHARS'])
    )
    
    # Calculate remaining length
    remaining_length = policy['MINIMUM_LENGTH'] - len(password_chars)
    
    # Add additional characters to meet minimum length
    all_chars = uppercase_chars + lowercase_chars + numeric_chars + special_chars
    password_chars.extend(random.choices(all_chars, k=remaining_length))
    
    # Shuffle the password characters to randomize their positions
    random.shuffle(password_chars)
    
    # Convert list of characters to string
    return ''.join(password_chars)

# Example usage
if __name__ == '__main__':
    password = generate_password()
    print("Generated Password:", password)
    
    # Verify password meets requirements
    def validate_password(password):
        return (
            len(password) >= PASSWORD_POLICY['MINIMUM_LENGTH'] and
            sum(1 for c in password if c.isupper()) >= PASSWORD_POLICY['MIN_NO_OF_UPPERCASE_CHARS'] and
            sum(1 for c in password if c.islower()) >= PASSWORD_POLICY['MIN_NO_OF_LOWERCASE_CHARS'] and
            sum(1 for c in password if c.isdigit()) >= PASSWORD_POLICY['MIN_NO_OF_NUMERIC_CHARS']
        )
    
    print("Password Meets Requirements:", validate_password(password))