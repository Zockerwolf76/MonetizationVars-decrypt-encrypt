import base64
import json
import os

DEFAULT_CIPHER_KEY = "com.wtfapps.apollo16"

# Dictionary for the obfuscated cipher key mapping
obf_char_map = {
    0x62: 0x6d, 0x63: 0x79, 0x64: 0x6c,
    0x65: 0x78, 0x66: 0x6b, 0x67: 0x77,
    0x68: 0x6a, 0x69: 0x76, 0x6a: 0x69,
    0x6b: 0x75, 0x6c: 0x68, 0x6d: 0x74,
    0x6e: 0x67, 0x6f: 0x73, 0x70: 0x66,
    0x71: 0x72, 0x72: 0x65, 0x73: 0x71,
    0x74: 0x64, 0x75: 0x70, 0x76: 0x63,
    0x77: 0x6f, 0x78: 0x62, 0x79: 0x6e,
    0x7a: 0x61, 0x61: 0x7a
}

# Known base64 strings for True and False (need to find out how to encode those)
TRUE_BASE64 = "AAEAAAD/////AQAAAAAAAAAEAQAAAA5TeXN0ZW0uQm9vbGVhbgEAAAAHbV92YWx1ZQABAQs="
FALSE_BASE64 = "AAEAAAD/////AQAAAAAAAAAEAQAAAA5TeXN0ZW0uQm9vbGVhbgEAAAAHbV92YWx1ZQABAAs="

# Function to cipher a string
def get_ciphered_item(item, obfuscated_cipher_key):
    ciphered_item = []
    i = 0
    while i < len(item):
        ciphered_item.append(chr(ord(item[i]) ^ ord(obfuscated_cipher_key[i % len(obfuscated_cipher_key)])))
        i += 1
    return base64.b64encode("".join(ciphered_item).encode('utf-8')).decode('utf-8')

# Function to decipher a string
def get_deciphered_item(b64_item, obfuscated_cipher_key):
    b64_decoded_item = base64.b64decode(b64_item).decode('utf-8')
    deciphered_item = []
    i = 0
    while i < len(b64_decoded_item):
        deciphered_item.append(chr(ord(b64_decoded_item[i]) ^ ord(obfuscated_cipher_key[i % len(obfuscated_cipher_key)])))
        i += 1
    return "".join(deciphered_item)

# Function to decode and check for boolean values (True/False)
def decode_and_check_boolean(b64_value):
    # First decode the base64 string
    decoded_value = base64.b64decode(b64_value).decode('utf-8', errors='ignore')
    
    # Check if it matches the known True/False base64 strings
    if b64_value == TRUE_BASE64:
        return True
    elif b64_value == FALSE_BASE64:
        return False
    else:
        return decoded_value

# Function to encode boolean True/False to their respective base64
def encode_boolean_to_base64(value):
    if value is True:
        return TRUE_BASE64
    elif value is False:
        return FALSE_BASE64
    else:
        return value  # If not a boolean, return the original value

# Function to decrypt the .var file
def decrypt_var_file(input_file, cipher_key=None):
    cipher_key = cipher_key or DEFAULT_CIPHER_KEY
    obfuscated_cipher_key = ""

    # Build the obfuscated cipher key
    for c in cipher_key.lower():
        obf_char = ord(c)
        if obf_char in obf_char_map:
            obfuscated_cipher_key += chr(obf_char_map[obf_char])
        else:
            obfuscated_cipher_key += chr(obf_char)

    # Read the file lines
    with open(input_file, 'r') as file:
        lines = file.readlines()

    item_map = {}

    for line in lines:
        key, value = line.strip().split(":", 1)
        
        # Decipher the key and value
        deciphered_key = get_deciphered_item(key, obfuscated_cipher_key)
        deciphered_value = get_deciphered_item(value, obfuscated_cipher_key)
        
        # Decode and check for boolean values (True/False)
        parsed_value = decode_and_check_boolean(deciphered_value)
        
        item_map[deciphered_key] = parsed_value

    # Output the JSON file
    output_file = input_file + ".json"
    with open(output_file, 'w') as json_file:
        json.dump(item_map, json_file, indent=4)

    print(f"Decrypted var file to: {output_file}")

# Function to encrypt the .json file back to .var
def encrypt_json_file(input_file, cipher_key=None):
    cipher_key = cipher_key or DEFAULT_CIPHER_KEY
    obfuscated_cipher_key = ""

    # Build the obfuscated cipher key
    for c in cipher_key.lower():
        obf_char = ord(c)
        if obf_char in obf_char_map:
            obfuscated_cipher_key += chr(obf_char_map[obf_char])
        else:
            obfuscated_cipher_key += chr(obf_char)

    # Read the JSON file
    with open(input_file, 'r') as json_file:
        item_map = json.load(json_file)

    var_lines = []

    for key, value in item_map.items():
        # Encode the boolean value back to base64 (if it's a boolean)
        if isinstance(value, bool):
            encoded_value = encode_boolean_to_base64(value)
        else:
            # For non-boolean values, base64 encode the value first
            encoded_value = base64.b64encode(str(value).encode('utf-8')).decode('utf-8')
        
        # Now, cipher both the base64 encoded key and value
        ciphered_key = get_ciphered_item(key, obfuscated_cipher_key)
        ciphered_value = get_ciphered_item(encoded_value, obfuscated_cipher_key)
        
        # Prepare the line for the var file
        var_lines.append(f"{ciphered_key}:{ciphered_value}\n")

    # Output the var file
    output_file = input_file + ".var"
    with open(output_file, 'w') as var_file:
        var_file.writelines(var_lines)

    print(f"Encrypted JSON file to: {output_file}")


# Main function to handle file type and process accordingly
def process_file(input_file):
    # Check if file has an extension or not
    file_name, file_extension = os.path.splitext(input_file)

    if file_extension == "":
        # No extension, treat it as a .var file
        decrypt_var_file(input_file)
    elif file_extension == ".var":
        # If it's a .var file, decrypt it to JSON
        decrypt_var_file(input_file)
    elif file_extension == ".json":
        # If it's a .json file, encrypt it back to .var
        encrypt_json_file(input_file)
    else:
        print("Unsupported file type. Please provide a .var or .json file.")

# Main function to execute the decryption/encryption
if __name__ == "__main__":
    input_file = input("Enter the path of the file: ").strip()
    if not os.path.exists(input_file):
        print("The specified file does not exist.")
    else:
        process_file(input_file)
