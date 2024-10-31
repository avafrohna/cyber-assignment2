import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, TCP, UDP, rdpcap, Ether
import hashlib
from Crypto.Hash import HMAC, SHA256

def encrypt_data(data, key, iv):
    """
    Initialize an AES cipher object using CBC mode and encrypt data.

    :param data: The plaintext data to be encrypted (byte string).
    :param key: The encryption key (byte string).
    :param iv: The initialization vector (byte string).
    :return: Encrypted data (byte string).
    """
    # Initialize the AES cipher for CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data after padding it to ensure it fits the block size
    return cipher.encrypt(pad(data, AES.block_size))

def compute_hmac(data, key):
    """
    Compute HMAC for the given data using SHA-256.

    :param data: Data to be authenticated (byte string).
    :param key: HMAC key (byte string).
    :return: HMAC value (byte string).
    """
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data)
    return hmac.digest()

def calculate_packet_hash(packet):
    """
    Calculate a SHA-256 hash of the given packet for integrity checking.

    :param packet: The Scapy packet object.
    :return: SHA-256 hash as a hexadecimal string.
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(bytes(packet))
    return hash_obj.hexdigest()

def add_padding(plaintext: bytes, block_size: int) -> bytes:
    """
    Adds padding to the plaintext to make its length a multiple of the block size.
    Padding should follow PKCS#7 padding scheme. This scheme adds padding bytes where each byte's value is equal to the number of padding bytes added. For example, if 3 bytes of padding are needed, the padding would be 03 03 03.
    
    Parameters:
    - plaintext (bytes): The data to be encrypted.
    - block_size (int): The block size required by the encryption algorithm.
    
    Returns:
    - bytes: The padded plaintext.
    """
    # Calculate number of padding bytes needed
    padding_len = block_size - (len(plaintext) % block_size)
    # Generate padding in PKCS#7 format
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def build_esp_packet(original_packet, mode, key, iv, hmac_key):
    """
    Constructs the ESP packet based on the selected mode.
    """
    # Checks if mode is transport or tunnel
    if mode == 'transport':
        # Checks if TCP or UDP and extracts payload
        if TCP in original_packet:
            payload = bytes(original_packet[IP].payload)
        elif UDP in original_packet:
            payload = bytes(original_packet[IP].payload)
        else:
            raise ValueError("Unsupported protocol. Only TCP and UDP are currently handled.") 
    else:
        payload = bytes(original_packet[IP])

    # Converts to a single byte
    next_header = bytes([original_packet.proto])
    # Pads the payload
    padded_data = add_padding(payload, AES.block_size)
    # Calculate padding length
    pad_len = bytes([len(padded_data) - len(payload)])
    # Create ESP trailer
    esp_trailer = padded_data + pad_len + next_header
    # Encrypt payload
    encrypted_data = encrypt_data(esp_trailer, key, iv)

    # Create ESP header
    spi = bytes([1]) * 4 
    sequence_number = b'\x00\x00\x00\x01'
    esp_header = spi + sequence_number + iv
    # Combine header and payload
    esp_data = esp_header + encrypted_data
    esp_hmac = compute_hmac(esp_data, hmac_key)

    # Create packet based on mode
    if mode == 'transport':
        esp_packet = original_packet.copy()
        esp_packet[IP].remove_payload()
        esp_packet[IP].add_payload(esp_data + esp_hmac)
        return esp_packet[IP]
    elif mode == 'tunnel':
        new_ip = IP(src="192.168.99.99", dst=original_packet[IP].dst)
        return new_ip / (esp_data + esp_hmac)

def main():
    """
    Main function to process command line arguments, read pcap file, encrypt payload,
    construct ESP packet, and display results.
    """
    try:
        # Checks to make sure there are a correct number of arguments
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 Q5.py [path_to_pcap_file] [mode]")
        packet_file = sys.argv[1]
        mode = sys.argv[2].strip().lower()

        # Checks to make sure valid mode was chosen
        if mode not in ["tunnel", "transport"]:
            raise ValueError("Invalid mode. Choose 'tunnel' or 'transport'.")
        
        try:
            packets = rdpcap(packet_file)
            original_packet = packets[0]
        except:
            raise ValueError("Failed to read the pcap file.")
        
        # Remove Ethernet layer if present
        if Ether in original_packet:
            original_packet = original_packet[IP]

        key = hashlib.sha256(b"secret_key").digest()[:16]  # AES Key
        iv = hashlib.sha256(b"initialization_vector").digest()[:16]  # AES IV
        hmac_key = hashlib.sha256(b"hmac_key").digest()  # HMAC Key

        # Generate your ESP Packet based on the selected mode. 
        esp_packet = build_esp_packet(original_packet, mode, key, iv, hmac_key)

        packet_hash = calculate_packet_hash(esp_packet)
        print("SHA-256 Hash of the encrypted packet:", packet_hash)
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
