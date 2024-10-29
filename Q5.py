import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, TCP, UDP, rdpcap, Ether, Raw
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

def build_esp_packet(original_packet, mode, key, iv, hmac_key):
    """
    Constructs the ESP packet based on the selected mode.
    """
    if Raw in original_packet:
        payload = bytes(original_packet[Raw])
    else:
        payload = b''
    next_header = original_packet[IP].proto.to_bytes(1, 'big')
    
    pad_len = AES.block_size - (len(payload) % AES.block_size)
    padding = bytes([pad_len] * pad_len) + bytes([pad_len]) + next_header
    payload_with_trailer = payload + padding

    encrypted_data = encrypt_data(payload_with_trailer, key, iv)

    spi = bytes([1, 0, 0, 0])
    sequence_number = b'\x00\x00\x00\x01'
    esp_header = spi + sequence_number + iv + encrypted_data

    esp_hmac = compute_hmac(esp_header, hmac_key)

    if mode == 'transport':
        original_packet = original_packet.copy()
        original_packet.remove_payload()
        original_packet.add_payload(esp_header + esp_hmac)
        return original_packet

    elif mode == 'tunnel':
        new_ip_header = IP(src="192.168.99.99", dst=original_packet[IP].dst)
        return new_ip_header / esp_header / esp_hmac

def main():
    """
    Main function to process command line arguments, read pcap file, encrypt payload,
    construct ESP packet, and display results.
    """
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 Q5.py [path_to_pcap_file] [mode]")
        packet_file = sys.argv[1]
        mode = sys.argv[2].strip().lower()

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
