def dissect_ip_packet(hex_string):
    # Remove spaces and hyphens
    hex_string = hex_string.replace(" ", "").replace("-", "")
    
    # Convert hex to decimal
    decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    
    # Dissect the IP packet
    ip_packet = {
        "Version": (decimal_values[0] >> 4),
        "Header Length": (decimal_values[0] & 0x0F) * 4,
        "Explicit Congestion Notification": decimal_values[1],
        "Total Length": (decimal_values[2] << 8) + decimal_values[3],
        "Identification": (decimal_values[4] << 8) + decimal_values[5],
        "Flags": (decimal_values[6] >> 5),
        "Fragment Offset": ((decimal_values[6] & 0x1F) << 8) + decimal_values[7],
        "TTL": decimal_values[8],
        "Protocol": decimal_values[9],
        "Header Checksum": (decimal_values[10] << 8) + decimal_values[11],
        "Source IP": f"{decimal_values[12]}.{decimal_values[13]}.{decimal_values[14]}.{decimal_values[15]}",
        "Destination IP": f"{decimal_values[16]}.{decimal_values[17]}.{decimal_values[18]}.{decimal_values[19]}"
    }
    
    return ip_packet

def extract_ascii(hex_string):
    # Remove spaces and hyphens
    hex_string = hex_string.replace(" ", "").replace("-", "")
    
    # Convert hex to decimal
    decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    
    # Convert decimal to ASCII characters
    ascii_characters = [chr(value) for value in decimal_values]
    
    # Join ASCII characters to form the plain text
    plain_text = ''.join(ascii_characters)
    
    return plain_text

# Hexadecimal string example
hex_string = "45 00 00 3C 1C 46 40 00 40 06 B1 E6 C0 A8 01 02 C0 A8 01 01F"

# Dissect the IP packet and print the results
ip_packet = dissect_ip_packet(hex_string)
print("========= Pacote IP ============")
for field, value in ip_packet.items():
    print(f"{field}: {value}")
print("===============================")

# Extract ASCII and print the results
plain_text = extract_ascii(hex_string)
print(f"ASCII Text: {plain_text}")
