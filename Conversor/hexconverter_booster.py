
def dissect_ip_packet(hex_string):
    # Remove espaços e hífens
    hex_string = hex_string.replace(" ", "").replace("-", "")
    
    # Verifica se tem pelo menos 20 bytes (40 caracteres hex)
    if len(hex_string) < 40:
        raise ValueError("Hex inválido: cabeçalho IPv4 precisa de pelo menos 20 bytes.")
    
    # Converte hex para lista de valores decimais
    decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    
    # Extrai campos do cabeçalho IPv4
    ip_packet = {
        "Version": (decimal_values[0] >> 4),
        "Header Length": (decimal_values[0] & 0x0F) * 4,
        "Type of Service": decimal_values[1],
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
    
    # Se houver payload, extrai
    payload_start = ip_packet["Header Length"]
    payload = decimal_values[payload_start:] if len(decimal_values) > payload_start else []
    
    return ip_packet, payload

def extract_ascii(payload):
    # Converte payload para ASCII (ignora valores não imprimíveis)
    ascii_characters = [chr(b) if 32 <= b <= 126 else '.' for b in payload]
    return ''.join(ascii_characters)

# Exemplo com cabeçalho IP válido
hex_string = "45 00 00 3C 1C 46 40 00 40 06 B1 E6 C0 A8 01 02 C0 A8 01 01 48 65 6C 6C 6F 20 57 6F 72 6C 64"

# Dissecando o pacote
ip_packet, payload = dissect_ip_packet(hex_string)

print("========= Cabeçalho IP =========")
for field, value in ip_packet.items():
    print(f"{field}: {value}")
print("================================")

# Se houver payload, mostra ASCII
if payload:
    print(f"Payload ASCII: {extract_ascii(payload)}")
else:
    print("Sem payload no pacote.")
