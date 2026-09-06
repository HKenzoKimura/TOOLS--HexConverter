# 🔬 IPv4 Hex Packet Dissector — Network Protocol Analyzer

> **Type:** Network Protocol Analysis Tool
> **Layer:** OSI Layer 3 — Network (IPv4)
> **Input:** Raw hex string (Wireshark copy, tcpdump, manual)
> **Output:** Parsed IPv4 header fields + ASCII payload
>
> Ferramenta de análise que recebe um pacote IPv4 em formato hexadecimal e disseca cada campo do cabeçalho usando operações de bit — o mesmo mecanismo que Wireshark, Scapy e tcpdump usam internamente para exibir campos de protocolo.

---

## `$ cat ./objective.txt`

Implementar do zero um **parser de cabeçalho IPv4** em Python puro para:

- Entender a estrutura binária do protocolo IP no nível de bits e bytes
- Aprender operações de bit manipulation (shift, mask, AND, OR) aplicadas a protocolos reais
- Construir a base para ferramentas de análise de rede, IDS e forense de pacotes
- Complementar o uso de ferramentas como Wireshark com compreensão do que acontece por baixo

---

## `$ cat ./ipv4_header_structure.txt`

### RFC 791 — Estrutura do Cabeçalho IPv4

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌─────────┬─────────┬─────────────────────────────────────────────┐
│ Version │   IHL   │  Type of Service  │       Total Length      │ Byte 0-3
├─────────┴─────────┴───────────────────┴─────────────────────────┤
│           Identification              │Flags│  Fragment Offset   │ Byte 4-7
├───────────────────────────────────────┴─────┴───────────────────┤
│      TTL          │    Protocol       │       Header Checksum    │ Byte 8-11
├───────────────────┴───────────────────┴─────────────────────────┤
│                       Source IP Address                         │ Byte 12-15
├─────────────────────────────────────────────────────────────────┤
│                    Destination IP Address                       │ Byte 16-19
├─────────────────────────────────────────────────────────────────┤
│                    Options (se IHL > 5)        │    Padding     │ Byte 20+
├─────────────────────────────────────────────────────────────────┤
│                         PAYLOAD                                 │ Byte IHL*4+
└─────────────────────────────────────────────────────────────────┘

Tamanho mínimo do cabeçalho: 20 bytes (IHL=5 → 5×4=20)
Tamanho máximo do cabeçalho: 60 bytes (IHL=15 → 15×4=60)
```

---

## `$ cat ./design_decisions.md`

### 1. Conversão Hex → Lista Decimal

```python
decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
```

**Por que lista de decimais e não bytes nativo (`bytes.fromhex()`)?**

A lista de inteiros permite acesso direto por índice com semântica clara:
```
decimal_values[0] → byte 0 do pacote → contém Version + IHL
decimal_values[9] → byte 9 → contém o número do protocolo (TCP=6, UDP=17, ICMP=1)
```

Com `bytes.fromhex()` o resultado seria equivalente, mas a list comprehension torna explícita a conversão par-a-par — didaticamente mais claro para quem está aprendendo que cada 2 caracteres hex = 1 byte.

**Suporte a múltiplos formatos de entrada:**
```python
hex_string.replace(" ", "").replace("-", "")
# "45 00 00 3C" → "45 00003C" → "45 00003C" → "4500003C"
# "45-00-00-3C" → "4500003C"
# Wireshark, tcpdump, CyberChef — todos suportados
```

---

### 2. Extração de Campos — Bit Manipulation

O byte 0 do cabeçalho IP contém **dois campos compactados em um único byte**:

```
Byte 0:  [ V V V V | I I I I ]
          Version   IHL (Header Length)
          (4 bits)  (4 bits)
```

**Version — deslocamento à direita:**
```python
"Version": (decimal_values[0] >> 4)

# Exemplo com byte 0x45 = 0100 0101
# 0x45 >> 4 = 0000 0100 = 4  ✓ (IPv4)
```

`>> 4` desloca os 4 bits da Version para a posição de bit menos significativo, descartando os 4 bits do IHL.

**IHL (Header Length) — máscara AND:**
```python
"Header Length": (decimal_values[0] & 0x0F) * 4

# 0x45 & 0x0F = 0100 0101 & 0000 1111 = 0000 0101 = 5
# 5 × 4 = 20 bytes  ✓ (cabeçalho mínimo sem opções)
```

`0x0F = 0000 1111` é a máscara que zera os 4 bits superiores, preservando apenas os 4 bits inferiores do IHL. O multiplicador `× 4` converte o valor em **unidades de palavras de 32 bits** para bytes.

**Flags e Fragment Offset — campo de 16 bits particionado:**
```python
"Flags":           (decimal_values[6] >> 5)
"Fragment Offset": ((decimal_values[6] & 0x1F) << 8) + decimal_values[7]

# Byte 6: [ F F F | O O O O O ] Byte 7: [ O O O O O O O O ]
#          Flags    Fragment Offset (13 bits no total)
```

Os 3 bits de Flags ficam nos bits 7-5 do byte 6 (`>> 5` os traz para posição 0-2). Os 13 bits do Fragment Offset ocupam os bits 4-0 do byte 6 + todos os 8 bits do byte 7 — a máscara `& 0x1F` (`0001 1111`) extrai os 5 bits inferiores do byte 6, que são então deslocados `<< 8` para criar espaço para os 8 bits do byte 7.

**Campos de 16 bits (Total Length, Identification, Checksum):**
```python
"Total Length": (decimal_values[2] << 8) + decimal_values[3]

# decimal_values[2] = 0x00 = 0
# decimal_values[3] = 0x3C = 60
# (0 << 8) + 60 = 60 bytes de pacote total
```

Dois bytes contíguos formam um inteiro de 16 bits (big-endian, conforme RFC 791). O byte mais significativo é deslocado 8 posições à esquerda e somado ao byte menos significativo — equivalente a `struct.unpack(">H", bytes([b2, b3]))[0]`, mas explícito.

**Source / Destination IP — notação decimal pontilhada:**
```python
"Source IP": f"{decimal_values[12]}.{decimal_values[13]}.{decimal_values[14]}.{decimal_values[15]}"
# 0xC0.0xA8.0x01.0x02 → 192.168.1.2
```

Cada byte de endereço IP é um octeto independente — sem operações de bit necessárias, apenas formatação direta.

---

### 3. Payload Dinâmico com `Header Length`

```python
payload_start = ip_packet["Header Length"]   # IHL × 4 (pode ser > 20 se houver opções)
payload = decimal_values[payload_start:] if len(decimal_values) > payload_start else []
```

**Por que usar `Header Length` como offset e não simplesmente `[20:]`?**

O cabeçalho IPv4 tem tamanho variável — o campo IHL indica quantas **palavras de 32 bits** o cabeçalho ocupa. Com opções IP (Timestamp, Record Route, Loose Source Routing), o cabeçalho pode ter até 60 bytes. Usar `Header Length` calculado garante que o payload seja extraído corretamente independente de opções presentes.

---

### 4. `extract_ascii()` — Filtro de Printabilidade

```python
ascii_characters = [chr(b) if 32 <= b <= 126 else '.' for b in payload]
```

O intervalo `32 <= b <= 126` representa os **caracteres ASCII imprimíveis** (espaço até `~`). Bytes fora desse range (bytes de controle, dados binários) são substituídos por `.` — o mesmo comportamento do Wireshark no painel ASCII do hexdump e do `xxd`/`hexdump -C` no terminal.

```
0x48 0x65 0x6C 0x6C 0x6F → "Hello"   (printável)
0x00 0x0A 0xFF            → "..."     (substituído)
```

---

## `$ cat ./packet_walkthrough.txt`

### Análise do Pacote de Exemplo

```
Input: "45 00 00 3C 1C 46 40 00 40 06 B1 E6 C0 A8 01 02 C0 A8 01 01 48 65 6C 6C 6F 20 57 6F 72 6C 64"
```

```
Hex:  45    00    00 3C    1C 46    40 00    40    06    B1 E6    C0 A8 01 02    C0 A8 01 01
Dec:  69    0     60       7238     16384    64    6     45542    192.168.1.2    192.168.1.1
      │     │     │        │        │        │     │     │        │              │
      │     │     │        │        │        │     │     │        │              └─ Dst IP
      │     │     │        │        │        │     │     │        └─ Src IP
      │     │     │        │        │        │     │     └─ Checksum
      │     │     │        │        │        │     └─ Protocol 6 = TCP
      │     │     │        │        │        └─ TTL = 64 (Linux default)
      │     │     │        │        └─ Flags=010 (DF=Don't Fragment) + Offset=0
      │     │     │        └─ ID = 0x1C46 = 7238
      │     │     └─ Total Length = 60 bytes
      │     └─ ToS = 0 (Best Effort)
      └─ 0x45: Version=4, IHL=5 (cabeçalho de 20 bytes)

Payload: 48 65 6C 6C 6F 20 57 6F 72 6C 64 → "Hello World"
```

**Output gerado:**
```
========= Cabeçalho IP =========
Version: 4
Header Length: 20
Type of Service: 0
Total Length: 60
Identification: 7238
Flags: 2
Fragment Offset: 0
TTL: 64
Protocol: 6
Header Checksum: 45542
Source IP: 192.168.1.2
Destination IP: 192.168.1.1
================================
Payload ASCII: Hello World
```

---

## `$ cat ./protocol_numbers.md`

> Referência rápida para o campo Protocol (byte 9 do cabeçalho).

| Decimal | Hex | Protocolo | Uso comum |
|---------|-----|-----------|-----------|
| 1 | 0x01 | ICMP | ping, traceroute |
| 6 | 0x06 | TCP | HTTP, HTTPS, SSH, FTP |
| 17 | 0x11 | UDP | DNS, DHCP, QUIC |
| 47 | 0x2F | GRE | VPN tunneling |
| 50 | 0x32 | ESP | IPSec encrypted |
| 51 | 0x33 | AH | IPSec auth |
| 89 | 0x59 | OSPF | Routing protocol |

---

## `$ cat ./usage.sh`

```bash
# Sem dependências externas — Python stdlib apenas
python hex_dissector.py

# Exemplos de pacotes para testar:

# ICMP (ping)
hex_string = "45 00 00 1C 00 01 00 00 40 01 F3 CD C0 A8 01 01 C0 A8 01 02"

# UDP
hex_string = "45 00 00 28 AB CD 00 00 40 11 XX XX 0A 00 00 01 0A 00 00 02"

# Pacote com opções IP (IHL > 5)
hex_string = "4F 00 ..."  # IHL=15 → cabeçalho de 60 bytes com opções
```

---

## `$ cat ./extensions.md`

| Feature | Implementação | Valor |
|---------|--------------|-------|
| Protocolo de transporte | Parsear TCP/UDP/ICMP após payload_start | Dissector multicamada |
| Flags decodificadas | `{DF, MF, Reserved}` em vez de inteiro | Legibilidade |
| Validação de checksum | Calcular e comparar com o campo | Detectar corrupção/spoofing |
| Leitura de .pcap | `import struct` + parsing do PCAP global header | Analisar capturas reais |
| Colorização | `colorama` para output colorido por campo | UX no terminal |
| Argparse / stdin | `python dissector.py "45 00 ..."` | Uso em pipeline |
| Suporte IPv6 | Parser separado (header fixo de 40 bytes, sem IHL) | Cobertura completa |

---

## `$ cat ./lessons_learned.txt`

```
[+] Bit manipulation (>>, <<, &) é a ferramenta fundamental de parsers de protocolo de rede
[+] O campo IHL ser variável (e não fixo em 20) é a causa de muitos bugs em parsers ingênuos
[+] Big-endian (network byte order) é o padrão em todos os protocolos de rede — entender isso
    é essencial para ler capturas do Wireshark corretamente
[+] O intervalo 32-126 para ASCII printável é o mesmo usado por xxd, hexdump -C e Wireshark
[+] Validar o tamanho mínimo antes de indexar evita IndexError em pacotes truncados
[-] Sem validação de checksum — um pacote corrompido seria aceito e parseado sem aviso
[-] Protocol field retorna número inteiro — adicionar mapeamento para nome seria mais útil
[-] Sem suporte a opções IPv4 (Timestamp, Record Route) — IHL > 5 faz o payload começar mais tarde
[→] Próximo nível: parsear a camada de transporte (TCP flags, portas, seq/ack) após o IP header
```

---

<p align="center">
  <i>Pure Python stdlib · RFC 791 compliant parsing · Zero dependencies · Network layer foundation</i>
</p>
