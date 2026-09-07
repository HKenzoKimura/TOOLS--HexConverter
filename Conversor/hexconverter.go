
package main

import (
    "encoding/hex"
    "fmt"
    "os"
    "strings"
)

func main() {
    // Exemplo de pacote IP com payload | CONTÉM PAYLOAD "HELLO WORLD"
    hexString := "45 00 00 3C 1C 46 40 00 40 06 B1 E6 C0 A8 01 02 C0 A8 01 01 48 65 6C 6C 6F 20 57 6F 72 6C 64"


    hexString = strings.ReplaceAll(hexString, " ", "")
    hexString = strings.ReplaceAll(hexString, "-", "")

    data, err := hex.DecodeString(hexString)
    if err != nil {
        fmt.Println("Erro ao converter hex:", err)
        os.Exit(1)
    }

    if len(data) < 20 {
        fmt.Println("Pacote inválido: cabeçalho IPv4 precisa de pelo menos 20 bytes.")
        os.Exit(1)
    }

    version := data[0] >> 4
    headerLength := (data[0] & 0x0F) * 4
    totalLength := uint16(data[2])<<8 | uint16(data[3])
    identification := uint16(data[4])<<8 | uint16(data[5])
    flags := data[6] >> 5
    fragmentOffset := (uint16(data[6]&0x1F) << 8) | uint16(data[7])
    ttl := data[8]
    protocol := data[9]
    checksum := uint16(data[10])<<8 | uint16(data[11])
    sourceIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
    destIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])

    fmt.Println("========= Cabeçalho IP =========")
    fmt.Printf("Version: %d\n", version)
    fmt.Printf("Header Length: %d bytes\n", headerLength)
    fmt.Printf("Total Length: %d\n", totalLength)
    fmt.Printf("Identification: %d\n", identification)
    fmt.Printf("Flags: %d\n", flags)
    fmt.Printf("Fragment Offset: %d\n", fragmentOffset)
    fmt.Printf("TTL: %d\n", ttl)
    fmt.Printf("Protocol: %d\n", protocol)
    fmt.Printf("Header Checksum: %d\n", checksum)
    fmt.Printf("Source IP: %s\n", sourceIP)
    fmt.Printf("Destination IP: %s\n", destIP)
    fmt.Println("================================")

    // Payload
    if len(data) > int(headerLength) {
        payload := data[headerLength:]
        ascii := ""
        for _, b := range payload {
            if b >= 32 && b <= 126 {
                ascii += string(b)
            } else {
                ascii += "."
            }
        }
        fmt.Printf("Payload ASCII: %s\n", ascii)
    } else {
        fmt.Println("Sem payload no pacote.")
    }
}
