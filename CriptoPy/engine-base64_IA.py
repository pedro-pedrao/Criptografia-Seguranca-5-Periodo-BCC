ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def Encode(word: str) -> str:
    byte_word = word.encode('utf-8')
    i = 0
    result = ""

    while True:
        if i >= len(byte_word):
            break
        
        if len(byte_word) - i >= 3:
            byte1 = byte_word[i]
            byte2 = byte_word[i + 1]
            byte3 = byte_word[i + 2]
            g1 = byte1 >> 2
            g2 = ((byte1 & 0x03) << 4) | (byte2 >> 4)
            g3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6)
            g4 = byte3 & 0x3F
            result += ALPHABET[g1] + ALPHABET[g2] + ALPHABET[g3] + ALPHABET[g4]

        if len(byte_word) - i == 2:
            byte1 = byte_word[i]
            byte2 = byte_word[i + 1]
            g1 = byte1 >> 2
            g2 = ((byte1 & 0x03) << 4) | (byte2 >> 4)
            g3 = (byte2 & 0x0F) << 2
            result += ALPHABET[g1] + ALPHABET[g2] + ALPHABET[g3] + "="

        if len(byte_word) - i == 1:
            byte1 = byte_word[i]
            g1 = byte1 >> 2
            g2 = (byte1 & 0x03) << 4
            result += ALPHABET[g1] + ALPHABET[g2] + "=" + "="

        i += 3

    return result


def Decode(base64: str) -> str:
    i = 0
    result = ""

    while True:
        if i >= len(base64):
            break

        if '=' not in base64[i:i+4]:           # bloco completo
            g1 = ALPHABET.index(base64[i])
            g2 = ALPHABET.index(base64[i+1])
            g3 = ALPHABET.index(base64[i+2])
            g4 = ALPHABET.index(base64[i+3])

            byte1 = (g1 << 2) | (g2 >> 4)
            byte2 = ((g2 & 0x0F) << 4) | (g3 >> 2)
            byte3 = ((g3 & 0x03) << 6) | g4

            result += chr(byte1) + chr(byte2) + chr(byte3)

        elif base64[i+2] == '=':               # padding == (2 chars úteis)
            g1 = ALPHABET.index(base64[i])
            g2 = ALPHABET.index(base64[i+1])

            byte1 = (g1 << 2) | (g2 >> 4)

            result += chr(byte1)

        elif base64[i+3] == '=':               # padding = (3 chars úteis)
            g1 = ALPHABET.index(base64[i])
            g2 = ALPHABET.index(base64[i+1])
            g3 = ALPHABET.index(base64[i+2])

            byte1 = (g1 << 2) | (g2 >> 4)
            byte2 = ((g2 & 0x0F) << 4) | (g3 >> 2)

            result += chr(byte1) + chr(byte2)

        i += 4

    return result


t1 = Encode("Man")
t2 = Encode("Ma")
t3 = Encode("M")

print(f"Encode t1: {t1}")
print(f"Encode t2: {t2}")
print(f"Encode t3: {t3}")


t4 = Decode(t1)
t5 = Decode(t2)
t6 = Decode(t3)

print(f"Decode t1: {t4}")
print(f"Decode t2: {t5}")
print(f"Decode t3: {t6}")
