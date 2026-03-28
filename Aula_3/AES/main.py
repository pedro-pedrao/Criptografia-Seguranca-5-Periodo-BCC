import os
import hashlib
import hmac

# ============================================================
# ETAPA 1 — Constantes do AES
# ============================================================

# S-Box: tabela de substituição usada no SubBytes e no Key Schedule (SubWord)
# Índice = byte original, valor = byte substituído
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# S-Box Inversa: tabela de substituição usada no InvSubBytes (decifragem)
# É o mapeamento reverso da S-Box: se S_BOX[a] = b, então S_BOX_INV[b] = a
S_BOX_INV = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Rcon: constantes de rodada usadas no Key Schedule
# Cada valor é uma potência de 2 calculada em GF(2⁸)
# Usado para diferenciar as subchaves geradas a cada rodada
RCON = [

    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]

# ============================================================
# ETAPA 2 — xtime e gmul
# ============================================================

def xtime(b:bytes):
    bit7 =  b & 0x80
    resultado = (b << 1) & 0xFF
    if(bit7):
        resultado = resultado ^ 0X1B
    return resultado


def gmul(a: bytes, b: bytes):
    resultado = 0
    for i in range(8):
        if(b & 0x01):
            resultado = resultado ^ a
        a = xtime(a)
        b = b >> 1
    return resultado & 0XFF

# ============================================================
# ETAPA 3 — As 4 transformações
# ============================================================

def sub_bytes(estado: list):
    for linha in range(4):
        for coluna in range(4):
            estado[linha][coluna] = S_BOX[estado[linha][coluna]]

def inv_sub_bytes(estado: list):
    for linha in range(4):
        for coluna in range(4):
            estado[linha][coluna] = S_BOX_INV[estado[linha][coluna]]

def shift_rows(estado: list):
    estado[0] = estado[0][0:] + estado[0][:0]
    estado[1] = estado[1][1:] + estado[1][:1]
    estado[2] = estado[2][2:] + estado[2][:2]
    estado[3] = estado[3][3:] + estado[3][:3]

def inv_shift_rows(estado:list):
    estado[0] = estado[0][0:] + estado[0][:0]
    estado[1] = estado[1][-1:] + estado[1][:-1]
    estado[2] = estado[2][-2:] + estado[2][:-2]
    estado[3] = estado[3][-3:] + estado[3][:-3]

def mix_columns(estado: list):
    for i in range(4):
        b0 = estado[0][i]
        b1 = estado[1][i]
        b2 = estado[2][i]
        b3 = estado[3][i]
        novo_b0 = gmul(b0,2) ^ gmul(b1,3) ^ gmul(b2,1) ^ gmul(b3,1)
        novo_b1 = gmul(b0,1) ^ gmul(b1,2) ^ gmul(b2,3) ^ gmul(b3,1)
        novo_b2 = gmul(b0,1) ^ gmul(b1,1) ^ gmul(b2,2) ^ gmul(b3,3)
        novo_b3 = gmul(b0,3) ^ gmul(b1,1) ^ gmul(b2,1) ^ gmul(b3,2)
        estado[0][i] = novo_b0
        estado[1][i] = novo_b1
        estado[2][i] = novo_b2
        estado[3][i] = novo_b3

def inv_mix_columns(estado: list):
    for i in range(4):
        b0 = estado[0][i]
        b1 = estado[1][i]
        b2 = estado[2][i]
        b3 = estado[3][i]
        novo_b0 = gmul(b0, 0x0E) ^ gmul(b1, 0x0B) ^ gmul(b2, 0x0D) ^ gmul(b3, 0x09)
        novo_b1 = gmul(b0, 0x09) ^ gmul(b1, 0x0E) ^ gmul(b2, 0x0B) ^ gmul(b3, 0x0D)
        novo_b2 = gmul(b0, 0x0D) ^ gmul(b1, 0x09) ^ gmul(b2, 0x0E) ^ gmul(b3, 0x0B)
        novo_b3 = gmul(b0, 0x0B) ^ gmul(b1, 0x0D) ^ gmul(b2, 0x09) ^ gmul(b3, 0x0E)
        estado[0][i] = novo_b0
        estado[1][i] = novo_b1
        estado[2][i] = novo_b2
        estado[3][i] = novo_b3

def add_round_key(estado: list, subchave: list):
    for linha in range(4):
        for coluna in range(4):
            estado[linha][coluna] = estado[linha][coluna] ^ subchave[linha][coluna]


# ============================================================
# ETAPA 4 — Key Schedule
# ============================================================
def key_schedule(chave: bytes) -> list:
    w = []
    for i in range(8):
        palavra =  [chave[4*i], chave[4*i+1], chave[4*i+2], chave[4*i+3]]
        w.append(palavra)

    for i in range(8,60):
        temp = w[i-1][:]

        if(i % 8 == 0):
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]

            temp[0] ^= RCON[i//8-1]
        
        elif(i % 4 == 0):
            temp = [S_BOX[b] for b in temp]
        
        temp = [temp[j] ^ w[i-8][j] for j in range(4)]
        w.append(temp)

    subchaves = []
    for i in range(15):
        palavras = w[i*4 : i*4+4]
        subchave = [
            [palavras[0][linha], palavras[1][linha], palavras[2][linha], palavras[3][linha]]
            for linha in range(4)
        ]
        subchaves.append(subchave)

    return subchaves

# ============================================================
# ETAPA 5 — Cifragem e Decifragem de um bloco
# ============================================================
def cifrar_bloco(bloco: bytes, subchaves: list) -> bytes:
    estado = [
        [bloco[0],  bloco[4],  bloco[8],  bloco[12]],
        [bloco[1],  bloco[5],  bloco[9],  bloco[13]],
        [bloco[2],  bloco[6],  bloco[10], bloco[14]],
        [bloco[3],  bloco[7],  bloco[11], bloco[15]],
    ]

    add_round_key(estado, subchaves[0])

    for rodada in range(1,14):
        sub_bytes(estado)
        shift_rows(estado)
        mix_columns(estado)
        add_round_key(estado, subchaves[rodada])

    sub_bytes(estado)
    shift_rows(estado)
    add_round_key(estado, subchaves[14])

    resultado = []
    for coluna in range(4):
        for linha in range(4):
            resultado.append(estado[linha][coluna])

    return bytes(resultado)

def decifrar_bloco(bloco: bytes, subchaves: list) -> bytes:
    estado = [
        [bloco[0],  bloco[4],  bloco[8],  bloco[12]],
        [bloco[1],  bloco[5],  bloco[9],  bloco[13]],
        [bloco[2],  bloco[6],  bloco[10], bloco[14]],
        [bloco[3],  bloco[7],  bloco[11], bloco[15]],
    ]

    add_round_key(estado, subchaves[14])

    for rodada in range(13, 0, -1):
        inv_shift_rows(estado)
        inv_sub_bytes(estado)
        add_round_key(estado, subchaves[rodada])
        inv_mix_columns(estado)
    
    inv_shift_rows(estado)
    inv_sub_bytes(estado)
    add_round_key(estado, subchaves[0])

    resultado = []
    for coluna in range(4):
        for linha in range(4):
            resultado.append(estado[linha][coluna])

    return bytes(resultado)


# ============================================================
# ETAPA 6 — Padding
# ============================================================
def adicionar_padding(dados: bytes) -> bytes:
    n = 16 - (len(dados) % 16)
    if(n == 0):
        n = 16
    return dados + bytes([n] * n)

def remover_padding(dados: bytes) -> bytes:
    n = dados[-1]
    return dados[:-n]

# ============================================================
# ETAPA 7 — Modo CBC
# ============================================================
def cifrar_cbc(dados: bytes, subchaves:list) -> bytes:
    iv = os.urandom(16)

    dados = adicionar_padding(dados)
    
    resultado = []
    bloco_anterior = iv

    for i in range(0, len(dados), 16):
        blocos = dados[i : i+16]
        bloco = bytes([a ^ b for a, b in zip(blocos, bloco_anterior)])
        bloco = cifrar_bloco(bloco, subchaves)
        resultado.append(bloco)
        bloco_anterior = bloco
    return iv + b''.join(resultado)

def decifrar_cbc(dados: bytes, subchaves: list) -> bytes:
    iv = dados[:16]
    dados = dados[16:]

    resultado = []
    bloco_anterior = iv

    for i in range(0, len(dados), 16):
        bloco_cifrado = dados[i : i+16]
        bloco = decifrar_bloco(bloco_cifrado, subchaves)
        bloco = bytes([a ^ b for a,b in zip(bloco, bloco_anterior)])
        resultado.append(bloco)
        bloco_anterior = bloco_cifrado

    return remover_padding(b''.join(resultado))

# ============================================================
# ETAPA 8 — 
# ============================================================

def pbkdf2(senha: str, salt: bytes, iteracoes: int = 100000, tamanho: int = 32) -> bytes:
    
    if(isinstance(senha, str)):
        senha = senha.encode('utf-8')

    resultado = b''
    numero_bloco = 1

    while len(resultado) < tamanho:
        u = hmac.new(senha, salt + numero_bloco.to_bytes(4, 'big'), hashlib.sha256).digest()
        acumulado = u
        
        for _ in range(iteracoes - 1):
            u = hmac.new(senha, u, hashlib.sha256).digest()
            acumulado = bytes([a ^ b for a, b in zip(acumulado, u)])

        resultado += acumulado
        numero_bloco += 1

    return resultado[:tamanho]

def encrypt(texto: str, senha: str) -> bytes:
    
    salt = os.urandom(16)
    chave = pbkdf2(senha, salt)

    subchaves = key_schedule(chave)

    dados = texto.encode('utf-8')
    cifrado = cifrar_cbc(dados, subchaves)

    return salt + cifrado

def decrypt(dados: bytes, senha: str) -> str:
    salt = dados[:16]
    dados = dados[16:]

    chave = pbkdf2(senha, salt)

    subchaves = key_schedule(chave)

    decifrado = decifrar_cbc(dados, subchaves)

    return decifrado.decode('utf-8')


# cifrar
cifrado = encrypt("minha mensagem secreta", "minha_senha")

print(f"Cifrado byte = {cifrado} \n\n")
print(f"Cifrado hexadecimal = {cifrado.hex()} \n\n")
# decifrar
texto = decrypt(cifrado, "minha_senha")
print(f"Decifrado = {texto}" )  # "minha mensagem secreta"