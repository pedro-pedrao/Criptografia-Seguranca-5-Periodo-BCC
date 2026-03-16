ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def Encode(palavra: str) -> str:
    binario = []
    decimais = []
    response = []
    i = 0

    for c in palavra:
        binario.append(bin(ord(c))[2:].zfill(8))

    binario_join = "".join(binario)
    tamain = len(palavra)
    if(tamain % 3 == 0):
        binario_parts = [binario_join[i:i+6] for i in range(0, len(binario_join), 6)]
        for b in binario_parts:
            decimais.append(int(b, 2))
            response.append(ALPHABET[decimais[i]])
            i+=1
        # print(f"binario_parts: {binario_parts}")
        # print(f"decimais: {decimais}")
        # print(f"response: {response}")

    elif(tamain % 3 == 2):
        binario_join += '0' * 8
        binario_parts = [binario_join[i:i+6] for i in range(0, len(binario_join), 6)]
        for b in binario_parts:
            decimais.append(int(b, 2))
            response.append(ALPHABET[decimais[i]])
            i+=1
        print(f"binario_parts: {binario_parts}")
        print(f"decimais: {decimais}")
        print(f"response: {response}")
        response[-1] = "="
        
    elif(tamain % 3 == 1):
        binario_join += '0' * 16
        binario_parts = [binario_join[i:i+6] for i in range(0, len(binario_join), 6)]
        for b in binario_parts:
            decimais.append(int(b, 2))
            response.append(ALPHABET[decimais[i]])
            i+=1
        # print(f"binario_parts: {binario_parts}")
        # print(f"decimais: {decimais}")
        # print(f"response: {response}")
        response[-1] = "="
        response[-2] = "="


    return "".join(response)

def Decode(cripto: str) -> str:
    binario = []
    response: str

    if "=" not in cripto:
        for c in cripto:
            binario.append(bin(ALPHABET.index(c))[2:].zfill(6))
        binario_join = "".join(binario)
        binario_parts = [binario_join[i:i+8] for i in range(0, len(binario_join), 8)]

    elif cripto[-2] == '=':
        cripto = cripto.replace("=", "")
        for c in cripto:
            binario.append(bin(ALPHABET.index(c))[2:].zfill(6))
        binario_join = "".join(binario)
        binario_parts = [binario_join[i:i+8] for i in range(0, len(binario_join), 8)]
    
    elif cripto[-1] == '=':
        cripto = cripto.replace("=", "")
        for c in cripto:
            binario.append(bin(ALPHABET.index(c))[2:].zfill(6))
        binario_join = "".join(binario)
        binario_parts = [binario_join[i:i+8] for i in range(0, len(binario_join), 8)]
        
    response = "".join([chr(int(b, 2)) for b in binario_parts])

    return response

## Main

t1 = Encode("Man")
t2 = Encode("Ma")
t3 = Encode("M")

t4 = Decode(t1)
t5 = Decode(t2)
t6 = Decode(t3)

print(f"Encode t1: {t1}")
print(f"Encode t2: {t2}")
print(f"Encode t3: {t3}")
print(f"Decode t1: {t4}")
print(f"Decode t2: {t5}")
print(f"Decode t3: {t6}")
