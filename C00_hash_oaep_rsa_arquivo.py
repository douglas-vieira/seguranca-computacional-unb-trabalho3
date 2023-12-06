from pickle import *
import random as rng
import math
import struct
import hashlib
import os


def checar_assinatura(hash_arquivo_assinado, hash_arquivo_decifrado_com_chave):
    if hash_arquivo_assinado == hash_arquivo_decifrado_com_chave:
        print("Verificado com sucesso!!")
        return 1
    else:
        print("Verificacao com ERROR!!! O arquivo foi alterado.")
        return 0

def ler_arquivo_modo_binario(nome_arquivo):
    with open(nome_arquivo, "rb") as file:
        dados_arquivo = file.read()
    return(dados_arquivo)

def gerar_num_primo() -> int:
    while True:
        candidato_num_primo = (rng.randrange(1 << 1024 - 1, 1 << 1024) << 1) + 1
        if teste_num_primo(candidato_num_primo):
            return candidato_num_primo


def teste_num_primo_unidade(numero: int, v_nt: int) -> bool:
    exp, rem = numero - 1, 0
    while not exp & 1:  # checa se é ar
        exp >>= 1
        rem += 1
    x = pow(v_nt, exp, numero)
    if x == 1 or x == numero - 1:
        return True
    for _ in range(rem - 1):
        x = pow(x, 2, numero)
        if x == numero - 1:
            return True
    return False


def teste_num_primo(numero: int, k=40) -> bool:
    if numero <= 1:
        return False

    if numero <= 3:
        return True

    if numero % 2 == 0 or numero % 3 == 0:
        return False

    for _ in range(k):
        v_nt = rng.randrange(2, numero - 1)
        if not teste_num_primo_unidade(numero, v_nt):
            return False
    return True


def gerar_chaves():
    hash_func = hashlib.sha3_256
    tam_hash = hash_func().digest_size

    primo_p = gerar_num_primo()
    primo_q = gerar_num_primo()

    modulo = primo_p * primo_q

    v_t = (primo_p - 1) * (primo_q - 1)

    exp_criptografia = 65537

    out_mdc_estendido = mdc_estendido(exp_criptografia, v_t)
    exp_descriptografia = out_mdc_estendido[1]

    if exp_descriptografia < 0:
        exp_descriptografia += v_t

    chave_publica = [modulo, exp_criptografia]
    chave_privada = [modulo, exp_descriptografia]

    return (chave_publica, chave_privada, tam_hash)


def RSA_codificar(mensagem_codificada, chave_publica):
    criptograma = []
    for i in mensagem_codificada:
        criptograma.append(pow(i, chave_publica[1], chave_publica[0]))
    return criptograma


def RSA_decodificar(mensagem_codificada, chave_privada):
    mensagem = []
    for i in mensagem_codificada:
        mensagem.append(pow(i, chave_privada[1], chave_privada[0]))
    return mensagem


def formar_bloco_dados(l_hash, mensagem, k, tam_hash):
    ps = bytearray()
    for _ in range(k - len(mensagem) - (2 * tam_hash) - 2):
        ps.append(0)
    return l_hash + ps + b"\x01" + mensagem


def OAEP_codificar(mensagem, chave_publica, tam_hash, rotulo="", k=128):
    rotulo = rotulo.encode()

    if len(mensagem) > k - 2 * tam_hash - 2:
        raise ValueError("O conteúdo é muito grande para ser codificado com OAEP.")

    hash_func = hashlib.sha3_256
    l_hash = hash_func(rotulo).digest()
    db = formar_bloco_dados(l_hash, mensagem, k, tam_hash)
    seed = os.urandom(tam_hash)
    db_mask = mdf(seed, k - tam_hash - 1, hash_func)
    masked_db = bytes(xor(db, db_mask))
    seed_mask = mdf(masked_db, tam_hash, hash_func)
    masked_seed = bytes(xor(seed, seed_mask))
    mensagem_codificada = b"\x00" + masked_seed + masked_db

    return RSA_codificar(mensagem_codificada, chave_publica)


def OAEP_decodificar(mensagem_codificada, chave_privada, tam_hash, rotulo="", k=128):
    rotulo = rotulo.encode()
    mensagem_codificada = RSA_decodificar(list(mensagem_codificada), chave_privada)
    hash_func = hashlib.sha3_256
    l_hash = hash_func(rotulo).digest()

    if len(mensagem_codificada) != k:
        raise ValueError("O tamanho da mensagem cifrada está inadequado.")

    masked_seed = bytes(mensagem_codificada[1 : tam_hash + 1])
    masked_db = bytes(mensagem_codificada[tam_hash + 1 :])
    seed_mask = mdf(masked_db, tam_hash, hash_func)
    seed = bytes(xor(masked_seed, seed_mask))
    db_mask = mdf(seed, k - tam_hash - 1, hash_func)
    db = bytes(xor(masked_db, db_mask))
    l_hash_gen = db[:tam_hash]

    if l_hash_gen != l_hash:
        raise ValueError("O hash do rótulo na mensagem decifrada está errado.")

    inicio_mensagem = tam_hash + db[tam_hash:].find(b"\x01") + 1
    mensagem = db[inicio_mensagem:]

    return mensagem


def mdf(seed, tam_mascara, hash_func):
    if tam_mascara > 2**32 * hash_func().digest_size:
        raise ValueError("Tamanho da Máscara maior que o esperado.")

    T = bytearray()
    for contador in range(math.ceil(tam_mascara / hash_func().digest_size)):
        c = struct.pack(">I", contador)
        T += hash_func(seed + c).digest()

    return T[:tam_mascara]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def mdc_estendido(a, b):
    if b == 0:
        return a, 1, 0
    else:
        mdc, x, y = mdc_estendido(b, a % b)
        return mdc, y, x - (a // b) * y