import base64
from C00_hash_oaep_rsa_arquivo import *

arquivo_original_a_ser_assinado     = "mensagem_original.txt"
arquivo_alterado_para_comparacao    = "mensagem_alterada.txt"

def main():

    
    #   _                    _                               _            
    #  | |                  | |                             (_)           
    #  | |     ___ _ __   __| | ___     __ _ _ __ __ _ _   _ ___   _____  
    #  | |    / _ \ '_ \ / _` |/ _ \   / _` | '__/ _` | | | | \ \ / / _ \ 
    #  | |___|  __/ | | | (_| | (_) | | (_| | | | (_| | |_| | |\ V / (_) |
    #  |______\___|_| |_|\__,_|\___/   \__,_|_|  \__, |\__,_|_| \_/ \___/ 
    #                                               | |                   
    #                                               |_|                   
    print("\n=============== Lendo arquivo para assinar")
    mensagem = ler_arquivo_modo_binario(arquivo_original_a_ser_assinado)
    print("\nConteudo do arquivo:",mensagem)


    #    _____                          _          _____ _                          
    #   / ____|                        | |        / ____| |                         
    #  | |  __  ___ _ __ __ _ _ __   __| | ___   | |    | |__   __ ___   _____  ___ 
    #  | | |_ |/ _ \ '__/ _` | '_ \ / _` |/ _ \  | |    | '_ \ / _` \ \ / / _ \/ __|
    #  | |__| |  __/ | | (_| | | | | (_| | (_) | | |____| | | | (_| |\ V /  __/\__ \
    #   \_____|\___|_|  \__,_|_| |_|\__,_|\___/   \_____|_| |_|\__,_| \_/ \___||___/
    print("\n=============== Criando Pub-KEY e a Priv-KEY.")
    chave_publica, chave_privada, tam_hash = gerar_chaves()
    print("Pub-KEY: ", chave_publica)
    print("Priv-KEY: ", chave_privada)

        
    #    _____ _  __                     _         _____   _____               ____          ______ _____  
    #   / ____(_)/ _|                   | |       |  __ \ / ____|  /\         / __ \   /\   |  ____|  __ \ 
    #  | |     _| |_ _ __ __ _ _ __   __| | ___   | |__) | (___   /  \ ______| |  | | /  \  | |__  | |__) |
    #  | |    | |  _| '__/ _` | '_ \ / _` |/ _ \  |  _  / \___ \ / /\ \______| |  | |/ /\ \ |  __| |  ___/ 
    #  | |____| | | | | | (_| | | | | (_| | (_) | | | \ \ ____) / ____ \     | |__| / ____ \| |____| |     
    #   \_____|_|_| |_|  \__,_|_| |_|\__,_|\___/  |_|  \_\_____/_/    \_\     \____/_/    \_\______|_|     
    mensagem_cifrada = OAEP_codificar(mensagem, chave_publica, tam_hash)
    # print("\n=============== Dados criptografados: \n", mensagem_cifrada, "\n")


    #   _____            _  __                     _         _____   _____               ____          ______ _____  
    #  |  __ \          (_)/ _|                   | |       |  __ \ / ____|  /\         / __ \   /\   |  ____|  __ \ 
    #  | |  | | ___  ___ _| |_ _ __ __ _ _ __   __| | ___   | |__) | (___   /  \ ______| |  | | /  \  | |__  | |__) |
    #  | |  | |/ _ \/ __| |  _| '__/ _` | '_ \ / _` |/ _ \  |  _  / \___ \ / /\ \______| |  | |/ /\ \ |  __| |  ___/ 
    #  | |__| |  __/ (__| | | | | | (_| | | | | (_| | (_) | | | \ \ ____) / ____ \     | |__| / ____ \| |____| |     
    #  |_____/ \___|\___|_|_| |_|  \__,_|_| |_|\__,_|\___/  |_|  \_\_____/_/    \_\     \____/_/    \_\______|_|     
    mensagem_decifrada = OAEP_decodificar(mensagem_cifrada, chave_privada, tam_hash)
    print("\n=============== Dados descriptografados: ", mensagem_decifrada)
    

    #   _    _           _     _                 __      _           ____   __  
    #  | |  | |         | |   (_)               / /     | |         |___ \  \ \ 
    #  | |__| | __ _ ___| |__  _ _ __   __ _   | |   ___| |__   __ _  __) |  | |
    #  |  __  |/ _` / __| '_ \| | '_ \ / _` |  | |  / __| '_ \ / _` ||__ <   | |
    #  | |  | | (_| \__ \ | | | | | | | (_| |  | |  \__ \ | | | (_| |___) |  | |
    #  |_|  |_|\__,_|___/_| |_|_|_| |_|\__, |  | |  |___/_| |_|\__,_|____/   | |
    #                                   __/ |   \_\                         /_/ 
    #                                  |___/                                    
    hash_sha3 = hashlib.sha3_256(mensagem).digest()
    print("\n=============== Hasheando os dados (sha3)")


    #    _____ _  __                     _                   _    _           _     
    #   / ____(_)/ _|                   | |                 | |  | |         | |    
    #  | |     _| |_ _ __ __ _ _ __   __| | ___      ___    | |__| | __ _ ___| |__  
    #  | |    | |  _| '__/ _` | '_ \ / _` |/ _ \    / _ \   |  __  |/ _` / __| '_ \ 
    #  | |____| | | | | | (_| | | | | (_| | (_) |  | (_) |  | |  | | (_| \__ \ | | |
    #   \_____|_|_| |_|  \__,_|_| |_|\__,_|\___/    \___/   |_|  |_|\__,_|___/_| |_|
    assinatura_mensagem = OAEP_codificar(hash_sha3, chave_publica, tam_hash)
    print("\n=============== Cifrando os dados hasheados")
    
    
    
    #   ______                         _                        ____                     __ _  _   
    #  |  ____|                       | |                      |  _ \                   / /| || |  
    #  | |__ ___  _ __ _ __ ___   __ _| |_ __ _ _ __   ______  | |_) | __ _ ___  ___   / /_| || |_ 
    #  |  __/ _ \| '__| '_ ` _ \ / _` | __/ _` | '__| |______| |  _ < / _` / __|/ _ \ | '_ \__   _|
    #  | | | (_) | |  | | | | | | (_| | || (_| | |             | |_) | (_| \__ \  __/ | (_) | | |  
    #  |_|  \___/|_|  |_| |_| |_|\__,_|\__\__,_|_|             |____/ \__,_|___/\___|  \___/  |_|  
    b64_mensagem_codificada = base64.b64encode(dumps(assinatura_mensagem))
    print("\n=============== Formatando com base64")



    
    #   _                    _             _           _                           _                 _           
    #  | |                  | |           | |         | |                         (_)               | |          
    #  | |     ___ _ __   __| | ___     __| | __ _  __| | ___  ___    __ _ ___ ___ _ _ __   __ _  __| | ___  ___ 
    #  | |    / _ \ '_ \ / _` |/ _ \   / _` |/ _` |/ _` |/ _ \/ __|  / _` / __/ __| | '_ \ / _` |/ _` |/ _ \/ __|
    #  | |___|  __/ | | | (_| | (_) | | (_| | (_| | (_| | (_) \__ \ | (_| \__ \__ \ | | | | (_| | (_| | (_) \__ \
    #  |______\___|_| |_|\__,_|\___/   \__,_|\__,_|\__,_|\___/|___/  \__,_|___/___/_|_| |_|\__,_|\__,_|\___/|___/
    b64_mensagem_decodificada = base64.b64decode(b64_mensagem_codificada) #desformatando o base64
    assinatura_mensagem = loads(b64_mensagem_decodificada)
    print("\n=============== Desformatando o base64")

    
    #   _____            _  __                          _    _           _     
    #  |  __ \          (_)/ _|                        | |  | |         | |    
    #  | |  | | ___  ___ _| |_ _ __ __ _ _ __    ___   | |__| | __ _ ___| |__  
    #  | |  | |/ _ \/ __| |  _| '__/ _` | '__|  / _ \  |  __  |/ _` / __| '_ \ 
    #  | |__| |  __/ (__| | | | | | (_| | |    | (_) | | |  | | (_| \__ \ | | |
    #  |_____/ \___|\___|_|_| |_|  \__,_|_|     \___/  |_|  |_|\__,_|___/_| |_|
    hash_decifrado = OAEP_decodificar(assinatura_mensagem, chave_privada, tam_hash)
    print("\n=============== Decifrando o Hash")

    
    
    

    #    _____ _                                            _             _                               ____       _       _             _ 
    #   / ____| |                             /\           (_)           | |                             / __ \     (_)     (_)           | |
    #  | |    | |__   ___  ___ __ _ _ __     /  \   ___ ___ _ _ __   __ _| |_ _   _ _ __ __ _   ______  | |  | |_ __ _  __ _ _ _ __   __ _| |
    #  | |    | '_ \ / _ \/ __/ _` | '__|   / /\ \ / __/ __| | '_ \ / _` | __| | | | '__/ _` | |______| | |  | | '__| |/ _` | | '_ \ / _` | |
    #  | |____| | | |  __/ (_| (_| | |     / ____ \\__ \__ \ | | | | (_| | |_| |_| | | | (_| |          | |__| | |  | | (_| | | | | | (_| | |
    #   \_____|_| |_|\___|\___\__,_|_|    /_/    \_\___/___/_|_| |_|\__,_|\__|\__,_|_|  \__,_|           \____/|_|  |_|\__, |_|_| |_|\__,_|_|
    #                                                                                                                   __/ |                
    #                                                                                                                  |___/                 
    # Mensagem original
    dado_arquivo_original = ler_arquivo_modo_binario(arquivo_original_a_ser_assinado)
    print("\n=============== Checando arquivo ORIGINAL")
    checar_assinatura( hashlib.sha3_256(dado_arquivo_original).digest(), hash_decifrado)


    #    _____ _                                            _             _                              __  __           _ _  __ _               _       
    #   / ____| |                             /\           (_)           | |                            |  \/  |         | (_)/ _(_)             | |      
    #  | |    | |__   ___  ___ __ _ _ __     /  \   ___ ___ _ _ __   __ _| |_ _   _ _ __ __ _   ______  | \  / | ___   __| |_| |_ _  ___ __ _  __| | ___  
    #  | |    | '_ \ / _ \/ __/ _` | '__|   / /\ \ / __/ __| | '_ \ / _` | __| | | | '__/ _` | |______| | |\/| |/ _ \ / _` | |  _| |/ __/ _` |/ _` |/ _ \ 
    #  | |____| | | |  __/ (_| (_| | |     / ____ \\__ \__ \ | | | | (_| | |_| |_| | | | (_| |          | |  | | (_) | (_| | | | | | (_| (_| | (_| | (_) |
    #   \_____|_| |_|\___|\___\__,_|_|    /_/    \_\___/___/_|_| |_|\__,_|\__|\__,_|_|  \__,_|          |_|  |_|\___/ \__,_|_|_| |_|\___\__,_|\__,_|\___/ 
    # Arquivo Modificado
    dado_arquivo_modificado = ler_arquivo_modo_binario(arquivo_alterado_para_comparacao)
    print("\n=============== Checando arquivo MODIFICADO")
    checar_assinatura( hashlib.sha3_256(dado_arquivo_modificado).digest(), hash_decifrado)

    return

main()