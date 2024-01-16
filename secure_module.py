from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import os
import platform


def obter_informacoes_cpu():
    system_info = platform.uname()
    return system_info.processor


caminho_chave = 'kip.txt'

with open('kip.txt', 'r') as arquivo_chave:
    chave_criptografia = arquivo_chave.read()


def validar_chave_licenca(nome_arquivo, chave_criptografia):

    # Ler a chave criptografada do arquivo
    # Crie um objeto Fernet com a chave de criptografia fornecida
    fernet = Fernet(chave_criptografia)
    with open(nome_arquivo, 'r') as arquivo_chave:
        info_cripy = arquivo_chave.read()

    # Descriptografe a chave
    chave_descriptografada = fernet.decrypt(info_cripy).decode()

    # Obter as informações da CPU
    cpu_info = obter_informacoes_cpu()

    # Extrair a parte da CPU da chave descriptografada (a parte antes do primeiro "_")
    partes_chave = chave_descriptografada
    chave_cpu = partes_chave

    # Comparar as informações da CPU com a parte da CPU da chave
    if cpu_info == chave_cpu:
        print("Chave de licença válida!")
        return True
    else:
        print("Chave de licença inválida!")
        return False


# Nome do arquivo onde a chave criptografada foi salva
nome_arquivo = "key.txt"
# A chave de criptografia deve ser a mesma que você usou para criptografar a chave de licença

validar_chave_licenca(nome_arquivo, chave_criptografia)
# Função para carregar a chave privada (pode ser chamada do código principal)


def load_private_key():
    if os.path.exists("private_key.pem"):
        with open("private_key.pem", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    else:
        raise FileNotFoundError("Arquivo 'private_key.pem' não encontrado.")


# Função para assinar o código


def sign_code(private_key, code):
    signature = private_key.sign(
        code,
        padding.PKCS1v15(),  # Especifica o algoritmo de preenchimento
        hashes.SHA256()
    )
    return signature

# Função para verificar a assinatura


def verify_signature(public_key, code, signature):
    try:
        public_key.verify(
            signature,
            code,
            padding.PKCS1v15(),  # Especifica o algoritmo de preenchimento
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


source_code = """
import atexit
import os
import time
import pandas as pd
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.select import Select
from secure_module import load_private_key, source_code, verify_signature, sign_code, validar_chave_licenca, nome_arquivo, chave_criptografia

private_key = load_private_key()
code_signature = sign_code(private_key, source_code.encode())

# Verificar a assinatura antes de executar o programa
public_key = private_key.public_key()
if not verify_signature(public_key, source_code.encode(), code_signature):
    print("Assinatura inválida. O código foi modificado ou corrompido.")
    exit(1)
# Inicialize o DataFrame vazio
df = pd.DataFrame()

# Função para salvar a planilha


def save_dataframe():
    global df
    if not df.empty:
        df.to_excel(os.path.join(base_folder, file_name), index=False)
        print("Planilha salva com sucesso!")


def update_progress(progress_file, last_processed_line):
    with open(progress_file, "w") as file:
        file.write(str(last_processed_line))


# Registrar a função para ser executada no término do programa
atexit.register(save_dataframe)


private_key = load_private_key()
code_signature = sign_code(private_key, source_code.encode())

# Verificar a assinatura antes de executar o programa
public_key = private_key.public_key()
if not verify_signature(public_key, source_code.encode(), code_signature):
    print("Assinatura inválida. O código foi modificado ou corrompido.")
    exit(1)
# Inicialize o DataFrame vazio
df = pd.DataFrame()

# Função para salvar a planilha


def save_dataframe():
    global df
    if not df.empty:
        df.to_excel(os.path.join(base_folder, file_name), index=False)
        print("Planilha salva com sucesso!")


def update_progress(progress_file, last_processed_line):
    with open(progress_file, "w") as file:
        file.write(str(last_processed_line))


# Registrar a função para ser executada no término do programa
atexit.register(save_dataframe)


def read_login_info():
    try:
        with open("login_info.txt", "r") as file:
            lines = file.read().splitlines()
            if len(lines) == 1:
                data = lines[0].split(',')
                if len(data) == 2:
                    username, password = data
                    return username, password
            print(
                "Arquivo login_info.txt deve conter uma única linha formatada como: Nome de Usuário,Senha")
    except FileNotFoundError:
        print("Arquivo login_info.txt não encontrado.")
    return None, None


if validar_chave_licenca(nome_arquivo, chave_criptografia):
    try:
        # Configurar as opções do Firefox
        firefox_options = webdriver.FirefoxOptions()

        # Inicialize o driver do Firefox com as opções configuradas
        driver = webdriver.Firefox(options=firefox_options)

        # Abra a página de login
        login_url = "https://v8sistema.com/auth/signin?callbackUrl=https%3A%2F%2Fv8sistema.com%2Fproposals%2Fsimulate"
        driver.get(login_url)

        # Função para fazer login
        username, password = read_login_info()

        def perform_login(username, password):
            time.sleep(1)
            user_input = driver.find_element(By.NAME, "user")
            password_input = driver.find_element(By.NAME, "password")
            user_input.send_keys(username)
            time.sleep(1.2)
            password_input.send_keys(password)
            login_button = driver.find_element(
                By.XPATH, "//button[contains(text(), 'Sign in')]")
            time.sleep(0.2)
            login_button.click()
            time.sleep(1.5)
            return "signin" not in driver.current_url

        # Repita o processo de login duas vezes
        for i in range(2):
            if perform_login(username, password):
                # Login bem-sucedido
                print(f"Login {i + 1} bem-sucedido.")
            else:
                print(
                    f"Login {i + 1} falhou. Verifique suas credenciais de login.")

        time.sleep(2)

        # Localize o campo de entrada de CPF
        select = Select(driver.find_element(By.NAME, "tables"))
        select.select_by_value("7")

        base_folder = "base"
        file_name = None
        for root, dirs, files in os.walk(base_folder):
            for file in files:
                if file.endswith(".xlsx"):
                    file_name = file
                    break

        # Verifique se há um arquivo de progresso salvo
        progress_file = "progress.txt"

        if os.path.exists(progress_file):
            # Se o arquivo de progresso existe, leia a linha onde a automação parou
            with open(progress_file, "r") as file:
                last_processed_line = int(file.read())
        else:
            # Se o arquivo de progresso não existe, comece do início
            last_processed_line = 0

        # Lê a planilha Excel
        df = pd.read_excel(os.path.join(base_folder, file_name))

        # Localize o campo de entrada de CPF
        cpf_input = driver.find_element(By.NAME, "cpf")

        # Localize o botão "Simular" pelo texto (pode variar)
        simular_button = driver.find_element(
            By.XPATH, "//button[contains(text(), 'Simular')]")

        # Loop para processar os CPFs da planilha, começando da última linha processada
        for index, row in df.iterrows():
            if index < last_processed_line:
                continue  # Pule linhas já processadas

            # Assuma que a coluna do CPF na planilha é chamada de 'cpf'
            cpf = str(row['cpf'])
            cpf_input.clear()
            cpf_input.send_keys(cpf)
            simular_button.click()
            time.sleep(2)  # Aguarde 2 segundos
            df.at[index, "Status"] = "consultado"
            last_processed_line = index
            update_progress(progress_file, last_processed_line)

            # Escreva o índice da linha atual no arquivo de progresso
            with open(progress_file, "w") as file:
                file.write(str(index))

        # Salve a planilha com as alterações
        df.to_excel(os.path.join(base_folder, file_name), index=False)

    except Exception as e:
        print(f"Erro inesperado: {e}")

    finally:
        save_dataframe()
        update_progress(progress_file, last_processed_line)

# Encerre o navegador
    driver.quit()

"""


private_key = load_private_key()
code_signature = sign_code(private_key, source_code.encode())

# Verificar a assinatura
public_key = private_key.public_key()
if verify_signature(public_key, source_code.encode(), code_signature):
    print("Assinatura válida. O código não foi modificado.")
else:
    print("Assinatura inválida. O código foi modificado ou corrompido.")
