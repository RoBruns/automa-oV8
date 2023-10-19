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
