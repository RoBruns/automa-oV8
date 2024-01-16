# Flake8: noqa
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.select import Select
import pandas as pd
import glob
import time
import os
from pathlib import Path
import atexit
from secure_module import load_private_key, source_code, verify_signature, sign_code


def load_and_verify_key():
    try:
        private_key = load_private_key()
        public_key = private_key.public_key()
        code_signature = sign_code(private_key, source_code.encode())
        if not verify_signature(public_key, source_code.encode(), code_signature):
            print("Assinatura inválida. O código foi modificado ou corrompido.")
            exit(1)
    except FileNotFoundError as e:
        print(e)
        exit(1)
    except Exception as e:
        print(f"Erro ao processar a chave: {e}")
        exit(1)



def read_login_info():
    try:
        with open("login_info.txt", "r") as file:
            username, password = file.read().strip().split(',')
            return username, password
    except (FileNotFoundError, ValueError):
        print("Erro ao ler informações de login.")
        return None, None


def init_webdriver():
    chrome_options = Options()
    driver = webdriver.Chrome(options=chrome_options)
    return driver


def perform_login(driver, username, password):
    max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        try:
            driver.get("https://v8sistema.com/auth/signin?callbackUrl=https%3A%2F%2Fv8sistema.com%2Fproposals%2Fsimulate")
            user_input = driver.find_element(By.NAME, "user")
            password_input = driver.find_element(By.NAME, "password")
            user_input.send_keys(username)
            password_input.send_keys(password)
            login_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Sign in')]")
            login_button.click()
            time.sleep(1)

            if "signin" not in driver.current_url:
                print(f"Login {attempt} bem-sucedido.")
                return True
            else:
                print(f"Login {attempt} falhou. Tentando novamente.")
        except Exception as e:
            print(f"Erro durante o login {attempt}: {e}")
            if attempt == max_attempts:
                return False
            time.sleep(1)  # Pausa antes de tentar novamente

    return False


def load_last_processed_line():
    progress_file = "progress.txt"
    if os.path.exists(progress_file):
        with open(progress_file, "r") as file:
            return int(file.read())
    return 0       


def is_valid_cpf(cpf):
    if not cpf.isdigit() or len(cpf) != 11:
        return False
    
    cpf = list(map(int, cpf))
    d1 = sum(cpf[i] * (10 - i) for i in range(9)) % 11
    d1 = 0 if d1 < 2 else 11 - d1
    d2 = sum(cpf[i] * (11 - i) for i in range(10)) % 11
    d2 = 0 if d2 < 2 else 11 - d2
    
    return cpf[9] == d1 and cpf[10] == d2


def process_cpf(driver, df, excel_file):
    progress_file = "progress.txt"
    last_processed_line = load_last_processed_line()

    try:
        select_bank = Select(driver.find_element(By.NAME, "averbador"))
        select_bank.select_by_value("qi")
        select = Select(driver.find_element(By.NAME, "tables"))
        select.select_by_value("10")
        cpf_input = driver.find_element(By.NAME, "cpf")
        simular_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Simular')]")

        for index, row in df.iterrows():
            if index < last_processed_line:
                continue

            cpf = str(row['cpf'])  # Converte o valor do CPF para uma string
            
            # Remove qualquer ".0" no final do CPF
            cpf = cpf.rstrip('.0')
            
            # Verifica se o CPF é válido
            if not is_valid_cpf(cpf):
                print(f"CPF inválido: {cpf}. Pulando para a próxima iteração.")
                update_progress(index)  # Atualiza o progresso mesmo para CPFs inválidos
                continue
            
            cpf_input.clear()
            cpf_input.send_keys(cpf)
            simular_button.click()
            time.sleep(2)
            
            df.at[index, "Status"] = str("consultado")
            last_processed_line = index  
            update_progress(last_processed_line)  

        save_dataframe(df, excel_file)

    except Exception as e:
        print(f"Erro ao processar CPFs: {e}")
        update_progress(last_processed_line)  
        
    update_progress(last_processed_line) 

def update_progress(last_processed_line):
    with open("progress.txt", "w") as file:
        file.write(str(last_processed_line))


def save_dataframe(df, excel_file):
    if not df.empty:
        df.to_excel(excel_file, index=False)
        print("Planilha salva com sucesso!")


def find_excel_file(folder_path):
    list_of_files = glob.glob(os.path.join(folder_path, '*.xlsx'))  # Lista todos os arquivos .xlsx
    if not list_of_files:
        print("Nenhum arquivo .xlsx encontrado.")
        return None

    latest_file = max(list_of_files, key=os.path.getmtime)
    return latest_file


def main():
    load_and_verify_key()
    driver = init_webdriver()
    username, password = read_login_info()

    if not perform_login(driver, username, password):
        print("Falha no login. Encerrando.")
        return
    
    base_folder = "base"
    excel_file = find_excel_file(base_folder)
    
    if excel_file is None:
        print("Nenhum arquivo Excel para processar.")
        return
    
    df = pd.read_excel(excel_file)
    progress_file = os.path.join(base_folder, "progress.txt")
    process_cpf(driver, df, excel_file)
    driver.quit()


atexit.register(main)
