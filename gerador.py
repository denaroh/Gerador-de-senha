import random
import string
import uuid
import bcrypt
import psycopg2
from psycopg2 import sql
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Função para gerar senhas
def gerar_senha(tamanho=12, caracteres_especiais=True):
    caracteres = string.ascii_letters + string.digits
    if caracteres_especiais:
        caracteres += string.punctuation
    
    senha = ''.join(random.choice(caracteres) for i in range(tamanho))
    return senha

# Função para criptografar a senha
def criptografar_senha(senha):
    salt = bcrypt.gensalt()
    senha_criptografada = bcrypt.hashpw(senha.encode(), salt)
    return senha_criptografada

# Função para conectar ao banco de dados PostgreSQL
def conectar_bd_postgres():
    conn = psycopg2.connect(
        dbname='gerador_senhas',
        user='postgres',
        password='123456',
        host='localhost',
        port='5432'
    )
    return conn

# Função para inserir senha no banco de dados PostgreSQL
def inserir_senha_postgres(senha, local, criptografada=False):
    conn = conectar_bd_postgres()
    cursor = conn.cursor()

    # Verificar se o local já existe na base de dados
    cursor.execute("SELECT COUNT(*) FROM senhas WHERE local = %s", (local,))
    existe_local = cursor.fetchone()[0] > 0
    if existe_local:
        print(f"{Fore.YELLOW}Já existe uma senha para este local.{Style.RESET_ALL}")
        return None
    
    senha_original = senha
    if criptografada:
        senha = criptografar_senha(senha).decode('utf-8')
    
    token = str(uuid.uuid4())
    query = sql.SQL("INSERT INTO senhas (senha_original, senha_criptografada, token, local) VALUES (%s, %s, %s, %s)")
    cursor.execute(query, [senha_original, senha, token, local])
    conn.commit()
    cursor.close()
    conn.close()

    return token

# Função para listar todas as senhas do banco de dados PostgreSQL
def listar_senhas_postgres():
    conn = conectar_bd_postgres()
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha_original, token, local FROM senhas")
    senhas = cursor.fetchall()
    cursor.close()
    conn.close()
    return senhas

# Função para conectar ao banco de dados de texto
def conectar_bd_txt(arquivo):
    try:
        with open(arquivo, 'r') as file:
            senhas = [linha.strip().split(',') for linha in file.readlines()]
        return senhas
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo não encontrado.{Style.RESET_ALL}")
        return []

# Função para inserir senha no banco de dados de texto
def inserir_senha_txt(senha, local):
    with open("senhas.txt", 'a') as file:
        file.write(f"{senha},{local}\n")
    print(f"{Fore.GREEN}Senha inserida com sucesso no arquivo!{Style.RESET_ALL}")

# Função para listar todas as senhas do banco de dados de texto
def listar_senhas_txt():
    try:
        with open("senhas.txt", 'r') as file:
            senhas = [linha.strip().split(',') for linha in file.readlines()]
        return senhas
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo não encontrado.{Style.RESET_ALL}")
        return []

# Função para visualizar senhas (restrito por senha de admin)
def visualizar_senhas(senha_admin):
    if senha_admin != "naotemsenha":
        print(f"\n{Fore.RED}Acesso não autorizado!{Style.RESET_ALL}")
        return
    
    senhas = listar_senhas_postgres() # Alterado para listar senhas do banco de dados PostgreSQL
    print(f"\n{Fore.CYAN}ID\t| Senha Original\t| Token\t\t\t\t| Local{Style.RESET_ALL}")
    print("-" * 90)
    for senha in senhas:
        print(f"{senha[0]}\t| {senha[1]}\t\t| {senha[2]}\t| {senha[3]}")

# Função para excluir uma senha pelo ID
def excluir_senha_por_id(id_senha, senha_admin):
    if senha_admin != "naotemsenha":
        print(f"\n{Fore.RED}Acesso não autorizado! É necessário a senha de administração para excluir senhas.{Style.RESET_ALL}")
        return
    
    conn = conectar_bd_postgres()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM senhas WHERE id = %s", (id_senha,))
    conn.commit()
    cursor.close()
    conn.close()
    print(f"\n{Fore.GREEN}Senha excluída com sucesso!{Style.RESET_ALL}")

# Menu para escolher tipo de conexão
def menu_escolher_conexao():
    print(f"\n{Fore.CYAN}CONEXÃO{Style.RESET_ALL}")
    print("-" * 20)
    opcao = input("Escolha uma opção (1: PostgreSQL, 2: Arquivo de texto): ")
    if opcao == '1':
        return "postgres"
    elif opcao == '2':
        return "txt"
    else:
        print(f"\n{Fore.RED}Opção inválida! Por favor, escolha uma opção válida.{Style.RESET_ALL}")
        return None

# Menu para escolher tipo de senha
def menu_gerar_senha(conexao):
    print(f"\n{Fore.CYAN}GERAR SENHA{Style.RESET_ALL}")
    print("-" * 20)
    tipo = input("Escolha o tipo de senha (1: Inserir própria senha, 2: Gerar aleatoriamente): ")
    local = input("Digite o local onde a senha será utilizada: ")
    if tipo == '1':
        senha = input("Digite a senha: ")
    elif tipo == '2':
        tamanho = int(input("Digite o tamanho da senha: "))
        caracteres_especiais = input("Incluir caracteres especiais? (s/n): ").lower() == 's'
        senha = gerar_senha(tamanho, caracteres_especiais)

    if conexao == "postgres":
        criptografada = input("Deseja criptografar a senha? (s/n): ").lower() == 's'
        token = inserir_senha_postgres(senha, local, criptografada=criptografada)
        if token:
            print(f"\n{Fore.GREEN}Senha inserida com sucesso! Token gerado: {token}{Style.RESET_ALL}")
    elif conexao == "txt":
        inserir_senha_txt(senha, local)

# Menu para gerenciar senhas
def menu_gerenciar_senhas(conexao):
    print(f"\n{Fore.CYAN}GERENCIAR SENHAS{Style.RESET_ALL}")
    print("-" * 20)
    opcao = input("Escolha uma opção (1: Visualizar senhas, 2: Excluir senha por ID): ")
    if opcao == '1':
        senha_admin = input("Digite a senha de administração: ")
        visualizar_senhas(senha_admin)
    elif opcao == '2':
        id_senha = int(input("Digite o ID da senha que deseja excluir: "))
        senha_admin = input("Digite a senha de administração: ")
        excluir_senha_por_id(id_senha, senha_admin)

# Executar o menu
if __name__ == "__main__":
    conexao = None
    while conexao is None:
        conexao = menu_escolher_conexao()

    while True:
        print(f"\n{Fore.CYAN}MENU{Style.RESET_ALL}")
        print("-" * 20)
        opcao = input("Escolha uma opção (1: Gerar senha, 2: Gerenciar senhas, 3: Sair): ")
        if opcao == '1':
            menu_gerar_senha(conexao)
        elif opcao == '2':
            menu_gerenciar_senhas(conexao)
        elif opcao == '3':
            print("\nEncerrando o programa...")
            break
        else:
            print(f"\n{Fore.RED}Opção inválida! Por favor, escolha uma opção válida.{Style.RESET_ALL}")
