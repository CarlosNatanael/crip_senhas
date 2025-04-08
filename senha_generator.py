import tkinter as tk
from tkinter import messagebox
import random
import string
import os
from cryptography.fernet import Fernet


# Gera chave crytografada
def gerar_chave():
    if not os.path.exists("chave.key"):
        chave = Fernet.generate_key()
        with open("chave.key","wb") as chave_arquivo:
            chave_arquivo.write(chave)

# Carrega as chaves criptografada
def carregar_chave():
    with open("chave.key","rb") as chave_arquivo:
        return chave_arquivo.read()
    
# Criptografa os dados salvos
def salvar_dados(servico, usuario, senha):
    if not servico or not usuario or not senha:
        messagebox.showwarning("Campo vazios","Preencha todos os campos!")
        return
    
    dados = f"Serviço: {servico}\nUsuario: {usuario}\nSenha: {senha}\n\n"
    dados_bytes = dados.encode()

    chave = carregar_chave()
    fernet = fernet(chave)
    dados_criptografados = fernet.encrypt(dados_bytes)

    with open("dados_senhas.dat", "ab") as arquivos:
        arquivos.write(dados_criptografados + b"\n")

    messagebox.showinfo("Sucesso","Senha salva com sucesso")
    entrada_servico.delete(0, tk.END)
    entrada_usuario.delete(0, tk.END)
    campo_senha.delete(0, tk.END)

def gerar_senha(tamanho=12):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    senha = ''.join(random.choice(caracteres) for _ in range(tamanho))
    return senha

def atualizar_senha():
    nova = gerar_senha()
    campo_senha.delete(0, tk.END)
    campo_senha.insert(0, nova)

gerar_chave()

# Cria a janela
janela = tk.Tk()
janela.title("Gerenciador de Senhas")
janela.geometry("420x300")
janela.resizable(False, False)

# Widgets
tk.Label(janela, text="Serviço:", font=("Arial", 10)).pack(pady=2)
entrada_servico = tk.Entry(janela, width=40, font=("Arial", 11))
entrada_servico.pack() 

tk.Label(janela, text="Usuário:", font=("Arial", 10)).pack(pady=2)
entrada_usuario = tk.Entry(janela, width=40, font=("Arial", 11))
entrada_usuario.pack()

tk.Label(janela, text="Senha:", font=("Arial", 10)).pack(pady=2)
campo_senha = tk.Entry(janela, width=40, font=("Arial", 11), justify="center")
campo_senha.pack()

tk.Button(janela, text="Gerar Senha", font=("Arial", 11), command=atualizar_senha).pack(pady=5)
tk.Button(janela, text="Salvar Senha", font=("Arial", 11), command=lambda: salvar_dados(
    entrada_servico.get(),
    entrada_usuario.get(),
    campo_senha.get()
)).pack(pady=5)

# Loop
janela.mainloop()