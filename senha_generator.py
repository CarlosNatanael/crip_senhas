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
    
    dados = f"{servico} | {usuario} | {senha}"
    dados_bytes = dados.encode()

    chave = carregar_chave()
    fernet = Fernet(chave)
    dados_criptografados = fernet.encrypt(dados_bytes)

    with open("dados_senhas.dat", "ab") as arquivos:
        arquivos.write(dados_criptografados + b"\n")

    messagebox.showinfo("Sucesso","Senha salva com sucesso")
    entrada_servico.delete(0, tk.END)
    entrada_usuario.delete(0, tk.END)
    campo_senha.delete(0, tk.END)

# Salva senha-mestra criptografada
def definir_senha_master():
    def salvar():
        senha = entrada_senha.get()
        if not senha:
            messagebox.showwarning("Aviso", "Digite uma senha-mestra")
            return
        
        chave = carregar_chave()
        f = Fernet(chave)
        senha_cripto = f.encrypt(senha.encode())

        with open("Senha_admin.key", "wb") as f_senha:
            f_senha.write(senha_cripto)

        messagebox.showinfo("Sucesso", "Senha-mestra definida!")
        janela_definir.destroy()

    janela_definir = tk.Toplevel()
    janela_definir.title("Definir senha-mestra")
    janela_definir.geometry("300x150")

    tk.Label(janela_definir, text="Defina uma senha-mestra", font=("Arial", 10)).pack(pady=10)
    entrada_senha = tk.Entry(janela_definir, show="*", width=30)
    entrada_senha.pack()
    tk.Button(janela_definir, text="salvar", command=salvar).pack(pady=10)

# Verifica senha-mestra para acessar dados
def autenticador_admin():
    def verificar():
        senha_digitada = entrada.get()
        try:
            with open("senha_admin.key", "rb") as arq:
                senha_cripto = arq.read()
        except FileNotFoundError:
            messagebox.showerror("Erro", "Senha-mestre não definida!")
            janela_login.destroy()
            return
        
        chave = carregar_chave()
        f = Fernet(chave)
        try:
            senha_original = f.decrypt(senha_cripto).decode()
        except:
            messagebox.showerror("Erro", "Falha ao decodificar a senha!")
            return
        
        if senha_digitada == senha_original:
            janela_login.destroy()
            mostrar_dados_salvos()
        else:
            messagebox.showerror("Erro", "Senha incorreta")

    janela_login = tk.Toplevel()
    janela_login.title("Admin - Autenticação")
    janela_login.geometry("300x150")

    tk.Label(janela_login, text="Digite a senha-mestra", font=("Arial", 10)).pack(pady=10)
    entrada = tk.Entry(janela_login, show="*", width=30)
    entrada.pack()
    tk.Button(janela_login, text="Entrar", command=verificar).pack(pady=10)

# Função para mostrar os dados salvos
def mostrar_dados_salvos():
    try:
        with open("dados_senhas.dat", "rb") as arq:
            linhas = arq.readlines()
    except FileNotFoundError:
        messagebox.showinfo("Nada salvo", "Nenhuma senha salva ainda.")
        return

    chave = carregar_chave()
    f = Fernet(chave)

    janela_dados = tk.Toplevel()
    janela_dados.title("Senhas Salvas")
    janela_dados.geometry("600x400")

    frame_busca = tk.Frame(janela_dados)
    frame_busca.pack(pady=5)

    tk.Label(frame_busca, text="Buscar Serviço:", font=("Arial", 10)).pack(side="left")
    entrada_busca = tk.Entry(frame_busca, width=30)
    entrada_busca.pack(side="left", padx=5)

    frame_resultados = tk.Frame(janela_dados)
    frame_resultados.pack(fill="both", expand=True)

    def atualizar_resultados(filtro=""):
        for widget in frame_resultados.winfo_children():
            widget.destroy()

        for idx, linha in enumerate(linhas):
            try:
                decrypted = f.decrypt(linha.strip()).decode()
                if filtro.lower() not in decrypted.lower():
                    continue

                partes = decrypted.split(" | ")
                if len(partes) == 3:
                    servico, usuario, senha = partes
                    linha_frame = tk.Frame(frame_resultados)
                    linha_frame.pack(fill="x", padx=5, pady=2)

                    tk.Label(linha_frame, text=f"{servico} - {usuario}", font=("Arial", 10), width=35, anchor="w").pack(side="left")
                    tk.Button(linha_frame, text="Copiar Senha", command=lambda s=senha: copiar_para_area(s)).pack(side="left", padx=5)
                    tk.Button(linha_frame, text="Excluir", command=lambda i=idx: excluir_linha(i)).pack(side="left")
            except:
                continue

    def copiar_para_area(senha):
        janela_dados.clipboard_clear()
        janela_dados.clipboard_append(senha)
        messagebox.showinfo("Copiado", "Senha copiada para a área de transferência!")

    def excluir_linha(index):
        confirm = messagebox.askyesno("Confirmação", "Tem certeza que deseja excluir esta entrada?")
        if confirm:
            linhas.pop(index)
            with open("dados_senhas.dat", "wb") as arq:
                for l in linhas:
                    arq.write(l)
            atualizar_resultados(entrada_busca.get())

    entrada_busca.bind("<KeyRelease>", lambda e: atualizar_resultados(entrada_busca.get()))
    entrada_busca.pack(side="left", padx=5)


    atualizar_resultados()

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
janela.geometry("420x290")
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

#tk.Button(janela, text="Definir Senha-Mestra", font=("Arial", 10), command=definir_senha_master).pack(pady=10)
tk.Button(janela, text="Modo Administrador", font=("Arial", 10), command=autenticador_admin).pack(pady=10)

# Loop
janela.mainloop()