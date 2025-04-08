import tkinter as tk
from tkinter import messagebox
import random
import string
import os
from cryptography.fernet import Fernet
from PIL import Image, ImageTk


tema_claro = {
    "bg": "#f0f0f0",
    "fg": "#000000",
    "entry_bg": "#ffffff",
    "entry_fg": "#000000",
    "btn_bg": "#e0e0e0",
    "btn_fg": "#000000",
    "btn_hover": "#d0d0d0"
}

tema_escuro = {
    "bg": "#2b2b2b",
    "fg": "#ffffff",
    "entry_bg": "#353535",
    "entry_fg": "#ffffff",
    "btn_bg": "#3c3f41",
    "btn_fg": "#ffffff",
    "btn_hover": "#4b4f51"
}

tema_atual = tema_escuro
widgets_estilizados = []

janelas_secundarias = []

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
    janelas_secundarias.append(janela_definir)

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
    janela_login.iconbitmap('img\imagem.ico')
    janela_login.geometry("300x150")
    janelas_secundarias.append(janela_login)


    tk.Label(janela_login, text="Digite a senha-mestra", font=("Arial", 10)).pack(pady=10)
    entrada = tk.Entry(janela_login, show="*", width=30)
    entrada.pack()
    tk.Button(janela_login, text="Entrar", command=verificar).pack(pady=10)

# Função para mostrar os dados salvos
def mostrar_dados_salvos():
    if not autenticador_admin():
        return
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
    janela_dados.iconbitmap('img\imagem.ico')
    janela_dados.geometry("600x400")
    janelas_secundarias.append(janela_dados)


    frame_busca = tk.Frame(janela_dados)
    frame_busca.pack(pady=5)

    lbl_busca = tk.Label(janela_dados, text="Buscar Serviço:", bg=tema_atual["bg"], fg=tema_atual["fg"])
    lbl_busca.pack(pady=(10, 0))
    lbl_dica = tk.Label(janela_dados, text="(A busca é automática enquanto digita)", font=("Arial", 8), bg=tema_atual["bg"], fg=tema_atual["fg"])
    lbl_dica.pack(pady=(0, 10))
    entrada_busca = tk.Entry(janela_dados, width=40, bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
    entrada_busca.pack()

    frame_senhas = tk.Frame(janela_dados, bg=tema_atual["bg"])
    frame_senhas.pack()

    def exibir_dados():
        for widget in frame_senhas.winfo_children():
            widget.destroy()
        dados = carregar_dados()
        termo = entrada_busca.get().lower()

        for servico, info in dados.items():
            if termo in servico.lower():
                frame_linha = tk.Frame(frame_senhas, bg=tema_atual["bg"])
                frame_linha.pack(pady=5, fill='x', padx=10)

                texto = f"{servico} - {info['usuario']}"
                lbl = tk.Label(frame_linha, text=texto, bg=tema_atual["bg"], fg=tema_atual["fg"], anchor='w')
                lbl.pack(side='left', padx=5)

                btn_copiar = tk.Button(frame_linha, text="Copiar Senha", bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"], activebackground=tema_atual["btn_hover"], command=lambda s=info['senha']: copiar_senha(s))
                btn_copiar.pack(side='right', padx=5)

                btn_excluir = tk.Button(frame_linha, text="Excluir", bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"], activebackground=tema_atual["btn_hover"], command=lambda s=servico: excluir_entrada(s, exibir_dados))
                btn_excluir.pack(side='right')

    entrada_busca.bind("<KeyRelease>", lambda e: exibir_dados())
    exibir_dados()

    def atualizar_resultados(filtro=""):
        for widget in frame_senhas.winfo_children():
            widget.destroy()

        for idx, linha in enumerate(linhas):
            try:
                decrypted = f.decrypt(linha.strip()).decode()
                if filtro.lower() not in decrypted.lower():
                    continue

                partes = decrypted.split(" | ")
                if len(partes) == 3:
                    servico, usuario, senha = partes
                    linha_frame = tk.Frame(frame_senhas)
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

def alternar_tema():
    global tema_atual, modo_escuro
    modo_escuro = not modo_escuro
    tema_atual = tema_escuro if modo_escuro else tema_claro
    aplicar_tema()

    novo_icone = icone_lua if modo_escuro else icone_sol
    botao_tema.config(image=novo_icone, bg='white' if not modo_escuro else '#2e2e2e',
                      activebackground='white' if not modo_escuro else '#2e2e2e')
    botao_tema.image = novo_icone

def aplicar_tema():
    # Aplica tema na janela principal
    janela.configure(bg=tema_atual["bg"])
    for widget in widgets_estilizados:
        if isinstance(widget, tk.Entry):
            widget.configure(bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
        elif isinstance(widget, tk.Label):
            widget.configure(bg=tema_atual["bg"], fg=tema_atual["fg"])
        elif isinstance(widget, tk.Button):
            widget.configure(bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"], activebackground=tema_atual["btn_hover"])

    # Aplica tema em cada janela secundária
    for janela_sec in janelas_secundarias:
        try:
            janela_sec.configure(bg=tema_atual["bg"])
            for widget in janela_sec.winfo_children():
                if isinstance(widget, tk.Entry):
                    widget.configure(bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
                elif isinstance(widget, tk.Label):
                    widget.configure(bg=tema_atual["bg"], fg=tema_atual["fg"])
                elif isinstance(widget, tk.Button):
                    widget.configure(bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"], activebackground=tema_atual["btn_hover"])
        except:
            pass  # Evita erro se a janela foi fechada


gerar_chave()

janela = tk.Tk()
janela.title("Gerenciador de Senhas")
janela.geometry("450x300")
janela.iconbitmap('img\imagem.ico')
janela.resizable(False, False)

label1 = tk.Label(janela, text="Serviço:", font=("Arial", 10))
label1.pack(pady=2)
entrada_servico = tk.Entry(janela, width=40, font=("Arial", 11))
entrada_servico.pack()

label2 = tk.Label(janela, text="Usuário:", font=("Arial", 10))
label2.pack(pady=2)
entrada_usuario = tk.Entry(janela, width=40, font=("Arial", 11))
entrada_usuario.pack()

label3 = tk.Label(janela, text="Senha:", font=("Arial", 10))
label3.pack(pady=2)
campo_senha = tk.Entry(janela, width=40, font=("Arial", 11), justify="center")
campo_senha.pack()

botao_gerar = tk.Button(janela, text="Gerar Senha", font=("Arial", 11), command=atualizar_senha)
botao_gerar.pack(pady=5)

botao_salvar = tk.Button(janela, text="Salvar Senha", font=("Arial", 11), command=lambda: salvar_dados(
    entrada_servico.get(), entrada_usuario.get(), campo_senha.get()))
botao_salvar.pack(pady=5)

#tk.Button(janela, text="Definir Senha-Mestra", font=("Arial", 10), command=definir_senha_master).pack(pady=10)
botao_admin = tk.Button(janela, text="Modo Administrador", font=("Arial", 10), command=autenticador_admin)
botao_admin.pack(pady=10)

# botao_tema = tk.Button(janela, text="Alternar Tema", font=("Arial", 10), command=alternar_tema)
# botao_tema.pack(pady=5)

modo_escuro = tema_atual == tema_escuro

icone_sol_pil = Image.open("img\imagem_sol.jpg").resize((32, 32))  # Redimensiona
icone_sol = ImageTk.PhotoImage(icone_sol_pil)

icone_lua_pil = Image.open("img\imagem_lua.jpg").resize((32, 32))
icone_lua = ImageTk.PhotoImage(icone_lua_pil)
icone_atual = icone_sol if not modo_escuro else icone_lua

botao_gerar.pack(pady=5)
botao_salvar.pack(pady=5)
botao_admin.pack(pady=5)

botao_tema = tk.Button(janela, image=icone_lua, command=alternar_tema, bd=0, bg="#2d2d2d", activebackground="#2d2d2d")
botao_tema.pack(pady=5)

widgets_estilizados.extend([
    label1, entrada_servico,
    label2, entrada_usuario,
    label3, campo_senha,
    botao_gerar, botao_salvar,
    botao_admin, botao_tema
])

aplicar_tema()

janela.mainloop()