import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import os
from cryptography.fernet import Fernet
from PIL import Image, ImageTk

# ============ Configurações de Tema ============
tema_claro = {
    "bg": "#f5f5f5",
    "fg": "#333333",
    "entry_bg": "#ffffff",
    "entry_fg": "#000000",
    "btn_bg": "#2b83a1",
    "btn_fg": "#ffffff",
    "btn_hover": "#0b495e",
    "frame_bg": "#e0e0e0",
    "highlight": "#2196F3"
}

tema_escuro = {
    "bg": "#2b2b2b",
    "fg": "#e0e0e0",
    "entry_bg": "#424242",
    "entry_fg": "#ffffff",
    "btn_bg": "#2b83a1",
    "btn_fg": "#ffffff",
    "btn_hover": "#0b495e",
    "frame_bg": "#424242",
    "highlight": "#0D47A1"
}

tema_atual = tema_escuro
modo_escuro = True
widgets_estilizados = []
janelas_secundarias = []

# ============ Funções de Criptografia ============
def gerar_chave():
    if not os.path.exists("chave.key"):
        chave = Fernet.generate_key()
        with open("chave.key","wb") as chave_arquivo:
            chave_arquivo.write(chave)

def carregar_chave():
    with open("chave.key","rb") as chave_arquivo:
        return chave_arquivo.read()

# ============ Funções Principais ============
def salvar_dados():
    servico = entrada_servico.get()
    usuario = entrada_usuario.get()
    senha = campo_senha.get()
    
    if not servico or not usuario or not senha:
        messagebox.showwarning("Campos Vazios", "Preencha todos os campos!")
        return
    
    dados = f"{servico} | {usuario} | {senha}"
    dados_bytes = dados.encode()

    chave = carregar_chave()
    fernet = Fernet(chave)
    dados_criptografados = fernet.encrypt(dados_bytes)

    with open("dados_senhas.dat", "ab") as arquivos:
        arquivos.write(dados_criptografados + b"\n")

    messagebox.showinfo("Sucesso", "Senha salva com sucesso!")
    entrada_servico.delete(0, tk.END)
    entrada_usuario.delete(0, tk.END)
    campo_senha.delete(0, tk.END)

def definir_senha_master():
    def salvar():
        senha = entrada_senha.get()
        confirmacao = entrada_confirmacao.get()
        
        if not senha or not confirmacao:
            messagebox.showwarning("Aviso", "Preencha ambos os campos!")
            return
            
        if senha != confirmacao:
            messagebox.showwarning("Aviso", "As senhas não coincidem!")
            return
            
        chave = carregar_chave()
        f = Fernet(chave)
        senha_cripto = f.encrypt(senha.encode())

        with open("senha_admin.key", "wb") as f_senha:
            f_senha.write(senha_cripto)

        messagebox.showinfo("Sucesso", "Senha-mestra definida com sucesso!")
        janela_definir.destroy()

    janela_definir = tk.Toplevel()
    janela_definir.title("Definir Senha-Mestra")
    janela_definir.geometry("350x200")
    janela_definir.iconbitmap('icone.ico')
    janela_definir.resizable(False, False)
    janelas_secundarias.append(janela_definir)
    
    frame = tk.Frame(janela_definir, bg=tema_atual["frame_bg"], padx=20, pady=20)
    frame.pack(fill="both", expand=True)
    
    tk.Label(frame, text="Defina sua senha-mestra", font=("Arial", 12, "bold"), 
             bg=tema_atual["frame_bg"], fg=tema_atual["fg"]).pack(pady=(0, 10))
    
    tk.Label(frame, text="Nova Senha:", bg=tema_atual["frame_bg"], fg=tema_atual["fg"]).pack(anchor="w")
    entrada_senha = tk.Entry(frame, show="*", width=30, bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
    entrada_senha.pack(pady=(0, 10))
    
    tk.Label(frame, text="Confirme a Senha:", bg=tema_atual["frame_bg"], fg=tema_atual["fg"]).pack(anchor="w")
    entrada_confirmacao = tk.Entry(frame, show="*", width=30, bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
    entrada_confirmacao.pack(pady=(0, 15))
    
    btn_salvar = tk.Button(frame, text="Salvar", command=salvar, bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                          activebackground=tema_atual["btn_hover"], width=15)
    btn_salvar.pack()
    
    aplicar_tema()

def autenticador_admin():
    if not os.path.exists("senha_admin.key"):
        messagebox.showinfo("Senha Master", "Você precisa definir uma senha master primeiro.")
        definir_senha_master()
        return
    
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
            messagebox.showerror("Erro", "Senha incorreta!")
            entrada.delete(0, tk.END)

    janela_login = tk.Toplevel()
    janela_login.title("Autenticação Admin")
    janela_login.geometry("350x200")
    janela_login.iconbitmap('icone.ico')
    janela_login.resizable(False, False)
    janelas_secundarias.append(janela_login)
    
    frame = tk.Frame(janela_login, bg=tema_atual["frame_bg"], padx=20, pady=20)
    frame.pack(fill="both", expand=True)
    
    tk.Label(frame, text="Autenticação Administrativa", font=("Arial", 12, "bold"), 
             bg=tema_atual["frame_bg"], fg=tema_atual["fg"]).pack(pady=(0, 15))
    
    tk.Label(frame, text="Digite a senha-mestra:", bg=tema_atual["frame_bg"], fg=tema_atual["fg"]).pack(anchor="w")
    entrada = tk.Entry(frame, show="*", width=30, bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
    entrada.pack(pady=(0, 20))
    
    btn_entrar = tk.Button(frame, text="Entrar", command=verificar, bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                          activebackground=tema_atual["btn_hover"], width=15)
    btn_entrar.pack()
    
    aplicar_tema()

def aplicar_tema_janela_dados(janela):
    for widget in janela.winfo_children():
        if isinstance(widget, tk.Frame):
            widget.config(bg=tema_atual["bg"] if widget.winfo_name().startswith("!frame") else tema_atual["frame_bg"])
            for child in widget.winfo_children():
                aplicar_tema_janela_dados(child)
        elif isinstance(widget, tk.Label):
            widget.config(bg=tema_atual["frame_bg"] if widget.master.winfo_class() == "Frame" else tema_atual["bg"], 
                          fg=tema_atual["fg"])
        elif isinstance(widget, tk.Entry):
            widget.config(bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"],
                         insertbackground=tema_atual["fg"])
        elif isinstance(widget, tk.Button):
            if widget.cget("text") in ["Excluir Selecionado", "Excluir"]:
                widget.config(bg="#f44336", fg="#ffffff", activebackground="#d32f2f")
            else:
                widget.config(bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                             activebackground=tema_atual["btn_hover"])

def mostrar_dados_salvos():
    janela_dados = tk.Toplevel()
    janela_dados.title("Senhas Salvas")
    janela_dados.geometry("700x500")
    janela_dados.iconbitmap('icone.ico')
    janela_dados.resizable(True, True)
    janelas_secundarias.append(janela_dados)
    
    # Frame principal
    main_frame = tk.Frame(janela_dados, bg=tema_atual["bg"])
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Frame de busca
    frame_busca = tk.Frame(main_frame, bg=tema_atual["frame_bg"], pady=10, padx=10)
    frame_busca.pack(fill="x", pady=(0, 10))
    
    lbl_busca = tk.Label(frame_busca, text="Buscar:", bg=tema_atual["frame_bg"], fg=tema_atual["fg"])
    lbl_busca.pack(side="left", padx=(0, 10))
    
    entrada_busca = tk.Entry(frame_busca, width=40, bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
    entrada_busca.pack(side="left", expand=True, fill="x", padx=(0, 10))
    
    # Treeview para mostrar os dados
    frame_tree = tk.Frame(main_frame, bg=tema_atual["bg"])
    frame_tree.pack(fill="both", expand=True)
    
    # Configurar estilo da Treeview conforme o tema
    style = ttk.Style()
    style.theme_use('default')
    
    if modo_escuro:
        style.configure("Treeview",
                      background=tema_atual["entry_bg"],
                      foreground=tema_atual["fg"],
                      fieldbackground=tema_atual["entry_bg"])
        style.configure("Treeview.Heading",
                      background=tema_atual["btn_bg"],
                      foreground=tema_atual["btn_fg"])
        style.map('Treeview', background=[('selected', tema_atual["highlight"])])
    else:
        style.configure("Treeview",
                      background="white",
                      foreground="black",
                      fieldbackground="white")
        style.configure("Treeview.Heading",
                      background=tema_atual["btn_bg"],
                      foreground=tema_atual["btn_fg"])
    
    scroll_y = ttk.Scrollbar(frame_tree)
    scroll_y.pack(side="right", fill="y")
    
    colunas = ("Serviço", "Usuário", "Senha")
    tree = ttk.Treeview(frame_tree, columns=colunas, show="headings", yscrollcommand=scroll_y.set,
                       style="Treeview")
    
    for col in colunas:
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor="w")
    
    tree.pack(fill="both", expand=True)
    scroll_y.config(command=tree.yview)
    
    # Botões de ação
    frame_botoes = tk.Frame(main_frame, bg=tema_atual["frame_bg"], pady=10)
    frame_botoes.pack(fill="x", pady=(10, 0))
    
    btn_copiar = tk.Button(frame_botoes, text="Copiar Senha", bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                          activebackground=tema_atual["btn_hover"])
    btn_copiar.pack(side="left", padx=5)
    
    btn_excluir = tk.Button(frame_botoes, text="Excluir Selecionado", bg="#f44336", fg="#ffffff",
                           activebackground="#d32f2f")
    btn_excluir.pack(side="left", padx=5)
    
    # Aplicar tema imediatamente
    aplicar_tema_janela_dados(janela_dados)
    
    # Função para carregar dados na treeview
    def carregar_dados(filtro=""):
        tree.delete(*tree.get_children())
        dados = {}
        try:
            with open("dados_senhas.dat", "rb") as arq:
                linhas = arq.readlines()
                chave = carregar_chave()
                f = Fernet(chave)
            for linha in linhas:
                try:
                    decodificado = f.decrypt(linha.strip()).decode()
                    partes = decodificado.split(" | ")
                    if len(partes) == 3:
                        servico, usuario, senha = partes
                        if filtro.lower() in servico.lower():
                            tree.insert("", "end", values=(servico, usuario, "••••••••"))
                except:
                    continue
        except FileNotFoundError:
            pass
    
    # Função para copiar senha
    def copiar_senha():
        selecionado = tree.focus()
        if selecionado:
            item = tree.item(selecionado)
            servico, usuario, _ = item['values']
            
            try:
                with open("dados_senhas.dat", "rb") as arq:
                    linhas = arq.readlines()
                    chave = carregar_chave()
                    f = Fernet(chave)
                for linha in linhas:
                    try:
                        decodificado = f.decrypt(linha.strip()).decode()
                        partes = decodificado.split(" | ")
                        if len(partes) == 3 and partes[0] == servico and partes[1] == usuario:
                            janela_dados.clipboard_clear()
                            janela_dados.clipboard_append(partes[2])
                            messagebox.showinfo("Copiado", "Senha copiada para a área de transferência!")
                            return
                    except:
                        continue
            except FileNotFoundError:
                pass
    
    # Função para excluir entrada
    def excluir_entrada():
        selecionado = tree.focus()
        if selecionado:
            item = tree.item(selecionado)
            servico, usuario, _ = item['values']
            
            confirm = messagebox.askyesno("Confirmação", f"Tem certeza que deseja excluir a entrada para {servico}?")
            if confirm:
                try:
                    with open("dados_senhas.dat", "rb") as arq:
                        linhas = arq.readlines()

                    chave = carregar_chave()
                    f = Fernet(chave)

                    novas_linhas = []
                    for linha in linhas:
                        try:
                            decodificado = f.decrypt(linha.strip()).decode()
                            partes = decodificado.split(" | ")
                            if len(partes) == 3 and not (partes[0] == servico and partes[1] == usuario):
                                novas_linhas.append(linha)
                        except:
                            continue

                    with open("dados_senhas.dat", "wb") as arq:
                        arq.writelines(novas_linhas)

                    carregar_dados(entrada_busca.get())
                except Exception as e:
                    messagebox.showerror("Erro", f"Erro ao excluir: {e}")
    
    # Configurar eventos
    entrada_busca.bind("<KeyRelease>", lambda e: carregar_dados(entrada_busca.get()))
    btn_copiar.config(command=copiar_senha)
    btn_excluir.config(command=excluir_entrada)
    
    # Carregar dados iniciais
    carregar_dados()
    
    aplicar_tema()

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

def aplicar_tema():
    # Aplicar tema na janela principal
    janela.config(bg=tema_atual["bg"])
    frame_principal.config(bg=tema_atual["bg"])
    
    for widget in widgets_estilizados:
        if isinstance(widget, tk.Entry):
            widget.config(bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"],
                         insertbackground=tema_atual["fg"])
        elif isinstance(widget, tk.Label):
            widget.config(bg=tema_atual["bg"], fg=tema_atual["fg"])
        elif isinstance(widget, tk.Button):
            widget.config(bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                         activebackground=tema_atual["btn_hover"])
    
    # Aplicar tema nas janelas secundárias
    for janela_sec in janelas_secundarias:
        try:
            for widget in janela_sec.winfo_children():
                if isinstance(widget, tk.Frame):
                    widget.config(bg=tema_atual["frame_bg"])
                aplicar_tema_janela(widget)
        except:
            continue

def aplicar_tema_janela(widget):
    if isinstance(widget, tk.Frame):
        widget.config(bg=tema_atual["frame_bg"])
        for child in widget.winfo_children():
            aplicar_tema_janela(child)
    elif isinstance(widget, tk.Label):
        widget.config(bg=tema_atual["frame_bg"] if widget.master.winfo_class() == "Frame" else tema_atual["bg"], 
                      fg=tema_atual["fg"])
    elif isinstance(widget, tk.Entry):
        widget.config(bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"],
                     insertbackground=tema_atual["fg"])
    elif isinstance(widget, tk.Button):
        if widget.cget("bg") == "#f44336":  # Mantém cor do botão excluir
            widget.config(fg="#ffffff", activebackground="#d32f2f")
        else:
            widget.config(bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                         activebackground=tema_atual["btn_hover"])

# ============ Interface Principal ============
gerar_chave()

janela = tk.Tk()
janela.title("Gerenciador de Senhas Seguro")
janela.geometry("500x450")
janela.iconbitmap('icone.ico')
janela.resizable(False, False)

# Frame principal
frame_principal = tk.Frame(janela, bg=tema_atual["bg"], padx=20, pady=20)
frame_principal.pack(fill="both", expand=True)

# Título
tk.Label(frame_principal, text="Gerenciador de Senhas", font=("Arial", 16, "bold"), 
         bg=tema_atual["bg"], fg=tema_atual["highlight"]).pack(pady=(0, 20))

# Frame de formulário
frame_form = tk.Frame(frame_principal, bg=tema_atual["bg"], padx=10, pady=10)
frame_form.pack(fill="x", pady=5)

frame_form.columnconfigure(1, weight=1)

tk.Label(frame_form, text="Serviço:", font=("Arial", 10), 
         bg=tema_atual["bg"], fg=tema_atual["fg"]).grid(row=0, column=0, sticky="w", pady=(0, 5))
entrada_servico = tk.Entry(frame_form, font=("Arial", 11), 
                          bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
entrada_servico.grid(row=0, column=1, sticky="ew", pady=(0, 5), padx=(5, 0))

# Usuário/E-mail
tk.Label(frame_form, text="Usuário/E-mail:", font=("Arial", 10), 
         bg=tema_atual["bg"], fg=tema_atual["fg"]).grid(row=1, column=0, sticky="w", pady=(0, 5))
entrada_usuario = tk.Entry(frame_form, font=("Arial", 11), 
                          bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
entrada_usuario.grid(row=1, column=1, sticky="ew", pady=(0, 5), padx=(5, 0))

# Senha
tk.Label(frame_form, text="Senha:", font=("Arial", 10), 
         bg=tema_atual["bg"], fg=tema_atual["fg"]).grid(row=2, column=0, sticky="w", pady=(0, 5))

frame_senha = tk.Frame(frame_form, bg=tema_atual["bg"])
frame_senha.grid(row=2, column=1, sticky="ew", pady=(0, 5), padx=(5, 0))

campo_senha = tk.Entry(frame_senha, font=("Arial", 11), 
                      bg=tema_atual["entry_bg"], fg=tema_atual["entry_fg"])
campo_senha.pack(side="left", fill="x", expand=True)

btn_gerar = tk.Button(frame_senha, text="Gerar", command=atualizar_senha, width=8,
                     bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                     activebackground=tema_atual["btn_hover"])
btn_gerar.pack(side="right", padx=(5, 0))

# Configure o grid para expandir corretamente
frame_form.grid_rowconfigure(0, weight=1)
frame_form.grid_rowconfigure(1, weight=1)
frame_form.grid_rowconfigure(2, weight=1)

# Frame de botões
frame_botoes = tk.Frame(frame_principal, bg=tema_atual["bg"], pady=20)
frame_botoes.pack(fill="x")

btn_salvar = tk.Button(frame_botoes, text="Salvar Senha", command=salvar_dados, width=15,
                      bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                      activebackground=tema_atual["btn_hover"])
btn_salvar.pack(pady=5)

btn_admin = tk.Button(frame_botoes, text="Modo Administrador", command=autenticador_admin, width=20,
                     bg="#FF9800", fg="#ffffff", activebackground="#F57C00")
btn_admin.pack(pady=5)

# Botão de tema
btn_tema = tk.Button(frame_principal, text="Alternar Tema", command=alternar_tema, width=15,
                    bg=tema_atual["btn_bg"], fg=tema_atual["btn_fg"],
                    activebackground=tema_atual["btn_hover"])
btn_tema.pack(pady=(20, 0))

# Armazenar widgets para estilização
widgets_estilizados.extend([
    entrada_servico, entrada_usuario, campo_senha, 
    btn_gerar, btn_salvar, btn_admin, btn_tema
])

aplicar_tema()
janela.mainloop()