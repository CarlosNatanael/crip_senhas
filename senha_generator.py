import tkinter as tk
from tkinter import messagebox
import random
import string

def gerar_senha(tamanho=12):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    senha = ''.join(random.choice(caracteres) for _ in range(tamanho))
    return senha

def atualizar_senha():
    nova_senha = gerar_senha()
    campo_senha.delete(0, tk.END)
    campo_senha.insert(0, nova_senha)


janela = tk.Tk()
janela.title("Gerador de senha")
janela.geometry("400x200")
janela.resizable(False, False)

label_info = tk.Label(janela, text="Clique no botão para gerar uma nova senha segura", font=("Arial", 12))
label_info.pack(pady=10)

campo_senha = tk.Entry(janela, width=40, font=("Arial", 12), justify="center")
campo_senha.pack(pady=10)

botao_gerar = tk.Button(janela, text="Gerar senha", font=("Arial", 12), command=atualizar_senha)
botao_gerar.pack(pady=5)

janela.mainloop()