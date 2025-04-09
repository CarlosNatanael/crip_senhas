# Conteúdo do README.md
# 🔐 Gerenciador de Senhas - Versão 1.0

Este é um aplicativo de **gerenciamento de senhas** desenvolvido em **Python com Tkinter**, focado em simplicidade, segurança e personalização.

---

## 🧠 Funcionalidades

- **Geração de senhas aleatórias** seguras.
- **Criptografia de senhas** utilizando a biblioteca `Fernet` (do pacote `cryptography`).
- **Armazenamento local criptografado** de senhas com nome do serviço e nome de usuário.
- **Autenticação por senha-mestra (modo admin)** para acesso à visualização das senhas salvas.
- **Visualização protegida** com busca e exclusão de registros.
- **Cópia rápida da senha** com botão "Copiar".
- **Alternância de tema claro/escuro** com consistência visual.

---

## 🛠️ Tecnologias Utilizadas

- Python 3.13
- Tkinter  
- Cryptography (Fernet)

---

## 📦 Estrutura do Projeto

```bash
📁 gerenciador_senhas/
├── senha_generator.py     # Criptografia e descriptografia com Fernet
├── senha_admin.key        # Armazena a senha-mestra criptografada
├── chave.key              # Armazena a senha-mestra criptografada
├── dados_senhas.dat       # Armazena as senhas salvas
└── README.md              # Este arquivo
