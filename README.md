# 🔐 SecurePass Manager - Gerenciador de Senhas

![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Um aplicativo seguro e intuitivo para gerenciamento de credenciais, desenvolvido em Python com interface Tkinter.

![image](https://github.com/user-attachments/assets/4225db41-a227-49b0-8d59-700fdd9fe8db)
 <!-- Adicione uma screenshot real depois -->

## ✨ Funcionalidades Principais

### 🛡️ Segurança Avançada
- Criptografia AES-128 via Fernet (Cryptography)
- Armazenamento local seguro com dupla camada de proteção
- Autenticação por senha-mestre com hashing seguro

### 🔧 Ferramentas Úteis
- Gerador de senhas complexas (até 32 caracteres)
  - Letras maiúsculas/minúsculas
  - Números
  - Caracteres especiais
- Busca inteligente por serviços cadastrados
- Copiar senha com um clique (sem exibição)

### 🎨 Experiência do Usuário
- Interface limpa e intuitiva
- Temas claro/escuro com persistência
- Feedback visual imediato para todas as ações

## 🚀 Como Usar

### Pré-requisitos
- Python 3.13+
- Pacotes necessários:
  ```bash
  pip install cryptography pillow
