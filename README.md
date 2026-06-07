# Honeypot Shutdown v5.0

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=00e5ff&height=200&section=header&text=Honeypot%20Shutdown&fontSize=48&fontColor=ffffff&fontAlignY=38&desc=Threat%20Intelligence%20%26%20Deception%20Platform&descAlignY=58&descSize=18" width="100%"/>

<br/>

[![Autor](https://img.shields.io/badge/Autor-Rodrigo%20Coelho-00e5ff?style=for-the-badge\&logo=github\&logoColor=white)](https://github.com/RodCL-Dev)
[![Java](https://img.shields.io/badge/Java-17+-ff6b6b?style=for-the-badge\&logo=openjdk\&logoColor=white)](https://openjdk.org/)
[![Versão](https://img.shields.io/badge/Versão-5.0-00ff88?style=for-the-badge\&logo=git\&logoColor=white)]()
[![Licença](https://img.shields.io/badge/Licença-MIT-ffd60a?style=for-the-badge\&logo=opensourceinitiative\&logoColor=white)]()
[![Status](https://img.shields.io/badge/Status-Ativo-00ff88?style=for-the-badge\&logo=statuspage\&logoColor=white)]()

<br/>

> Sistema de Honeypot Multi-Protocolo desenvolvido em Java para captura, monitoramento e análise de ameaças em tempo real.

</div>

---

# 👤 Autor

<div align="center">

<img src="https://github.com/RodCL-Dev.png" width="120"/>

### Rodrigo Coelho

**CTO & Fundador — Shutdown Cybersecurity**

Especialista em Segurança Ofensiva, Red Team e Threat Intelligence.

</div>

---

# 📋 Índice

* Sobre o Projeto
* Funcionalidades
* Serviços Simulados
* Proteções Implementadas
* Instalação
* Como Utilizar
* Dashboard
* Estrutura do Projeto
* Testes
* Aviso Legal

---

# 🎯 Sobre o Projeto

O Honeypot Shutdown é uma plataforma de deception e threat intelligence projetada para simular serviços reais e registrar atividades maliciosas realizadas por atacantes.

O objetivo é fornecer visibilidade sobre:

* Scanners automatizados
* Tentativas de brute force
* Captura de credenciais
* Reconhecimento de rede
* Payloads suspeitos
* Origem geográfica dos ataques
* Inteligência de ameaças em tempo real

Ideal para:

* Laboratórios de Cyber Security
* Blue Team
* SOC
* Threat Hunting
* Pesquisa Acadêmica
* Ambientes Corporativos

---

# ✨ Funcionalidades

| Recurso                    | Descrição                                            |
| -------------------------- | ---------------------------------------------------- |
| 🌐 Multi-Protocolo         | HTTP, SSH, FTP, MySQL, Redis, Telnet e Elasticsearch |
| 🔑 Captura de Credenciais  | Registro de usuários e senhas enviados               |
| 🗺️ Geolocalização         | País, cidade e provedor                              |
| 🔍 Detecção de Scanner     | Nmap, Masscan, SQLMap, Nikto e similares             |
| 🔨 Detecção de Brute Force | Múltiplas tentativas em curto período                |
| 💣 Detecção de Exploits    | Identificação de payloads suspeitos                  |
| 🚫 Auto Block              | Bloqueio automático de IPs                           |
| 📊 Dashboard HTML          | Painel visual em tempo real                          |
| 🌎 Mapa de Ataques         | Origem geográfica das conexões                       |
| 📈 Estatísticas            | Métricas por protocolo                               |
| 🔄 Rotação de Logs         | Controle automático de tamanho                       |
| ⚡ Rate Limiting            | Proteção contra abuso                                |
| 🧠 Threat Intelligence     | Classificação automática de ameaças                  |
| 🖥️ Console Administrativo | Interface de gerenciamento                           |

---

# 🌐 Serviços Simulados

| Serviço       | Porta |
| ------------- | ----- |
| HTTP          | 8080  |
| SSH           | 2222  |
| FTP           | 2121  |
| MySQL         | 3307  |
| Redis         | 6379  |
| Telnet        | 23    |
| Elasticsearch | 9200  |

Todos os serviços são simulados exclusivamente para coleta de inteligência e monitoramento.

---

# 🛡️ Proteções Implementadas

✅ Thread Pool para conexões simultâneas

✅ Rate Limiting por IP

✅ Cooldown entre conexões

✅ Limite de payload HTTP

✅ Limite de cabeçalhos

✅ Cache de geolocalização

✅ Limpeza automática de memória

✅ Blocklist persistente

✅ Detecção de scanners

✅ Detecção de brute force

✅ Detecção de exploits

✅ Classificação automática de ameaças

✅ Rotação automática de logs

---

# 📦 Pré-Requisitos

* Java 17 ou superior
* Linux, Windows ou macOS

Verificar versão:

```bash
java -version
```

---

# 🚀 Instalação

## Clonar

```bash
git clone https://github.com/RodCL-Dev/honeypot-shutdown.git
cd honeypot-shutdown
```

## Compilar

```bash
javac Honeypot.java
```

## Executar

```bash
java Honeypot
```

Saída esperada:

```text
╔══════════════════════════════════════════════════════╗
║          HONEYPOT SHUTDOWN v5.0                     ║
║     Threat Intelligence & Deception Platform        ║
╚══════════════════════════════════════════════════════╝

[+] HTTP na porta 8080
[+] SSH na porta 2222
[+] FTP na porta 2121
[+] MySQL na porta 3307
[+] Redis na porta 6379
[+] Telnet na porta 23
[+] Elasticsearch na porta 9200

Digite 'help' para comandos.
```

---

# 📖 Como Utilizar

Executar em background:

```bash
nohup java Honeypot > console.log 2>&1 &
```

Ver logs:

```bash
tail -f honeypot_log.txt
```

Ver bloqueios:

```bash
cat blocked_ips.txt
```

Parar o honeypot:

```bash
pkill -f Honeypot
```

---

# 📊 Dashboard

O sistema gera automaticamente:

```text
honeypot_report.html
```

O painel apresenta:

* Conexões totais
* IPs bloqueados
* Scanners detectados
* Tentativas de brute force
* Exploits identificados
* Credenciais capturadas
* Estatísticas por serviço
* Origem geográfica dos ataques
* Timeline de eventos

Abrir:

```bash
xdg-open honeypot_report.html
```

---

# 🧪 Testes

HTTP:

```bash
curl http://localhost:8080
```

Captura de credenciais:

```bash
curl -X POST http://localhost:8080 \
-d "username=admin&password=123456"
```

Scanner:

```bash
nmap -sV -p 23,2121,2222,3307,6379,8080,9200 127.0.0.1
```

SSH:

```bash
nc 127.0.0.1 2222
```

FTP:

```bash
nc 127.0.0.1 2121
```

Redis:

```bash
nc 127.0.0.1 6379
```

Elasticsearch:

```bash
curl http://127.0.0.1:9200
```

---

# 📁 Estrutura do Projeto

```text
honeypot-shutdown/
│
├── Honeypot.java
├── Honeypot.class
├── honeypot_log.txt
├── honeypot_report.html
├── blocked_ips.txt
├── threats.txt
└── README.md
```

---

# ⚠️ Aviso Legal

Este projeto foi desenvolvido exclusivamente para:

* Pesquisa em Segurança da Informação
* Ambientes controlados
* Laboratórios de estudo
* Treinamento de Blue Team
* Threat Intelligence

O uso deve ocorrer apenas em ambientes próprios ou devidamente autorizados.

O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

<div align="center">

### Shutdown Cybersecurity

Threat Intelligence • Deception • Blue Team

Desenvolvido por Rodrigo Coelho

"Security is not a product, but a process."

</div>
