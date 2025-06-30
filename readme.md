# SWport

**swport** is a fast, multi-threaded port scanner inspired by Nmap — proudly built in Python by **Samurai\_vxtW** 🥷🏻. It supports TCP, UDP, OS detection (via ICMP ping), and Nmap-style output formatting, all via a clean command-line interface.

---

## 🔧 Features

* ✅ TCP Port Scanning
* ✅ UDP Scanning (`-sU`)
* ✅ OS Detection via TTL Guessing (`-Os`)
* ✅ Nmap-style output layout
* ✅ Banner-free, local and installable via `pip`
* ✅ Easy to use: just run `swport <target>`

---

## 📦 Installation

Make sure your file is named `swport.py` and `setup.py` is in the same directory.

```bash
pip install .
```

After that, you'll be able to run:

```bash
swport google.com -p 20-100
```

---

## 🚀 Usage

```bash
swport [target] [options]
```

### ✨ Options

| Flag            | Description                          |
| --------------- | ------------------------------------ |
| `-p`, `--ports` | Port range (e.g. `-p 22-80`)         |
| `--open`        | Show only open ports                 |
| `-sU`, `--udp`  | Enable UDP scan                      |
| `-Os`, `--os`   | Perform OS detection (via ICMP ping) |
| `-h`, `--help`  | Show usage help                      |

---

### 🧪 Example Commands

```bash
swport google.com
swport google.com -p 22-80 --open
swport 192.168.1.1 -sU -p 53-69
swport 10.0.0.5 -Os
```

---

## 📁 Project Structure

```
.
├── swport.py      # Main scanner logic
├── setup.py       # Installer definition
└── README.md      # You're reading it
```

---

## 🧠 About the Creator

**swport** is developed and maintained by \[Samurai\_vxtW].
A sharp mind, a love for code, and a mission to empower developers & hackers alike.

---

## ⚖️ License

MIT — free to use, modify, and share.
