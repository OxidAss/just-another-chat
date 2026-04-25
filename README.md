# Just Another Chat - Safe client for chatting via terminal.

---

### What's jsChat?

> It's safe chat inspired by **netcat** tool for Kali Linux

---

## Compatibility

jsChat have compatibility with **every** Linux distribution including **Termux** for Android.

---

## Features

> End-to-end encryption with **AES-256-GCM** Passphrase-based key derivation via **SHA-256** Multi-client server with heartbeat & auto-disconnect Reconnect support on connection loss In-session commands: `/quit` `/who` `/help`

---

## Installation

```bash
git clone https://github.com/OxidAss/just-another-chat.git
cd just-another-chat
sudo bash install.sh
```

> On **Termux** — no sudo needed, dependencies install automatically.

---

## Usage

**Start a server:**

```bash
jschat -s 5050 passphrase
```

**Connect as client:**

```bash
jschat -c 127.0.0.1 passphrase nickname
```

**Connect with custom port:**

```bash
jschat -c 192.168.1.5:7777 passphrase nickname
```

---

## Build manually

**Linux:**

```bash
sudo apt install build-essential libssl-dev   # Debian/Ubuntu
sudo pacman -S base-devel openssl             # Arch
sudo dnf install gcc-c++ openssl-devel        # Fedora
make
```

**Termux:**

```bash
pkg install clang make openssl
make
```

---

## Environment variables

|Variable|Default|Description|
|---|---|---|
|`JSCHAT_PORT`|`5050`|Override default port|
|`JSCHAT_TIMEOUT`|`10`|Connection timeout (sec)|
|`JSCHAT_RECONNECT`|`3`|Reconnect attempts|
|`JSCHAT_MAX_CLIENTS`|`32`|Max clients (server mode)|
|`JSCHAT_HEARTBEAT`|`15`|Heartbeat interval (sec)|

---

## Security

> All messages encrypted with a **fresh random IV** per message. Pre-shared passphrase model — no PKI required. Tampered messages are detected and dropped via **GCM auth tag**.