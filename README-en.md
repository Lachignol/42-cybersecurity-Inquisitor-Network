# 42 Cybersecurity - Inquisitor Network

[🇫🇷 Lire ce README en Français](README.md)

## Description
**Inquisitor** is a network-focused cybersecurity. This project implements a **Man-in-the-Middle (MitM)** attack using the **ARP Spoofing** technique.

Written in Go, this tool allows you to intercept communications between a victim machine and a server (specifically an FTP server) to listen to and capture network frames (Sniffing), extract transmitted files, and analyze traffic in real time.

A complete **Docker**-based test environment is provided to safely simulate an attacker, a victim, and a server.

---

## 🛠️ Prerequisites
Before you begin, make sure you have the following installed on your machine:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- `make` (Generally pre-installed on Linux and macOS)

---

##  Installation & Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Lachignol/42-cybersecurity-Inquisitor-Network
   cd 42-cybersecurity-Inquisitor-Network
   ```

2. **Generate and start the test environment**:
   The project includes a `Makefile` to facilitate deployment. To build the images and start the containers in the background, simply run:
   ```bash
   make
   # or 'make build'
   ```
   This will launch three containers:
   - `serveur` (IP: 10.0.0.10, MAC: 02:42:0A:00:00:0A) - *Hosts the FTP service*
   - `victime` (IP: 10.0.0.20, MAC: 02:42:0A:00:00:0B) - *The client that will connect to the server*
   - `attaquant` (IP: 10.0.0.30, MAC: 02:42:0A:00:00:0C) - *Your attack machine*

---

##  Usage

Once the environment is running, you can open separate terminals to access each machine:

### 1. Accessing the machines
Open multiple terminals and use the following commands:
- **Attacker Terminal**: `make bash-attaquant`
- **Victim Terminal**: `make bash-victime`
- **Server Terminal** (optional): `make bash-serveur`

### 2. Launching the attack (from the Attacker container)
Inside the attacker's shell (`make bash-attaquant`), the `inquisitor` binary tool should be compiled or executable. The general syntax is as follows:

```bash
./inquisitor [-v] <Victim_IP> <Victim_MAC> <Server_IP> <Server_MAC> <Attacker_MAC>
```
- `-v`: (Optional) Enables verbose mode (detailed traffic display).

**Example command using the current lab configuration:**
```bash
go run main.go -v "10.0.0.20" "02:42:0a:00:00:0B" "10.0.0.10" "02:42:0a:00:00:0A" "02:42:0a:00:00:0C"
```
*(If the `./inquisitor` binary is already compiled, use it directly instead of `go run`)*

### 3. Simulating traffic (from the Victim container)
While the attacker is listening, go to the victim's terminal and connect to the FTP server to generate traffic:
```bash
ftp 10.0.0.10
# (enter the credentials configured in the FTP server) for example:
user: "anonymous"
pwd: "anonymous"
```
In the attacker's terminal, you should see the credentials and the cleartext traffic passing through.

---

##  Useful Commands (Makefile)

- `make` or `make build`: Builds and launches the Docker containers (detached).
- `make bash-attaquant`: Opens an interactive shell in the attacker container.
- `make bash-victime`: Opens an interactive shell in the victim container.
- `make bash-serveur`: Opens an interactive shell in the server container.
- `make clean`: Stops the running containers.
- `make fclean`: Stops containers, removes generated Docker images and associated volumes.
- `make re`: Runs `fclean` followed by `build` (complete reset).
