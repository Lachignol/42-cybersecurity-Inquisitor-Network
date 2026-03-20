# 42 Cybersecurity - Inquisitor Network

[🇬🇧 Read this README in English](README-en.md)

## 📖 Description
**Inquisitor** est un projet de cybersécurité axé sur le réseau. Ce projet implémente une attaque **Man-in-the-Middle (MitM)** en utilisant la technique de l'**ARP Spoofing** (empoisonnement ARP). 

Écrit en Go, cet outil permet d'intercepter les communications entre une machine victime et un serveur (notamment un serveur FTP) pour écouter et capturer les trames réseau (Sniffing), extraire des fichiers transmis, et analyser le trafic en temps réel.

Un environnement de test complet basé sur **Docker** est fourni pour simuler un attaquant, une victime et un serveur en toute sécurité.

---

## 🛠️ Prérequis
Avant de commencer, assurez-vous d'avoir installé sur votre machine :
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- `make` (Généralement préinstallé sur Linux et macOS)

---

## 🚀 Installation & Démarrage

1. **Cloner le dépôt** :
   ```bash
   git clone https://github.com/Lachignol/42-cybersecurity-Inquisitor-Network
   cd 42-cybersecurity-Inquisitor-Network
   ```

2. **Générer et démarrer l'environnement de test** :
   Le projet inclut un `Makefile` pour faciliter le déploiement. Pour construire les images et démarrer les conteneurs en tâche de fond, exécutez simplement :
   ```bash
   make
   # ou 'make build'
   ```
   Cela va lancer trois conteneurs :
   - `serveur` (IP: 10.0.0.10, MAC: 02:42:0A:00:00:0A) - *Héberge le service FTP*
   - `victime` (IP: 10.0.0.20, MAC: 02:42:0A:00:00:0B) - *Le client qui va se connecter au serveur*
   - `attaquant` (IP: 10.0.0.30, MAC: 02:42:0A:00:00:0C) - *Votre machine d'attaque*

---

## 🎯 Utilisation

Une fois l'environnement démarré, vous pouvez ouvrir des terminaux distincts pour accéder à chaque machine :

### 1. Accéder aux machines
Ouvrez plusieurs terminaux et utilisez les commandes suivantes :
- **Terminal Attaquant** : `make bash-attaquant`
- **Terminal Victime** : `make bash-victime`
- **Terminal Serveur** (optionnel) : `make bash-serveur`

### 2. Lancer l'attaque (depuis le conteneur Attaquant)
Dans le shell de l'attaquant (`make bash-attaquant`), l'outil binaire `inquisitor` devrait être compilé ou exécutable. La syntaxe générale est la suivante :

```bash
./inquisitor [-v] <IP_Victime> <MAC_Victime> <IP_Serveur> <MAC_Serveur> <MAC_Attaquant>
```
- `-v` : (Optionnel) Active le mode verbose (affichage détaillé du trafic).

**Exemple de commande avec la configuration du lab actuel :**
```bash
go run main.go -v "10.0.0.20" "02:42:0a:00:00:0B" "10.0.0.10" "02:42:0a:00:00:0A" "02:42:0a:00:00:0C"
```
*(Si le binaire ./inquisitor est déjà compilé, utilisez-le directement au lieu de `go run`)*

### 3. Simuler le trafic (depuis le conteneur Victime)
Pendant que l'attaquant écoute, allez dans le terminal de la victime et connectez-vous au serveur FTP pour générer du trafic :
```bash
ftp 10.0.0.10
# (entrez les identifiants configurés dans le serveur FTP) par exemple:
user: "anonymous"
pwd: "anonymous"
```
Dans le terminal de l'attaquant, vous devriez voir les identifiants et le trafic transiter en clair.

---

## 🧹 Commandes utiles (Makefile)

- `make` ou `make build` : Construit et lance les conteneurs Docker (détachés).
- `make bash-attaquant` : Ouvre un shell interactif dans le conteneur de l'attaquant.
- `make bash-victime` : Ouvre un shell interactif dans le conteneur de la victime.
- `make bash-serveur` : Ouvre un shell interactif dans le conteneur du serveur.
- `make clean` : Arrête les conteneurs en cours d'exécution.
- `make fclean` : Arrête les conteneurs, supprime les images Docker générées et les volumes associés.
- `make re` : Exécute `fclean` suivi de `build` (réinitialisation complète).
