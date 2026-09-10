# NetTracer

**NetTracer** est un outil de surveillance réseau en ligne de commande (CLI/TUI) écrit en Python. Inspiré du Moniteur de ressources Windows, il permet de visualiser en temps réel les sockets réseau actifs, de les mapper aux processus locaux, et de les enrichir instantanément avec de la **géolocalisation IP** et de la **Threat Intelligence (Score d'abus)**.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 Fonctionnalités

- 🔍 **Mapping Processus → Sockets** : Affiche en temps réel le PID, le nom du processus et les ports distants associés.
- 🌐 **GeoIP locale ultra-rapide** : Intégration de la BDD MaxMind GeoLite2 (`.mmdb`) pour afficher le pays et le drapeau sans latence.
- 🛡️ **Threat Intel & Score d'abus** : Interrogation de l'API **AbuseIPDB** pour détecter les IP malveillantes, botnets et nœuds de sortie TOR.
- ⚡ **Traitement asynchrone & Cache SQLite** : Système de file d'attente multi-thread et cache local (`24h TTL`) pour un rendu TUI fluide à 1 FPS sans bloquer l'interface.
- 🎯 **Filtres avancés** : Filtrage par nom de processus, par port distant ou par score de réputation minimal.
- 📄 **Export DFIR / Audit** : Journalisation continue au format CSV pour analyse post-incident.

---

## 🛠️ Structure du projet

```
nettracer/
├── GeoLite2-City.mmdb      # Base de données GeoIP MaxMind
├── nettracer_cache.db      # Cache SQLite (généré au premier lancement)
├── pyproject.toml          # Configuration Packaging Python
└── src/
    └── nettracer/
        ├── __init__.py
        └── nettracer.py    # Code principal de l'application
```

---

## 📋 Prérequis

- **Python 3.10+**
- **Droits d'administration** (root / sudo) — requis par `psutil` pour associer les sockets système aux PID sous Linux et macOS.
- **Base GeoLite2 City (MaxMind)** — à télécharger et placer à la racine du projet :

```bash
curl -L -o GeoLite2-City.mmdb "https://git.io/GeoLite2-City.mmdb"
```

> **Note :** Assurez-vous de respecter les conditions de licence et d'utilisation de MaxMind pour la base GeoLite2.

---

## 📦 Installation

### Mode développeur (Editable)

**1. Cloner le projet**

```bash
git clone https://github.com/votre-user/nettracer.git
cd nettracer
```

**2. Créer et activer l'environnement virtuel**

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Installer le paquet**

```bash
pip install -e .
```

---

## 🔑 Configuration AbuseIPDB (optionnel)

Pour obtenir les scores de réputation IP via AbuseIPDB :

1. Créez un compte sur [AbuseIPDB](https://www.abuseipdb.com/).
2. Générez une clé API.
3. Définissez la variable d'environnement suivante :

```bash
export ABUSEIPDB_API_KEY="votre_cle_api_ici"
```

Vous pouvez également fournir directement la clé avec l'option `--api-key`.

> **Note :** En l'absence de clé API, NetTracer fonctionne normalement, mais sans les informations de réputation AbuseIPDB.

---

## 💻 Utilisation

**1. Lancement standard**

```bash
sudo -E $(which nettracer)
```

**2. Filtrer par processus**

Surveiller uniquement le trafic généré par un processus spécifique, par exemple `curl`, `python` ou `chrome` :

```bash
sudo nettracer --proc curl
```

**3. Filtrer par port distant**

Surveiller uniquement les connexions à destination d'un port spécifique.

HTTPS — port 443 :

```bash
sudo nettracer --port 443
```

SSH — port 22 :

```bash
sudo nettracer --port 22
```

**4. Filtrer par score de réputation**

En mode Threat Hunting, afficher uniquement les connexions dont le score d'abus est supérieur ou égal à 20 :

```bash
sudo -E nettracer --min-score 20
```

**5. Exporter les données au format CSV**

Enregistrer la session de capture dans un fichier CSV pour une analyse ultérieure ou un usage DFIR :

```bash
sudo nettracer --csv audit_reseau.csv
```

---

## ⚙️ Options CLI

```
Usage: nettracer [OPTIONS]

Options:
  -p, --proc TEXT       Filtrer par nom de processus (ex: curl)
  --port INTEGER         Filtrer par port distant (ex: 443)
  -s, --min-score INT    Afficher uniquement si le score d'abus >= valeur
                         [default: 0]
  --csv TEXT             Chemin du fichier de sortie CSV
  --api-key TEXT         Clé API AbuseIPDB
                         (ou via env ABUSEIPDB_API_KEY)
  --help                 Afficher ce message d'aide
```

---

## 🕵️ Exemples de Threat Hunting

**Détecter les connexions avec un score élevé**

```bash
sudo -E nettracer --min-score 50
```

**Surveiller uniquement un processus spécifique**

```bash
sudo nettracer --proc python
```

**Surveiller les connexions HTTPS suspectes**

```bash
sudo -E nettracer --port 443 --min-score 20
```

**Capturer les résultats pour analyse DFIR**

```bash
sudo -E nettracer --csv audit_reseau.csv
```

---

## 📊 Export CSV

L'option `--csv` permet de conserver les données collectées pendant la session afin de faciliter :

- l'analyse réseau ;
- les investigations DFIR ;
- la recherche d'indicateurs de compromission (IOC) ;
- la corrélation avec d'autres événements ;
- la création de rapports.

Exemple :

```bash
sudo nettracer --csv audit_reseau.csv
```

---

## 🔐 Privilèges

NetTracer nécessite généralement des privilèges élevés pour récupérer les informations permettant d'associer les connexions réseau aux processus correspondants.

Sous Linux et macOS, utilisez :

```bash
sudo nettracer
```

Si vous utilisez une clé API définie dans l'environnement, utilisez `sudo -E` afin de conserver les variables d'environnement :

```bash
sudo -E nettracer
```

---

## 📁 Structure du projet (détaillée)

```
nettracer/
├── GeoLite2-City.mmdb
├── nettracer/
│   └── ...
├── tests/
│   └── ...
├── pyproject.toml
├── README.md
└── venv/
```

> Il est recommandé de ne pas versionner l'environnement virtuel `venv/` ni les clés API.

---

## ⚠️ Sécurité

Ne partagez **jamais** votre clé API AbuseIPDB publiquement.

Évitez notamment de la placer directement dans le code source ou dans un dépôt Git :

```bash
export ABUSEIPDB_API_KEY="votre_cle_api_ici"
```

Pour un environnement de production, privilégiez un gestionnaire de secrets ou un mécanisme sécurisé de gestion des variables d'environnement.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**.

Vous êtes libre de modifier, utiliser et redistribuer le projet conformément aux termes de cette licence.