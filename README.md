# 📚 Documentation PKI & Stack ELK Sécurisée

---

## Table des matières

1. [Fondamentaux TLS/SSL](#1-fondamentaux-tlsssl)
2. [Composition d'un certificat X.509](#2-composition-dun-certificat-x509)
3. [Architecture PKI du projet](#3-architecture-pki-du-projet)
4. [Documentation des classes](#4-documentation-des-classes)
5. [Module cryptography](#5-module-cryptography)
6. [Commandes OpenSSL utiles](#6-commandes-openssl-utiles)

---

## 1. Fondamentaux TLS/SSL

### 1.1 Cryptographie asymétrique

```
┌─────────────────────────────────────────────────────────┐
│ PRINCIPE DE BASE                                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  CLÉ PRIVÉE (Private Key)                              │
│  ├─ Secrète, ne JAMAIS partager                        │
│  ├─ Permet de SIGNER des données                       │
│  └─ Permet de DÉCHIFFRER des messages                  │
│                                                         │
│  CLÉ PUBLIQUE (Public Key)                             │
│  ├─ Dérivée mathématiquement de la clé privée          │
│  ├─ Peut être partagée librement                       │
│  ├─ Permet de VÉRIFIER les signatures                  │
│  └─ Permet de CHIFFRER des messages                    │
│                                                         │
│  CERTIFICAT (Certificate)                              │
│  ├─ Contient la clé publique                           │
│  ├─ Contient des informations d'identité (CN, O, C)    │
│  ├─ Signé par une autorité de certification (CA)       │
│  └─ Prouve l'identité du propriétaire                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 1.2 Chaîne de confiance

```
┌──────────────────────────────────────────────────────┐
│ HIÉRARCHIE DES CERTIFICATS                           │
└──────────────────────────────────────────────────────┘

       Root CA (Auto-signée)
       ├─ Subject: CN=ELK-Root-CA
       ├─ Issuer:  CN=ELK-Root-CA  ← Identique !
       ├─ ca=True (peut signer d'autres certificats)
       └─ Clé privée: SECRÈTE, stockée en sécurité
              │
              ├─ Signe avec sa clé privée
              │
              ▼
       ┌─────────────────────────────────────┐
       │                                     │
       │  Certificat Elasticsearch           │  Certificat Logstash
       │  ├─ Subject: CN=elasticsearch       │  ├─ Subject: CN=logstash
       │  ├─ Issuer:  CN=ELK-Root-CA         │  ├─ Issuer:  CN=ELK-Root-CA
       │  ├─ ca=False (serveur)              │  ├─ ca=False (client)
       │  └─ SERVER_AUTH                     │  └─ CLIENT_AUTH
       │                                     │
       └─────────────────────────────────────┘
```

### 1.3 TLS Mutuel (mTLS)

```
┌────────────────────────────────────────────────────────┐
│ COMMUNICATION SÉCURISÉE LOGSTASH → ELASTICSEARCH       │
└────────────────────────────────────────────────────────┘

1. HANDSHAKE TLS
   ─────────────────────────────────────────────────
   Logstash                        Elasticsearch
      │                                   │
      │  1. ClientHello                   │
      ├──────────────────────────────────►│
      │                                   │
      │  2. ServerHello + ES Cert         │
      │◄──────────────────────────────────┤
      │                                   │
      │  3. Vérification du cert ES       │
      │     avec ca_cert.pem              │
      │     ✓ Signature valide            │
      │     ✓ CN/SAN correspond           │
      │     ✓ Pas expiré                  │
      │                                   │
      │  4. Client Cert (Logstash)        │
      ├──────────────────────────────────►│
      │                                   │
      │                   5. Vérification │
      │                      du cert      │
      │                      client avec  │
      │                      ca_cert.pem  │
      │                      ✓ Valide     │
      │                                   │
      │  6. ✅ Connexion établie          │
      │◄─────────────────────────────────►│

2. DONNÉES CHIFFRÉES
   ─────────────────────────────────────────────────
   Toutes les communications sont chiffrées avec
   une clé de session négociée durant le handshake.
```

---

## 2. Composition d'un certificat X.509

### 2.1 Structure complète

```yaml
Certificate:
  Data:
    Version: 3 (0x2)                      # Version X.509v3
    
    Serial Number:                        # Numéro unique
      49:09:3c:d8:a1:d4:d3:57:...
    
    Signature Algorithm:                  # Algorithme de signature
      sha256WithRSAEncryption
    
    Issuer:                               # Qui a signé ce certificat
      C  = MG                             # Country
      O  = ELK-DevOps                     # Organization
      CN = ELK-Root-CA                    # Common Name
    
    Validity:                             # Période de validité
      Not Before: Jan 14 03:29:38 2026 GMT
      Not After : Jan 14 03:29:38 2027 GMT
    
    Subject:                              # Qui possède ce certificat
      C  = MG
      O  = ELK-DevOps
      CN = elasticsearch
    
    Subject Public Key Info:              # Clé publique du propriétaire
      Public Key Algorithm: rsaEncryption
      Public-Key: (2048 bit)
      Modulus: 00:df:23:20:ba:...
      Exponent: 65537 (0x10001)
    
    X509v3 extensions:                    # Extensions (règles)
      
      X509v3 Basic Constraints: critical
        CA:FALSE                          # Pas une CA
      
      X509v3 Key Usage: critical
        Digital Signature                 # Peut signer
        Key Encipherment                  # Peut chiffrer des clés
      
      X509v3 Extended Key Usage:
        TLS Web Server Authentication     # SERVER_AUTH
      
      X509v3 Subject Alternative Name:    # Noms alternatifs
        DNS:elasticsearch
        DNS:localhost
        DNS:es.local
        IP Address:127.0.0.1
  
  Signature Algorithm: sha256WithRSAEncryption
    Signature (signée par la CA):
      a1:b2:c3:d4:...
```

### 2.2 Différences Serveur vs Client

| Champ | Serveur (ES) | Client (Logstash) |
|-------|--------------|-------------------|
| **Subject CN** | elasticsearch | logstash |
| **Issuer CN** | ELK-Root-CA | ELK-Root-CA |
| **Basic Constraints** | CA:FALSE | CA:FALSE |
| **Key Usage** | Digital Signature<br>Key Encipherment | Digital Signature<br>Key Encipherment |
| **Extended Key Usage** | **SERVER_AUTH** | **CLIENT_AUTH** |
| **Subject Alternative Name** | **OUI** (DNS + IP) | **NON** (pas nécessaire) |

### 2.3 Différence CA vs Certificat standard

| Champ | CA | Certificat standard |
|-------|-----|---------------------|
| **Subject = Issuer ?** | **OUI** (auto-signé) | **NON** (signé par CA) |
| **Basic Constraints** | **CA:TRUE** | CA:FALSE |
| **Key Usage** | **Certificate Sign**<br>CRL Sign | Digital Signature<br>Key Encipherment |
| **Durée de vie** | 10 ans | 1 an |
| **Taille clé** | 4096 bits | 2048 bits |

---

## 3. Architecture PKI du projet

### 3.1 Structure des fichiers

```
certs_output/
│
├── ca/                                   # Certificate Authority
│   ├── ca_cert.pem                      # Certificat CA (public)
│   │   ├─ Subject = Issuer (auto-signé)
│   │   ├─ CA:TRUE
│   │   └─ Validité: 10 ans
│   │
│   └── keys/
│       └── ca_private.pem               # Clé privée CA (SECRÈTE)
│           ├─ RSA 4096 bits
│           ├─ Permissions: 600
│           └─ Ne JAMAIS partager
│
├── elasticsearch/                        # Service serveur
│   ├── elasticsearch_cert.pem           # Certificat public
│   │   ├─ Subject: CN=elasticsearch
│   │   ├─ Issuer: CN=ELK-Root-CA
│   │   ├─ SERVER_AUTH
│   │   └─ SAN: 4 DNS + 1 IP
│   │
│   ├── ca_cert.pem                      # Copie de la CA (pour vérifier clients)
│   │
│   └── keys/
│       └── elasticsearch_private.pem    # Clé privée ES
│           ├─ RSA 2048 bits
│           └─ Permissions: 600
│
├── logstash/                             # Service client
│   ├── logstash_cert.pem                # Certificat public
│   │   ├─ Subject: CN=logstash
│   │   ├─ Issuer: CN=ELK-Root-CA
│   │   ├─ CLIENT_AUTH
│   │   └─ Pas de SAN
│   │
│   ├── ca_cert.pem                      # Copie de la CA (pour vérifier ES)
│   │
│   └── keys/
│       └── logstash_private.pem         # Clé privée Logstash
│           └─ Permissions: 600
│
└── kibana/                               # Service client
    ├── kibana_cert.pem
    ├── ca_cert.pem
    └── keys/
        └── kibana_private.pem
```

### 3.2 Qui a besoin de quoi ?

```
┌─────────────────────────────────────────────────────────┐
│ ELASTICSEARCH (Serveur)                                 │
├─────────────────────────────────────────────────────────┤
│ Fichiers nécessaires:                                   │
│  ├─ elasticsearch_cert.pem    (son certificat)          │
│  ├─ elasticsearch_private.pem (sa clé privée)           │
│  └─ ca_cert.pem               (pour vérifier clients)   │
│                                                         │
│ Configuration elasticsearch.yml:                        │
│  xpack.security.transport.ssl.enabled: true            │
│  xpack.security.transport.ssl.key: elasticsearch_...   │
│  xpack.security.transport.ssl.certificate: elast...    │
│  xpack.security.transport.ssl.certificate_author...    │
│  xpack.security.transport.ssl.client_authentication... │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ LOGSTASH (Client)                                       │
├─────────────────────────────────────────────────────────┤
│ Fichiers nécessaires:                                   │
│  ├─ logstash_cert.pem     (son certificat)              │
│  ├─ logstash_private.pem  (sa clé privée)               │
│  └─ ca_cert.pem           (pour vérifier ES)            │
│                                                         │
│ Configuration logstash.conf:                            │
│  output {                                               │
│    elasticsearch {                                      │
│      ssl => true                                        │
│      cacert => "ca_cert.pem"                            │
│      ssl_certificate => "logstash_cert.pem"             │
│      ssl_key => "logstash_private.pem"                  │
│    }                                                    │
│  }                                                      │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Documentation des classes

### 4.1 KeyManager

```python
"""
Gestion des clés RSA
"""

class KeyManager:
    """
    Génère et sauvegarde des paires de clés RSA.
    
    Attributes:
        key_dir (Path): Répertoire de stockage des clés
    
    Methods:
        create_rsa_keypair(key_name, key_size)
        └─ Génère une paire de clés et les sauvegarde
    """
    
    def __init__(self, key_dir: Path):
        """
        Initialise le gestionnaire de clés.
        
        Args:
            key_dir: Répertoire où sauvegarder les clés
                     Créé automatiquement s'il n'existe pas
        
        Example:
            manager = KeyManager(Path("./certs/keys"))
        """
    
    def create_rsa_keypair(
        self, 
        key_name: str, 
        key_size: int = 2048
    ) -> dict:
        """
        Génère une paire de clés RSA (privée/publique).
        
        Process:
            1. Génère clé privée RSA (2048 ou 4096 bits)
            2. Extrait la clé publique
            3. Sauvegarde en format PEM
            4. Définit les permissions (600 privée, 644 publique)
            5. Retourne les objets clés + chemins
        
        Args:
            key_name: Nom de base pour les fichiers
                     Ex: "ca" → ca_private.pem, ca_public.pem
            key_size: Taille de la clé en bits
                     2048 pour services, 4096 pour CA
        
        Returns:
            dict: {
                "private_key": RSAPrivateKey object,
                "public_key": RSAPublicKey object,
                "private_key_path": Path,
                "public_key_path": Path
            }
        
        Files created:
            {key_dir}/{key_name}_private.pem  (600)
            {key_dir}/{key_name}_public.pem   (644)
        
        Example:
            keypair = manager.create_rsa_keypair("elasticsearch", 2048)
            private_key = keypair["private_key"]
        """
```

### 4.2 ConfigLoader

```python
"""
Chargement et validation de la configuration YAML
"""

class ConfigLoader:
    """
    Charge la configuration depuis certs_config.yaml.
    
    Attributes:
        config_path (Path): Chemin du fichier YAML
        config (dict): Configuration chargée et validée
    
    Methods:
        get_ca_config()
        get_services_config()
    """
    
    def __init__(self, config_path: Path):
        """
        Charge et valide la configuration.
        
        Args:
            config_path: Chemin vers le fichier YAML
        
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si le YAML est invalide
            KeyError: Si une section obligatoire manque
        
        Validation:
            ✓ Fichier existe
            ✓ YAML valide
            ✓ Section 'ca' présente
            ✓ Section 'services' présente
            ✓ Champs obligatoires CA présents
        
        Example:
            config = ConfigLoader(Path("./certs_config.yaml"))
        """
    
    def get_ca_config(self) -> dict:
        """
        Retourne la configuration de la CA.
        
        Returns:
            dict: {
                "common_name": str,
                "validity_days": int,
                "key_size": int,
                "organization": str,
                "country": str
            }
        
        Example:
            ca_config = config.get_ca_config()
            cn = ca_config["common_name"]  # "ELK-Root-CA"
        """
    
    def get_services_config(self) -> dict:
        """
        Retourne la configuration de tous les services.
        
        Returns:
            dict: {
                "elasticsearch": {
                    "type": "server",
                    "key_size": 2048,
                    "validity_days": 365,
                    "dns_names": [...],
                    "ip_addresses": [...]
                },
                "logstash": {
                    "type": "client",
                    ...
                },
                ...
            }
        
        Example:
            services = config.get_services_config()
            for name, conf in services.items():
                print(f"{name}: {conf['type']}")
        """
```

### 4.3 CertManager

```python
"""
Gestion des certificats X.509
"""

class CertManager:
    """
    Crée et gère les certificats X.509.
    
    Attributes:
        cert_path (Path): Répertoire de stockage des certificats
        key_CA (RSAPrivateKey): Clé privée de la CA (pour signer)
        cert_CA (Certificate): Certificat de la CA
    
    Methods:
        create_ca_certificate(private_key, common_name, validity_days)
        create_server_certificate(...)
        create_client_certificate(...)
        save_certificate_pem(cert, filepath)
        load_certificate_pem(filepath)
    """
    
    def __init__(
        self, 
        cert_path: Path, 
        key_CA: RSAPrivateKey, 
        cert_CA: Certificate
    ):
        """
        Initialise le gestionnaire de certificats.
        
        Args:
            cert_path: Répertoire de stockage
            key_CA: Clé privée de la CA (pour signer)
            cert_CA: Certificat de la CA
        
        Example:
            manager = CertManager(
                cert_path=Path("./certs/elasticsearch"),
                key_CA=ca_private_key,
                cert_CA=ca_certificate
            )
        """
    
    def create_ca_certificate(
        self,
        private_key: RSAPrivateKey,
        common_name: str = "ELK-CA",
        validity_days: int = 3650
    ) -> Certificate:
        """
        Crée un certificat auto-signé pour la CA.
        
        Features:
            ✓ Subject = Issuer (auto-signé)
            ✓ BasicConstraints: ca=True, path_length=0
            ✓ KeyUsage: key_cert_sign, crl_sign
            ✓ Signature avec SHA256
        
        Args:
            private_key: Clé privée de la CA
            common_name: CN de la CA
            validity_days: Durée de validité (défaut: 10 ans)
        
        Returns:
            Certificate: Certificat X.509 auto-signé
        
        Example:
            ca_cert = manager.create_ca_certificate(
                private_key=ca_key,
                common_name="ELK-Root-CA",
                validity_days=3650
            )
        """
    
    def create_server_certificate(
        self,
        server_private_key: RSAPrivateKey,
        common_name: str,
        dns_names: list[str] = None,
        ip_addresses: list[str] = None,
        validity_days: int = 365
    ) -> Certificate:
        """
        Crée un certificat SERVEUR signé par la CA.
        
        Features:
            ✓ Subject ≠ Issuer (signé par CA)
            ✓ BasicConstraints: ca=False
            ✓ ExtendedKeyUsage: SERVER_AUTH
            ✓ SubjectAlternativeName: DNS names + IP addresses
            ✓ Signé avec la clé privée de la CA
        
        Args:
            server_private_key: Clé privée du serveur
            common_name: CN du serveur (ex: "elasticsearch")
            dns_names: Liste de noms DNS alternatifs
            ip_addresses: Liste d'adresses IP
            validity_days: Durée de validité (défaut: 1 an)
        
        Returns:
            Certificate: Certificat serveur signé
        
        Example:
            es_cert = manager.create_server_certificate(
                server_private_key=es_key,
                common_name="elasticsearch",
                dns_names=["localhost", "es.local"],
                ip_addresses=["127.0.0.1"],
                validity_days=365
            )
        """
    
    def create_client_certificate(
        self,
        client_private_key: RSAPrivateKey,
        common_name: str,
        validity_days: int = 365
    ) -> Certificate:
        """
        Crée un certificat CLIENT signé par la CA.
        
        Features:
            ✓ Subject ≠ Issuer (signé par CA)
            ✓ BasicConstraints: ca=False
            ✓ ExtendedKeyUsage: CLIENT_AUTH
            ✓ Pas de SubjectAlternativeName
            ✓ Signé avec la clé privée de la CA
        
        Args:
            client_private_key: Clé privée du client
            common_name: CN du client (ex: "logstash")
            validity_days: Durée de validité (défaut: 1 an)
        
        Returns:
            Certificate: Certificat client signé
        
        Example:
            logstash_cert = manager.create_client_certificate(
                client_private_key=logstash_key,
                common_name="logstash",
                validity_days=365
            )
        """
    
    @staticmethod
    def save_certificate_pem(cert: Certificate, filepath: Path) -> None:
        """
        Sauvegarde un certificat au format PEM.
        
        Args:
            cert: Certificat à sauvegarder
            filepath: Chemin de destination
        
        Creates:
            Fichier PEM avec permissions 644
            Format: -----BEGIN CERTIFICATE-----
        
        Example:
            CertManager.save_certificate_pem(
                cert=ca_cert,
                filepath=Path("./ca_cert.pem")
            )
        """
    
    def load_certificate_pem(self, filepath: Path) -> Certificate:
        """
        Charge un certificat depuis un fichier PEM.
        
        Args:
            filepath: Chemin du fichier PEM
        
        Returns:
            Certificate: Certificat chargé
        
        Example:
            ca_cert = manager.load_certificate_pem(
                Path("./ca_cert.pem")
            )
        """
```

---

## 5. Module cryptography

### 5.1 Imports essentiels

```python
# Génération de clés RSA
from cryptography.hazmat.primitives.asymmetric import rsa

# Algorithmes de hachage
from cryptography.hazmat.primitives import hashes

# Sérialisation (sauvegarde de clés)
from cryptography.hazmat.primitives import serialization

# Certificats X.509
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# Dates
from datetime import datetime, timedelta, timezone

# Adresses IP pour SAN
import ipaddress
```

### 5.2 Classes et méthodes principales

```python
# ============================================================================
# GÉNÉRATION DE CLÉS RSA
# ============================================================================

rsa.generate_private_key(
    public_exponent=65537,    # Standard (nombre premier de Fermat F4)
    key_size=2048             # 2048 ou 4096 bits
)
# Returns: RSAPrivateKey

private_key.public_key()
# Returns: RSAPublicKey (dérivée mathématiquement)

# ============================================================================
# SÉRIALISATION DES CLÉS
# ============================================================================

# Clé privée → bytes PEM
private_key.private_bytes(
    encoding=serialization.Encoding.PEM,      # Format texte base64
    format=serialization.PrivateFormat.PKCS8, # Standard moderne
    encryption_algorithm=serialization.NoEncryption()  # Pas de mot de passe
)

# Clé publique → bytes PEM
public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# ============================================================================
# CONSTRUCTION DE CERTIFICATS
# ============================================================================

# Subject/Issuer Name
x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "MG"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ELK-DevOps"),
    x509.NameAttribute(NameOID.COMMON_NAME, "elasticsearch"),
])

# Certificate Builder
x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    
    # Extensions
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            ...
        ),
        critical=True
    )
    .add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH  # ou CLIENT_AUTH
        ]),
        critical=False
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        ]),
        critical=False
    )
    
    # Signature
    .sign(private_key, hashes.SHA256())

# ============================================================================
# CHARGER UN CERTIFICAT
# ============================================================================

with open("cert.pem", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
```

### 5.3 OID (Object Identifiers)

```python
# NameOID - Identifiants pour Subject/Issuer
NameOID.COUNTRY_NAME           # C  = MG
NameOID.STATE_OR_PROVINCE_NAME # ST = Antananarivo
NameOID.LOCALITY_NAME          # L  = Antananarivo
NameOID.ORGANIZATION_NAME      # O  = ELK-DevOps
NameOID.ORGANIZATIONAL_UNIT_NAME # OU = IT
NameOID.COMMON_NAME            # CN = elasticsearch
NameOID.EMAIL_ADDRESS          # emailAddress = admin@example.com

# ExtendedKeyUsageOID - Usage du certificat
ExtendedKeyUsageOID.SERVER_AUTH      # Authentification serveur (TLS)
ExtendedKeyUsageOID.CLIENT_AUTH      # Authentification client (mTLS)
ExtendedKeyUsageOID.CODE_SIGNING     # Signature de code
ExtendedKeyUsageOID.EMAIL_PROTECTION # S/MIME
ExtendedKeyUsageOID.TIME_STAMPING    # Horodatage
```

### 5.4 Extensions X.509

```python
# BasicConstraints - Est-ce une CA ?
x509.BasicConstraints(
    ca=True,           # True = CA, False = certificat standard
    path_length=0      # Nombre de CA intermédiaires autorisées
)

# KeyUsage - Comment la clé peut être utilisée
x509.KeyUsage(
    digital_signature=True,   # Signer des données
    key_encipherment=True,    # Chiffrer des clés de session
    key_cert_sign=True,       # Signer des certificats (CA uniquement)
    crl_sign=True,            # Signer des CRL (CA uniquement)
    content_commitment=False, # Non-répudiation
    data_encipherment=False,  # Chiffrer directement des données
    key_agreement=False,      # Accord de clés (Diffie-Hellman)
    encipher_only=False,
    decipher_only=False
)

# ExtendedKeyUsage - Objectif du certificat
x509.ExtendedKeyUsage([
    ExtendedKeyUsageOID.SERVER_AUTH,  # Serveur TLS
    # ou
    ExtendedKeyUsageOID.CLIENT_AUTH   # Client TLS
])

# SubjectAlternativeName - Noms alternatifs
x509.SubjectAlternativeName([
    x509.DNSName("elasticsearch"),
    x509.DNSName("localhost"),
    x509.DNSName("es.local"),
    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
])
```

---

## 6. Commandes OpenSSL utiles

### 6.1 Inspection de certificats

```bash
# Afficher tout le certificat
openssl x509 -in cert.pem -text -noout

# Afficher uniquement Subject et Issuer
openssl x509 -in cert.pem -noout -subject -issuer

# Afficher les dates de validité
openssl x509 -in cert.pem -noout -dates

# Afficher les Subject Alternative Names
openssl