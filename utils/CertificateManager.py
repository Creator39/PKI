from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List
import ipaddress
from dataclasses import dataclass

@dataclass
class CertManager:
    cert_path: Path
    key_CA: rsa.RSAPrivateKey
    cert_CA: x509.Certificate
    
    def __post_init__(self):
        self.cert_path.parent.mkdir(parents=True, exist_ok=True)

    def create_client_certificate(
        self,
        client_private_key: rsa.RSAPrivateKey,
        common_name: str,
        validity_days: int = 365
        ) -> x509.Certificate:
        """
        Crée un certificat CLIENT signé par la CA.
    
        DIFFÉRENCES avec le certificat serveur (Lab 3) :
        - ExtendedKeyUsage : CLIENT_AUTH au lieu de SERVER_AUTH
        - Pas de Subject Alternative Names (SAN) nécessaires
        - Utilisé pour s'AUTHENTIFIER auprès d'un serveur
    
        Args:
            client_private_key: Clé privée du client (Logstash/Kibana)
            ca_cert: Certificat de la CA
            ca_private_key: Clé privée de la CA (pour signer)
            common_name: CN du client (ex: "logstash", "kibana")
            validity_days: Durée de validité
        
        Returns:
            Un certificat X.509 client
        """
        print(f"\n📝 Création du certificat client : {common_name}")
        if self.cert_CA is None or self.key_CA is None:
            raise ValueError("Le certificat de la CA doit être fourni pour créer un certificat client.")
        # 1. Subject : Le client
        subject = self.create_name(common_name)
    
        # 2. Issuer : La CA
        issuer = self.cert_CA.subject
    
        print(f"   Subject : {common_name}")
        print(f"   Issuer  : {issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        print(f"   Type    : CLIENT (authentification)")
    
        # 3. Construire le certificat
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(client_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        
            # EXTENSION 1 : BasicConstraints
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        
            # EXTENSION 2 : KeyUsage
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,    # Peut signer des données
                    key_encipherment=True,     # Peut chiffrer des clés (TLS)
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,       # NE peut PAS signer de certificats
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .sign(self.key_CA, hashes.SHA256())
        )
    
        print(f"✅ Certificat client créé (valide {validity_days} jours)\n")
    
        return cert
    
    def create_server_certificate(self,
        server_private_key: rsa.RSAPrivateKey,
        common_name: str,
        dns_names: List[str] = None,
        ip_addresses: List[str] = None,
        validity_days: int = 365
    ) -> x509.Certificate:
        """
        Crée un certificat serveur signé par la CA.
        DIFFÉRENCE MAJEURE avec Lab 2 :
        - Subject ≠ Issuer (pas auto-signé)
        - Signé avec la CLÉ PRIVÉE DE LA CA
        - Extensions différentes (SERVER_AUTH, pas ca=True)
    
        Args:
            server_private_key: Clé privée du serveur (ES)
            ca_cert: Certificat de la CA (pour obtenir l'Issuer)
            ca_private_key: Clé privée de la CA (pour SIGNER)
            common_name: CN du serveur (ex: "elasticsearch")
            dns_names: Noms DNS alternatifs (ex: ["localhost", "es.local"])
            ip_addresses: Adresses IP (ex: ["127.0.0.1"])
            validity_days: Durée de validité (1 an par défaut)
        
        Returns:
            Un certificat X.509 signé par la CA
        """
        if self.cert_CA is None or self.key_CA is None:
            raise ValueError("Le certificat de la CA doit être fourni pour créer un certificat serveur.")
        
        if dns_names is None:
            dns_names = []
        if ip_addresses is None:
            ip_addresses = []
    
        print(f"\n📝 Création du certificat serveur : {common_name}")
    
        # 1. Subject : Le serveur (elasticsearch)
        subject =   self.create_name(common_name)
    
        # 2. Issuer : La CA (on l'extrait du certificat CA)
        issuer = self.cert_CA.subject
    
        print(f"   Subject : {common_name}")
        print(f"   Issuer  : {issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        print(f"   → Ce certificat sera signé par la CA")
    
        # 3. Préparer les Subject Alternative Names (SAN)
        san_list = []
    
        # Ajouter le CN comme DNS name
        san_list.append(x509.DNSName(common_name))
    
        # Ajouter les DNS names additionnels
        for dns in dns_names:
            san_list.append(x509.DNSName(dns))
            print(f"   + DNS: {dns}")
    
        # Ajouter les IP addresses
        for ip in ip_addresses:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            print(f"   + IP: {ip}")
    
        # 4. Construire le certificat
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # ← Différent du subject !
            .public_key(server_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        
        # EXTENSION 1 : BasicConstraints
        # ca=False : Ce n'est PAS une CA, juste un serveur
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        
        # EXTENSION 2 : KeyUsage
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,    # Peut signer des données
                key_encipherment=True,     # Peut chiffrer des clés (TLS)
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,       # NE PEUT PAS signer des certificats
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        # EXTENSION 3 : ExtendedKeyUsage
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,  # Authentification serveur
            ]),
            critical=False,
        )
        
        # EXTENSION 4 : SubjectAlternativeName
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        
        # 5. SIGNER avec la CLÉ PRIVÉE DE LA CA (pas la clé du serveur !)
        .sign(self.key_CA, hashes.SHA256())
    )
    
        print(f"✅ Certificat serveur créé (valide {validity_days} jours)")
        print(f"   Signé par : {issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}\n")
    
        return cert

    def load_certificate_pem(self, filepath: Path) -> x509.Certificate:
        """
        Charge un certificat depuis un fichier PEM.
    
        Utile pour charger le certificat CA créé dans le Lab 2.
        """
        print(f"📂 Chargement du certificat depuis {filepath}...")
    
        with open(filepath, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
            print(f"✅ Certificat chargé")
        return cert
    
    def compare_server_client_certs(self) -> None:
        """
        Affiche une comparaison visuelle entre certificat serveur et client.
        """
        print("\n" + "="*60)
        print("COMPARAISON : CERTIFICAT SERVEUR vs CLIENT")
        print("="*60)
    
        comparison = """
    
        ┌─────────────────────────┬──────────────────────────────────┐
        │ ASPECT                  │ SERVEUR (ES)    │ CLIENT (Logstash/Kibana) │
        ├─────────────────────────┼──────────────────────────────────┤
        │ ExtendedKeyUsage        │ SERVER_AUTH     │ CLIENT_AUTH              │
        │ Subject Alternative Name│ OUI (obligatoire)│ NON (pas nécessaire)    │
        │ Rôle                    │ Écoute          │ Se connecte              │
        │ Présente son certificat │ Au client       │ Au serveur               │
        │ Vérifie l'autre partie  │ Avec ca_cert.pem│ Avec ca_cert.pem         │
        └─────────────────────────┴──────────────────────────────────┘

        💡 TLS MUTUEL (mTLS) :
        - Le serveur vérifie le client → CLIENT_AUTH requis
        - Le client vérifie le serveur → SERVER_AUTH requis
        - Les deux font confiance à la même CA

        ⚠️  IMPORTANT pour Elasticsearch :
        Si vous activez xpack.security.transport.ssl.client_authentication: required
        alors Logstash et Kibana DOIVENT présenter un certificat CLIENT valide.
        """
            
        print(comparison)
        print("="*60 + "\n")

    def save_certificate_pem(cert: x509.Certificate, filepath: Path) -> None:
        """
        Sauvegarde un certificat au format PEM.
    
        Format PEM pour certificat :
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
        """
        print(f"💾 Sauvegarde du certificat dans {filepath}...")

        pem_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_bytes(pem_bytes)
        filepath.chmod(0o644)
    
        print(f"✅ Certificat sauvegardé")

    def display_certificate_info(cert: x509.Certificate) -> None:

        """
        Affiche les informations principales du certificat.
        """
        print("\n" + "="*60)
        print("INFORMATIONS DU CERTIFICAT")
        print("="*60)
    
        # Subject
        print(f"\n📋 Subject (Propriétaire) :")
        for attr in cert.subject:
            print(f"   {attr.oid._name} = {attr.value}")
    
        # Issuer
        print(f"\n🔏 Issuer (Émetteur) :")
        for attr in cert.issuer:
            print(f"   {attr.oid._name} = {attr.value}")
    
        # Validité
        print(f"\n📅 Validité :")
        print(f"   Début     : {cert.not_valid_before_utc}")
        print(f"   Fin       : {cert.not_valid_after_utc}")
        
        # Serial Number
        print(f"\n🔢 Serial Number : {cert.serial_number}")
        
        # Extensions
        print(f"\n🔧 Extensions :")
        for ext in cert.extensions:
            print(f"   - {ext.oid._name} (critical={ext.critical})")
        
        print("\n" + "="*60 + "\n")

    def create_name(self, common_name: str, organization: str = "ELK-DevOps", country: str = "MG") -> x509.Name:
        """
        Crée un objet Name pour le Subject ou l'Issuer.
        
        Args:
            common_name: Le CN (nom principal)
            organization: Nom de l'organisation
            country: Code pays (2 lettres)
            
        Returns:
            Un objet x509.Name
        
        Point important : NameOID permet d'identifier les champs standardisés
        """
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

    def create_ca_certificate(self,
        private_key: rsa.RSAPrivateKey,
        common_name: str = "ELK-CA",
        validity_days: int = 3650,  # 10 ans
        organization: str = "ELK-DevOps",
        country: str = "MG"
        ) -> x509.Certificate:
        """
        Crée un certificat auto-signé pour la Certificate Authority.
        
        Auto-signé signifie : Subject = Issuer (la CA se signe elle-même)
        
        Args:
            private_key: Clé privée de la CA
            common_name: Nom de la CA
            validity_days: Durée de validité en jours
            
        Returns:
            Un certificat X.509
        """
        if private_key is None:
            raise ValueError("La clé privée de la CA doit être fournie pour créer le certificat CA.")

        # 1. Créer le Subject et l'Issuer (identiques pour auto-signé)
        subject = issuer = self.create_name(common_name, organization, country)
        
        print(f"📝 Création du certificat CA : {common_name}")
        
        # 2. Construire le certificat avec CertificateBuilder
        cert = (
            x509.CertificateBuilder()
            
            # Qui possède ce certificat
            .subject_name(subject)
            
            # Qui a signé ce certificat (soi-même pour une CA)
            .issuer_name(issuer)
            
            # La clé publique du propriétaire
            .public_key(private_key.public_key())
            
            # Numéro de série unique (généré aléatoirement)
            .serial_number(x509.random_serial_number())
            
            # Période de validité
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            
            # EXTENSION 1 : BasicConstraints
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,  # Cette extension est critique (doit être comprise)
            )
            
            # EXTENSION 2 : KeyUsage
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,   # Peut signer
                    key_cert_sign=True,       # Peut signer des certificats ← Important pour CA
                    crl_sign=True,            # Peut signer des listes de révocation
                    key_encipherment=False,   # Ne chiffre pas de clés
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # 3. Signer le certificat avec la clé privée de la CA
            .sign(private_key, hashes.SHA256())
        )
        
        print(f"✅ Certificat CA créé (valide {validity_days} jours)")
        
        return cert