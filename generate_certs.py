from pathlib import Path
import shutil
import os
from utils.CertificateManager import CertManager
from utils.KeyManager import KeyManager
from utils.load_config import ConfigLoader


class ELKCertGenerator:
    """
    Générateur de certificats pour la stack ELK.
    
    Usage:
        generator = ELKCertGenerator(
            config_path=Path("./certs_config.yaml"),
            output_dir=Path("./certs_output")
        )
        generator.generate_all()
    """
    
    def __init__(self, config_path: Path, output_dir: Path):
        """
        Initialise le générateur.
        
        Args:
            config_path: Chemin vers certs_config.yaml
            output_dir: Dossier de sortie pour tous les certificats
        """
        self.config_loader = ConfigLoader(config_path)
        self.output_dir = output_dir
        self.ca_private_key = None
        self.ca_certificate = None
    
    def generate_or_load_ca(self) -> None:
        """
        Génère ou charge la Certificate Authority.
        
        Idempotence : Si la CA existe déjà, elle est chargée.
        """
        ca_config = self.config_loader.get_ca_config()
        ca_path = self.output_dir / "ca"
        ca_key_dir = ca_path / "keys"
        ca_cert_file = ca_path / "ca_cert.pem"
        
        # Vérifier si CA existe déjà
        if ca_cert_file.exists():
            print("♻️  CA existante détectée, chargement...")
            
            # Charger la clé privée existante (ne pas la régénérer !)
            key_manager = KeyManager(key_dir=ca_key_dir)
            ca_key_file = ca_key_dir / "ca_private.pem"
            
            if not ca_key_file.exists():
                raise FileNotFoundError(
                    f"Certificat CA trouvé mais clé privée manquante: {ca_key_file}\n"
                    "Supprimez le dossier ca/ et régénérez tout."
                )
            
            self.ca_private_key = key_manager.load_private_key(ca_key_file)
            
            # Charger le certificat existant
            temp_cert_manager = CertManager(
                cert_path=ca_path,
                key_CA=self.ca_private_key,
                cert_CA=None
            )
            self.ca_certificate = temp_cert_manager.load_certificate_pem(ca_cert_file)
            
            print(f"✅ CA chargée depuis {ca_cert_file}")
            return
        
        # Générer nouvelle CA
        print("\n🔑 Génération de la CA...")
        print(f"   Common Name: {ca_config.get('common_name', 'ELK-Root-CA')}")
        print(f"   Validité: {ca_config.get('validity_days', 3650)} jours")
        print(f"   Taille clé: {ca_config.get('key_size', 4096)} bits")
        
        # Générer la clé CA
        key_manager = KeyManager(key_dir=ca_key_dir)
        ca_keypair = key_manager.create_rsa_keypair(
            key_name="ca",
            key_size=ca_config.get('key_size', 4096)
        )
        self.ca_private_key = ca_keypair["private_key"]
        
        # Créer un CertManager temporaire pour générer le certificat CA
        temp_cert_manager = CertManager(
            cert_path=ca_path,
            key_CA=self.ca_private_key,
            cert_CA=None
        )
        
        # Créer le certificat auto-signé
        self.ca_certificate = temp_cert_manager.create_ca_certificate(
            private_key=self.ca_private_key,
            common_name=ca_config.get('common_name', 'ELK-Root-CA'),
            validity_days=ca_config.get('validity_days', 3650),
            organization=ca_config.get('organization', 'ELK-DevOps'),
            country=ca_config.get('country', 'MG')
        )
        
        # Sauvegarder
        CertManager.save_certificate_pem(self.ca_certificate, ca_cert_file)
        
        print(f"✅ CA générée et sauvegardée dans {ca_path}")
    
    def generate_service_certificate(
        self,
        service_name: str,
        service_config: dict
    ) -> bool:
        """
        Génère un certificat pour un service spécifique.
        
        Args:
            service_name: Nom du service (ex: "elasticsearch")
            service_config: Configuration du service
            
        Returns:
            True si généré, False si skip (déjà existant)
        """
        service_path = self.output_dir / service_name
        service_key_dir = service_path / "keys"
        service_cert_file = service_path / f"{service_name}_cert.pem"
        
        # Vérifier si existe déjà
        if service_cert_file.exists():
            print(f"♻️  {service_name}: Certificat existant, skip")
            return False
        
        print(f"\n📋 Génération: {service_name}")
        print(f"   Type: {service_config.get('type', 'unknown')}")
        print(f"   Validité: {service_config.get('validity_days', 365)} jours")
        
        # Générer la clé du service
        key_manager = KeyManager(key_dir=service_key_dir)
        service_keypair = key_manager.create_rsa_keypair(
            key_name=service_name,
            key_size=service_config.get('key_size', 2048)
        )
        service_private_key = service_keypair["private_key"]
        
        # Créer le CertManager avec la CA
        cert_manager = CertManager(
            cert_path=service_path,
            key_CA=self.ca_private_key,
            cert_CA=self.ca_certificate
        )
        
        # Générer le certificat selon le type
        service_type = service_config.get('type')
        
        if service_type == "server":
            service_cert = cert_manager.create_server_certificate(
                server_private_key=service_private_key,
                common_name=service_name,
                dns_names=service_config.get('dns_names', []),
                ip_addresses=service_config.get('ip_addresses', []),
                validity_days=service_config.get('validity_days', 365)
            )
        elif service_type == "client":
            service_cert = cert_manager.create_client_certificate(
                client_private_key=service_private_key,
                common_name=service_name,
                validity_days=service_config.get('validity_days', 365)
            )
        else:
            raise ValueError(f"Type de service inconnu: {service_type}")
        
        # Sauvegarder le certificat
        CertManager.save_certificate_pem(service_cert, service_cert_file)
        
        # Copier ca_cert.pem dans le dossier du service
        ca_cert_copy = service_path / "ca_cert.pem"
        if not ca_cert_copy.exists():
            ca_source = self.output_dir / "ca" / "ca_cert.pem"
            shutil.copy(ca_source, ca_cert_copy)
            print(f"   📋 ca_cert.pem copié pour vérification")
        
        print(f"✅ {service_name}: Certificat généré")
        return True
    
    def generate_all_services(self) -> None:
        """
        Génère les certificats pour tous les services de la configuration.
        """
        print("\n" + "="*60)
        print("CERTIFICATS DES SERVICES")
        print("="*60)
        
        services_config = self.config_loader.get_services_config()
        
        for service_name, service_config in services_config.items():
            self.generate_service_certificate(service_name, service_config)
    
    def generate_all(self) -> None:
        """
        Génère tous les certificats : CA + services.
        
        Point d'entrée principal pour générer l'ensemble de l'infrastructure PKI.
        """
        print("\n" + "🔐 GÉNÉRATION DES CERTIFICATS ELK ".center(60, "="))
        print()
        
        # Charger la configuration
        ca_config = self.config_loader.get_ca_config()
        services_config = self.config_loader.get_services_config()
        
        print(f"✅ Configuration chargée")
        print(f"   CA: {ca_config.get('common_name', 'ELK-Root-CA')}")
        print(f"   Services: {', '.join(services_config.keys())}")
        
        # Générer/charger la CA
        print("\n" + "="*60)
        print("CERTIFICATE AUTHORITY")
        print("="*60)
        
        self.generate_or_load_ca()
        
        # Générer les certificats des services
        self.generate_all_services()
        
        # Corriger les permissions
        self.fix_permissions()
        
        # Récapitulatif
        self.display_summary()
    
    def fix_permissions(self) -> None:
        """
        Corrige les permissions des fichiers de certificats.
        
        Les fichiers de certificats doivent être lisibles par Elasticsearch (uid 1000).
        Les clés privées doivent être lisibles uniquement par le propriétaire.
        """
        print("\n" + "="*60)
        print("CORRECTION DES PERMISSIONS")
        print("="*60)
        
        # Vérifier si on tourne en root
        if os.getuid() != 0:
            print("⚠️  Avertissement : Ce script doit tourner en root pour changer le propriétaire des fichiers")
            print("   Les permissions seront définies mais le propriétaire restera inchangé")
        
        try:
            # Parcourir tous les fichiers dans output_dir
            for root, dirs, files in os.walk(self.output_dir):
                root_path = Path(root)
                
                # Permissions pour les dossiers: 755 (rwxr-xr-x)
                os.chmod(root_path, 0o755)
                
                # Changer le propriétaire pour Elasticsearch (UID 1000, GID 1000)
                if os.getuid() == 0:
                    os.chown(root_path, 1000, 1000)
                
                for file in files:
                    file_path = root_path / file
                    
                    if "private" in file.lower() or file_path.parent.name == "keys":
                        # Clés privées: 644 (rw-r--r--) pour permettre la lecture par Elasticsearch
                        os.chmod(file_path, 0o644)
                        print(f"✅ Permissions clé privée  : {file_path.relative_to(self.output_dir)} (644)")
                    else:
                        # Certificats publics: 644 (rw-r--r--)
                        os.chmod(file_path, 0o644)
                        print(f"✅ Permissions certificat : {file_path.relative_to(self.output_dir)} (644)")
                    
                    # Changer le propriétaire pour Elasticsearch (UID 1000, GID 1000)
                    if os.getuid() == 0:
                        os.chown(file_path, 1000, 1000)
            
            if os.getuid() == 0:
                print(f"\n✅ Permissions et propriétaire corrigés pour tous les fichiers")
                print(f"   Propriétaire: elasticsearch (UID 1000, GID 1000)")
            else:
                print(f"\n✅ Permissions corrigées (propriétaire inchangé)")
            
        except Exception as e:
            print(f"❌ Erreur lors de la correction des permissions : {e}")
            raise
    
    def verify_certificate_chain(self, service_name: str) -> bool:
        """
        Vérifie qu'un certificat de service est valide et signé par la CA.
        
        Args:
            service_name: Nom du service à vérifier
            
        Returns:
            True si valide, False sinon
        """
        import subprocess
        
        ca_cert = self.output_dir / "ca" / "ca_cert.pem"
        service_cert = self.output_dir / service_name / f"{service_name}_cert.pem"
        
        if not service_cert.exists():
            print(f"⚠️  Certificat {service_name} introuvable")
            return False
        
        try:
            result = subprocess.run(
                ["openssl", "verify", "-CAfile", str(ca_cert), str(service_cert)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                print(f"✅ {service_name}: Chaîne de confiance valide")
                return True
            else:
                print(f"❌ {service_name}: Erreur de validation")
                print(f"   {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⚠️  {service_name}: Timeout lors de la validation")
            return False
        except FileNotFoundError:
            print(f"⚠️  openssl n'est pas installé (validation ignorée)")
            return False

    def display_summary(self) -> None:
        """
        Affiche un récapitulatif de la génération.
        """
        print("\n" + "="*60)
        print("✅ GÉNÉRATION TERMINÉE")
        print("="*60 + "\n")
        
        services_config = self.config_loader.get_services_config()
        
        print(f"📁 Structure des certificats dans {self.output_dir}/")
        print(f"   ├── ca/")
        print(f"   │   ├── ca_cert.pem")
        print(f"   │   └── keys/ca_private.pem")
        
        for service_name in services_config.keys():
            print(f"   ├── {service_name}/")
            print(f"   │   ├── {service_name}_cert.pem")
            print(f"   │   ├── ca_cert.pem (copie)")
            print(f"   │   └── keys/{service_name}_private.pem")
        
        # Validation automatique
        print(f"\n🔍 Validation des certificats:")
        for service_name in services_config.keys():
            self.verify_certificate_chain(service_name)
        
        print(f"\n💡 Commandes de vérification manuelles :")
        print(f"   # Vérifier le certificat Elasticsearch")
        print(f"   openssl x509 -in {self.output_dir}/elasticsearch/elasticsearch_cert.pem -text -noout")
        print(f"\n   # Vérifier la chaîne de confiance")
        print(f"   openssl verify -CAfile {self.output_dir}/ca/ca_cert.pem {self.output_dir}/elasticsearch/elasticsearch_cert.pem")
        
        print("\n" + "="*60 + "\n")