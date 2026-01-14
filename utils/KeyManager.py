from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from dataclasses import dataclass

@dataclass
class KeyManager:
    key_dir : Path

    def __post_init__(self):
        self.key_dir.mkdir(parents=True, exist_ok=True)
    
    def create_rsa_keypair(self, key_name: str, key_size: int = 2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_path = self.key_dir / f"{key_name}_private.pem"
        public_key_path = self.key_dir / f"{key_name}_public.pem"

        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
            private_key_path.chmod(0o600)  # Restrict permissions
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
            public_key_path.chmod(0o644)  # Public key can be more permissive

        return {
            "private_key": private_key,
            "public_key": public_key,
            "private_key_path": private_key_path,
            "public_key_path": public_key_path
        }