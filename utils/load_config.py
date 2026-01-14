import yaml
from pathlib import Path
from dataclasses import dataclass
    

class ConfigLoader:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = None
        self.load_config()
    
    def load_config(self) -> dict:
        try:
            if not self.config_path.exists() or not self.config_path.is_file():
                raise FileNotFoundError(f"Le fichier de configuration {self.config_path} est introuvable.")
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self.config = yaml.safe_load(file)
            if not isinstance(self.config, dict):
                raise ValueError("Le fichier de configuration doit contenir un dictionnaire YAML valide.")
        except FileNotFoundError as fnf_error:
            raise fnf_error
        except yaml.YAMLError as yaml_error:
            raise Exception(f"Erreur lors du chargement du YAML: {yaml_error}")
        except ValueError as val_error:
            raise val_error
        except Exception as e:
            raise Exception(f"Erreur lors de l'initialisation: {e}")
    
    def get_ca_config(self) -> dict[str, str | int]:
        if self.config is None or 'ca' not in self.config:
            raise KeyError("La configuration de l'autorité de certification est manquante.")
        return self.config['ca']
    
    def get_services_config(self) -> dict[str, dict[str, str | int]]:
        if self.config is None or 'services' not in self.config:
            raise KeyError("La configuration des services est manquante.")
        return self.config['services']