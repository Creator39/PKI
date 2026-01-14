from generate_certs import ELKCertGenerator
from pathlib import Path

def main():
    """Point d'entrée du script de génération."""
    
    # Configuration
    config_path = Path("./certs_config.yaml")
    output_dir = Path("./certs_output")
    
    try:
        # Créer le générateur
        generator = ELKCertGenerator(
            config_path=config_path,
            output_dir=output_dir
        )
        
        # Générer tous les certificats
        generator.generate_all()
        
        return 0
        
    except FileNotFoundError as e:
        print(f"❌ Erreur : {e}")
        print(f"   Assurez-vous que {config_path} existe.")
        return 1
    
    except KeyError as e:
        print(f"❌ Configuration invalide : {e}")
        return 1
    
    except Exception as e:
        print(f"❌ Erreur inattendue : {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())