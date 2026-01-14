# 🔒 Recommandations de Sécurité PKI - ELK

## ⚠️ PROBLÈMES CRITIQUES DÉTECTÉS

### 1. **CLÉS PRIVÉES NON CHIFFRÉES**
**Risque** : Haute criticité  
**Fichier** : `utils/KeyManager.py`

```python
# ❌ ACTUEL : Clés stockées en clair
encryption_algorithm=serialization.NoEncryption()
```

**Solution recommandée** :
```python
# ✅ À IMPLÉMENTER : Clés protégées par mot de passe
from cryptography.hazmat.primitives import serialization
import getpass

password = getpass.getpass("Mot de passe pour la clé CA: ").encode()

encryption_algorithm=serialization.BestAvailableEncryption(password)
```

---

### 2. **PERMISSIONS FICHIERS**
**Risque** : Moyen  
Les permissions sont correctes (600 pour privées, 644 pour publiques) ✅

---

### 3. **VALIDITÉ DES CERTIFICATS**

#### CA
- **Validité** : 10 ans (3650 jours) ✅
- **Taille clé** : 4096 bits ✅

#### Services (Elasticsearch, Logstash, Kibana)
- **Validité** : 1 an (365 jours) ✅
- **Taille clé** : 2048 bits ✅

⚠️ **ATTENTION** : Prévoir un renouvellement **avant expiration** !

---

### 4. **MANQUE DE VALIDATION**

Aucune vérification après génération des certificats. À ajouter :

```python
def verify_certificate_chain(self, service_cert_path: Path) -> bool:
    """Vérifie que le certificat est valide et signé par la CA."""
    import subprocess
    
    ca_cert = self.output_dir / "ca" / "ca_cert.pem"
    
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca_cert), str(service_cert_path)],
        capture_output=True,
        text=True
    )
    
    return result.returncode == 0
```

---

### 5. **GESTION DES ERREURS**

✅ Bonne gestion des exceptions dans `main.py`  
✅ Messages d'erreur clairs

---

## 📋 CHECKLIST DE SÉCURITÉ

### Avant déploiement en production :

- [ ] **Chiffrer les clés privées** avec un mot de passe fort
- [ ] **Stocker les mots de passe** dans un gestionnaire sécurisé (Vault, AWS Secrets Manager)
- [ ] **Sauvegarder la CA** dans un endroit sûr et hors-ligne
- [ ] **Vérifier les certificats** après génération avec `openssl verify`
- [ ] **Configurer la rotation** des certificats avant expiration
- [ ] **Restreindre l'accès** au dossier `certs_output/` (chmod 700)
- [ ] **Ne jamais commiter** les clés privées dans Git
- [ ] **Ajouter au .gitignore** : `certs_output/`, `*.pem`, `*.key`

---

## 🔐 BONNES PRATIQUES ELK

### Pour Elasticsearch :
```yaml
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: /certs/elasticsearch/keys/elasticsearch_private.pem
xpack.security.transport.ssl.certificate: /certs/elasticsearch/elasticsearch_cert.pem
xpack.security.transport.ssl.certificate_authorities: ["/certs/ca/ca_cert.pem"]
```

### Pour Logstash :
```ruby
output {
  elasticsearch {
    ssl => true
    ssl_certificate_verification => true
    cacert => "/certs/ca/ca_cert.pem"
    client_cert => "/certs/logstash/logstash_cert.pem"
    client_key => "/certs/logstash/keys/logstash_private.pem"
  }
}
```

### Pour Kibana :
```yaml
elasticsearch.ssl.certificateAuthorities: ["/certs/ca/ca_cert.pem"]
elasticsearch.ssl.certificate: "/certs/kibana/kibana_cert.pem"
elasticsearch.ssl.key: "/certs/kibana/keys/kibana_private.pem"
elasticsearch.ssl.verificationMode: certificate
```

---

## 🚨 ERREURS À ÉVITER

1. ❌ **Ne pas utiliser les mêmes certificats en dev et prod**
2. ❌ **Ne pas partager la clé privée de la CA**
3. ❌ **Ne pas laisser expirer les certificats**
4. ❌ **Ne pas ignorer les avertissements de validation**
5. ❌ **Ne pas utiliser `verification_mode: none` en production**

---

## 📅 CALENDRIER DE MAINTENANCE

| Tâche | Fréquence | Prochaine date |
|-------|-----------|----------------|
| Vérifier expiration certificats | Mensuel | - |
| Renouveler certificats services | Annuel | - |
| Audit sécurité PKI | Trimestriel | - |
| Backup CA | Hebdomadaire | - |

---

## 🔍 COMMANDES DE VÉRIFICATION

```bash
# Vérifier le certificat Elasticsearch
openssl x509 -in certs_output/elasticsearch/elasticsearch_cert.pem -text -noout

# Vérifier la chaîne de confiance
openssl verify -CAfile certs_output/ca/ca_cert.pem certs_output/elasticsearch/elasticsearch_cert.pem

# Vérifier la date d'expiration
openssl x509 -in certs_output/elasticsearch/elasticsearch_cert.pem -noout -enddate

# Vérifier les extensions
openssl x509 -in certs_output/elasticsearch/elasticsearch_cert.pem -noout -ext extendedKeyUsage,subjectAltName
```
