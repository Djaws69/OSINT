# Djaws Secret Scanner



```ascii
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================
```



## Installation

1. Cloner le repository :
```bash
git clone https://github.com/votre-username/djaws-secret.git
cd djaws-secret
```

2. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python djaws_scanner.py example.com
```

## Exemple de Sortie

```
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================

Cible: example.com

Adresses IP:
  - 93.184.216.34

Sous-domaines:
  - www.example.com (93.184.216.34) - Example Domain [https]
  - mail.example.com (93.184.216.34) - Webmail [http]

Ports ouverts:
  - 80/tcp (http)
  - 443/tcp (https)
  - 21/tcp (ftp)

Technologies détectées:
  - PHP: 7.4.4
  - WordPress: Detected
  - jQuery: Detected

Chemins sensibles découverts:
  - /wp-login.php (200) - WordPress Login
  - /wp-content/uploads (200) - Index of /uploads
  - /robots.txt (200) - Robots file
  - /.env (403) - Forbidden
