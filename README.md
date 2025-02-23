# Djaws Secret Scanner

Un outil OSINT (Open Source Intelligence) puissant pour l'analyse de sécurité des sites web, avec une attention particulière pour les sites WordPress et les établissements scolaires.

```ascii
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================
```

## Fonctionnalités

### 1. Découverte de Sous-domaines
- Scan asynchrone de sous-domaines courants
- Détection des titres de pages
- Identification des adresses IP
- Support des protocoles HTTP et HTTPS
- Vérification des serveurs de messagerie

### 2. Scan de Ports
- Détection des ports courants (21, 22, 23, 25, 53, 80, etc.)
- Identification des services (HTTP, HTTPS, FTP, SSH, etc.)
- Vérification des ports sensibles (phpMyAdmin, admin panels, etc.)
- Scan optimisé avec timeouts appropriés

### 3. Détection des Technologies
- Identification des CMS (WordPress, etc.)
- Détection des langages (PHP, etc.)
- Frameworks JavaScript (jQuery, etc.)
- Versions des technologies détectées

### 4. Énumération WordPress
- Page de connexion (/wp-login.php)
- Interface d'administration (/wp-admin)
- Fichiers sensibles (wp-config.php)
- Thèmes et plugins installés
- Utilisateurs WordPress
- Fichiers de sauvegarde potentiels

### 5. Chemins Sensibles
- Fichiers de configuration (.env, config.php)
- Fichiers système (robots.txt, .htaccess)
- Pages d'administration
- Dossiers exposés
- Fichiers de backup
- Pages spécifiques à l'éducation (ENT, Pronote, etc.)

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
```

## Caractéristiques Techniques

- Scan asynchrone pour des performances optimales
- Gestion intelligente des timeouts
- Support des protocoles HTTP/HTTPS
- Détection automatique des technologies
- Interface colorée pour une meilleure lisibilité
- Barre de progression pour les opérations longues

## Note de Sécurité

Cet outil est destiné à des fins éducatives et de recherche légitimes uniquement. L'utilisation malveillante est strictement interdite. Certaines fonctionnalités peuvent être considérées comme intrusives, utilisez-les de manière responsable et uniquement sur des systèmes pour lesquels vous avez l'autorisation.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles fonctionnalités
- Améliorer la documentation
- Soumettre des pull requests

## Licence

MIT License
