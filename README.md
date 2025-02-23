# Djaws Secret

Un outil OSINT (Open Source Intelligence) autonome et puissant pour la collecte d'informations, développé en Python.

```ascii
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================
```

## Fonctionnalités Avancées

### Découverte de Sous-domaines et Répertoires
- Scan asynchrone de sous-domaines courants
- Détection des titres de pages pour chaque sous-domaine
- Découverte de répertoires sensibles (/admin, /phpmyadmin, etc.)
- Détection de fichiers de configuration exposés (.env, .git, etc.)

### Analyse des Technologies
- Détection précise des technologies web avec versions
- Identification des frameworks et CMS
- Détection des bibliothèques JavaScript
- Analyse des serveurs web et de leurs versions
- Recherche automatique de vulnérabilités (CVE) associées

### Scan de Ports Avancé
- Utilisation de nmap pour une détection précise
- Identification des versions des services
- Détection des produits sur chaque port
- Fallback sur scan TCP basique si nécessaire

### Détection des Réseaux Sociaux
- Support multi-plateformes (Facebook, Twitter, LinkedIn, etc.)
- Détection via Wayback Machine
- Extraction avancée des profils sociaux
- Support des nouveaux formats d'URL (x.com, etc.)

### Analyse de Sécurité
- Détection des vulnérabilités avec scores CVSS
- Identification des technologies obsolètes
- Repérage des fichiers sensibles exposés
- Analyse des en-têtes de sécurité

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

3. (Optionnel) Configuration des API :
Pour une analyse plus approfondie des vulnérabilités, vous pouvez configurer une clé API Vulners :
- Obtenez une clé API sur [vulners.com](https://vulners.com)
- Ajoutez votre clé dans le script (variable vulners_api)

## Utilisation

```bash
python djaws_secret.py --target example.com
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

[*] Cible: example.com

==================================================
Résultats pour example.com
==================================================

Adresses IP:
  - 93.184.216.34

Sous-domaines:
  - www.example.com (93.184.216.34) - Example Domain
  - mail.example.com (93.184.216.34) - Mail Server

Ports ouverts:
  - 80/tcp (http) - Version: Apache/2.4.41
  - 443/tcp (https) - Version: nginx/1.18.0
  - 25/tcp (smtp) - Produit: Postfix

Technologies détectées:
  - Apache: 2.4.41
  - PHP: 7.4.3
  - WordPress: 5.8.2
  - jQuery: 3.5.1

Vulnérabilités:
  - Technologie: WordPress
    Version: 5.8.2
    CVE: CVE-2022-21661
    CVSS: 8.8
    Description: Vulnérabilité XSS dans l'éditeur

Répertoires sensibles:
  - /wp-admin (200)
  - /phpmyadmin (403)
  - /.git (403)

Réseaux sociaux:
  - Twitter: twitter.com/example
  - LinkedIn: linkedin.com/company/example
  - Facebook: facebook.com/example
```

## Note de Sécurité

Cet outil est destiné à des fins éducatives et de recherche légitimes uniquement. L'utilisation malveillante est strictement interdite. Certaines fonctionnalités (comme le scan de ports) peuvent être considérées comme intrusives, utilisez-les de manière responsable et uniquement sur des systèmes pour lesquels vous avez l'autorisation.

## Licence

MIT License
