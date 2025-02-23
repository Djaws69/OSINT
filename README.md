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

## Fonctionnalités

### Découverte de Sous-domaines
- Scan asynchrone de sous-domaines courants
- Détection des titres de pages pour chaque sous-domaine
- Identification des adresses IP associées

### Analyse des Technologies
- Détection précise des technologies web avec versions
- Identification des frameworks et CMS
- Détection des bibliothèques JavaScript
- Analyse des serveurs web et de leurs versions
- Recherche automatique de vulnérabilités (CVE) associées

### Scan de Ports
- Scan TCP des ports courants
- Identification des services
- Détection des versions quand possible

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

[*] Cible: example.com

==================================================
Résultats pour example.com
==================================================

Adresses IP:
  - 93.184.216.34

Sous-domaines:
  - www.example.com (93.184.216.34) - Example Domain

Ports ouverts:
  - 80/tcp (http)
  - 443/tcp (https)

Technologies détectées:
  - Apache: 2.4.41
  - PHP: 7.4.3
  - WordPress: 5.8.2

Vulnérabilités détectées:
  - WordPress 5.8.2
    CVE: CVE-2022-21661
    CVSS: 8.8
    Description: Vulnérabilité XSS dans l'éditeur
```

## Note de Sécurité

Cet outil est destiné à des fins éducatives et de recherche légitimes uniquement. L'utilisation malveillante est strictement interdite. Certaines fonctionnalités (comme le scan de ports) peuvent être considérées comme intrusives, utilisez-les de manière responsable et uniquement sur des systèmes pour lesquels vous avez l'autorisation.

## Licence

MIT License
