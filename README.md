# Djaws Secret

Un outil OSINT (Open Source Intelligence) autonome et puissant pour la collecte d'informations, développé en Python.

```ascii
     ____  _____ _____ _____ _____ 
    |    \|  _  |  |  |   __|   __|
    |  |  |     |  |  |__   |__   |
    |____/|__|__|\___/|_____|_____|
    =====================================================
          Secret OSINT Tool - By Djaws
    =====================================================
```

## Fonctionnalités

- Découverte de sous-domaines
- Scan de ports
- Détection des technologies web utilisées
- Extraction d'adresses email
- Découverte de profils sur les réseaux sociaux
- Résolution DNS et collecte d'adresses IP
- Analyse asynchrone pour des performances optimales

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
python djaws_secret.py --target example.com
```

L'outil effectuera automatiquement :
- La résolution DNS du domaine
- La recherche de sous-domaines courants
- Le scan des ports les plus utilisés
- L'extraction d'emails du site web
- La détection des technologies web
- La recherche de profils sociaux

## Exemple de sortie

```
     ____  _____ _____ _____ _____ 
    |    \|  _  |  |  |   __|   __|
    |  |  |     |  |  |__   |__   |
    |____/|__|__|\___/|_____|_____|
    =====================================================
          Secret OSINT Tool - By Djaws
    =====================================================

[*] Cible: example.com

Adresses IP:
  - 93.184.216.34

Sous-domaines:
  - www.example.com (93.184.216.34)
  - mail.example.com (93.184.216.34)

Ports ouverts:
  - 80/tcp (http)
  - 443/tcp (https)

Technologies détectées:
  - Nginx
  - jQuery

Réseaux sociaux:
  - Twitter: twitter.com/example
  - LinkedIn: linkedin.com/company/example
```

## Note de sécurité

Cet outil est destiné à des fins éducatives et de recherche légitimes uniquement. L'utilisation malveillante est strictement interdite.

## Licence

MIT License
