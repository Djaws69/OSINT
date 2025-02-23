#!/usr/bin/env python3
import argparse
import dns.resolver
import requests
import json
import socket
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
from fake_useragent import UserAgent
import re
import concurrent.futures

init()  # Initialize colorama

class OsintToolkit:
    def __init__(self):
        self.ua = UserAgent()
        self.headers = {'User-Agent': self.ua.random}
        self.target = None
        self.results = {
            'subdomains': set(),
            'emails': set(),
            'social_media': set(),
            'technologies': set(),
            'ip_addresses': set(),
            'open_ports': set()
        }

    def print_banner(self):
        banner = """
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)

    async def fetch_page(self, url):
        """Récupère une page web de manière asynchrone"""
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        return await response.text()
        except Exception:
            return None

    def extract_emails(self, text):
        """Extrait les adresses email du texte"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return set(re.findall(email_pattern, text))

    def extract_social_media(self, text):
        """Extrait les liens vers les réseaux sociaux"""
        social_patterns = {
            'Facebook': r'facebook\.com/[\w\.-]+',
            'Twitter': r'twitter\.com/[\w\.-]+',
            'LinkedIn': r'linkedin\.com/[\w\.-]+',
            'Instagram': r'instagram\.com/[\w\.-]+',
            'GitHub': r'github\.com/[\w\.-]+'
        }
        
        results = set()
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text)
            results.update([f"{platform}: {match}" for match in matches])
        return results

    async def scan_ports(self, target, ports):
        """Scanner les ports ouverts"""
        open_ports = set()
        for port in tqdm(ports, desc="Scanning ports"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    open_ports.add(f"{port}/tcp ({service})")
                sock.close()
            except:
                continue
        return open_ports

    async def enumerate_subdomains(self, domain):
        """Énumère les sous-domaines"""
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
                           'staging', 'api', 'cdn', 'shop', 'store', 'remote']
        
        for subdomain in tqdm(common_subdomains, desc="Enumerating subdomains"):
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                self.results['subdomains'].add(f"{full_domain} ({ip})")
                self.results['ip_addresses'].add(ip)
            except:
                continue

    def detect_technologies(self, html):
        """Détecte les technologies utilisées sur le site"""
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'React': ['react.development.js', 'react.production.min.js'],
            'Angular': ['ng-app', 'angular.js'],
            'PHP': ['php'],
            'ASP.NET': ['asp.net', '.aspx'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'CloudFlare': ['cloudflare']
        }

        detected = set()
        for tech, signatures in tech_signatures.items():
            if any(sig in html.lower() for sig in signatures):
                detected.add(tech)
        return detected

    async def gather_info(self):
        """Collecte toutes les informations"""
        print(Fore.GREEN + "\n[+] Démarrage de la collecte d'informations..." + Style.RESET_ALL)

        # Résolution DNS
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip_addresses'].add(ip)
            print(f"\nIP principale: {ip}")
        except Exception as e:
            print(Fore.RED + f"[-] Erreur DNS: {str(e)}" + Style.RESET_ALL)

        # Scan des sous-domaines
        await self.enumerate_subdomains(self.target)

        # Scan des ports courants
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        self.results['open_ports'] = await self.scan_ports(self.target, common_ports)

        # Récupération et analyse de la page web
        url = f"http://{self.target}"
        html_content = await self.fetch_page(url)
        if html_content:
            # Extraction des emails
            self.results['emails'].update(self.extract_emails(html_content))
            
            # Extraction des réseaux sociaux
            self.results['social_media'].update(self.extract_social_media(html_content))
            
            # Détection des technologies
            self.results['technologies'].update(self.detect_technologies(html_content))

        # Affichage des résultats
        self.print_results()

    def print_results(self):
        """Affiche les résultats de manière organisée"""
        print("\n" + "="*50)
        print(Fore.YELLOW + f"Résultats pour {self.target}" + Style.RESET_ALL)
        print("="*50)

        sections = {
            'Adresses IP': self.results['ip_addresses'],
            'Sous-domaines': self.results['subdomains'],
            'Ports ouverts': self.results['open_ports'],
            'Technologies détectées': self.results['technologies'],
            'Adresses email': self.results['emails'],
            'Réseaux sociaux': self.results['social_media']
        }

        for title, items in sections.items():
            if items:
                print(f"\n{Fore.GREEN}{title}:{Style.RESET_ALL}")
                for item in items:
                    print(f"  - {item}")

def main():
    parser = argparse.ArgumentParser(description="OSINT Toolkit - Outil de collecte d'informations")
    parser.add_argument("--target", required=True, help="Domaine ou IP cible")
    args = parser.parse_args()

    toolkit = OsintToolkit()
    toolkit.print_banner()
    toolkit.target = args.target

    print(Fore.YELLOW + f"\n[*] Cible: {args.target}" + Style.RESET_ALL)
    
    asyncio.run(toolkit.gather_info())

if __name__ == "__main__":
    main()
