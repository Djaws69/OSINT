#!/usr/bin/env python3
import argparse
import dns.resolver
import requests
import json
import socket
import asyncio
import aiohttp
import nmap
import httpx
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
from fake_useragent import UserAgent
import re
import concurrent.futures
from wappalyzer import Wappalyzer, WebPage
from vulners import Vulners
from waybackpy import WaybackMachineURLs
import async_timeout
from socid_extractor import extract

init()  # Initialize colorama

class OsintToolkit:
    def __init__(self):
        self.ua = UserAgent()
        self.headers = {'User-Agent': self.ua.random}
        self.target = None
        self.vulners_api = Vulners(api_key="YOUR_VULNERS_API_KEY")  # Optionnel pour les CVE
        self.wappalyzer = Wappalyzer.latest()
        self.results = {
            'subdomains': set(),
            'directories': set(),
            'emails': set(),
            'social_media': set(),
            'technologies': {},  # Changed to dict to store versions
            'ip_addresses': set(),
            'open_ports': set(),
            'vulnerabilities': [],
            'wayback_urls': set()
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

    async def advanced_port_scan(self, target):
        """Scan avancé des ports avec nmap"""
        try:
            nm = nmap.PortScanner()
            # Scan des ports les plus courants avec détection de version
            nm.scan(target, arguments='-sV -sS -F --version-intensity 5')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        if service['state'] == 'open':
                            service_info = f"{port}/{proto} ({service['name']})"
                            if service['version']:
                                service_info += f" - Version: {service['version']}"
                            if service['product']:
                                service_info += f" - Produit: {service['product']}"
                            self.results['open_ports'].add(service_info)
        except Exception as e:
            print(f"Erreur lors du scan nmap: {str(e)}")
            # Fallback sur le scan de base si nmap échoue
            await self.basic_port_scan(target)

    async def basic_port_scan(self, target, ports=None):
        """Scan de ports basique en cas d'échec de nmap"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        
        open_ports = set()
        for port in tqdm(ports, desc="Scanning ports"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        open_ports.add(f"{port}/tcp ({service})")
                    except:
                        open_ports.add(f"{port}/tcp (unknown)")
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

    async def discover_directories(self):
        """Découverte des répertoires et fichiers sensibles"""
        common_paths = [
            'admin', 'administrator', 'phpmyadmin', 'mysql', 'wp-admin',
            'cp', 'cpanel', 'webmail', 'mail', 'webapp', 'api',
            'dev', 'development', 'test', 'testing', 'beta',
            'backup', 'backups', 'db', 'database', 'old', 'new',
            'wp-content', 'wp-includes', 'upload', 'uploads',
            'files', 'file', 'admin.php', 'login.php', 'config.php',
            '.git', '.env', 'robots.txt', 'sitemap.xml',
            'jenkins', 'jira', 'stage', 'staging', 'prod',
            'api/v1', 'api/v2', 'swagger', 'docs'
        ]

        async with aiohttp.ClientSession(headers=self.headers) as session:
            for path in tqdm(common_paths, desc="Scanning directories"):
                url = f"http://{self.target}/{path}"
                try:
                    async with session.get(url, timeout=5) as response:
                        if response.status < 404:
                            self.results['directories'].add(f"{path} ({response.status})")
                except:
                    continue

    async def discover_subdomains(self):
        """Découverte avancée de sous-domains"""
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'staging', 'api', 'cdn', 'shop', 'store', 'remote',
            'vpn', 'ns1', 'ns2', 'smtp', 'webmail', 'portal',
            'support', 'cloud', 'mx', 'email', 'app', 'apps',
            'gateway', 'proxy', 'backup', 'git', 'jenkins',
            'jira', 'wiki', 'docs', 'internal', 'intranet',
            'extranet', 'tools', 'services', 'media', 'images',
            'files', 'beta', 'alpha', 'demo', 'login', 'db',
            'database', 'auth', 'api-dev', 'staging-api', 'dev-www'
        ]

        tasks = []
        async with aiohttp.ClientSession() as session:
            for subdomain in wordlist:
                full_domain = f"{subdomain}.{self.target}"
                task = asyncio.create_task(self.check_subdomain(session, full_domain))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)

    async def check_subdomain(self, session, domain):
        """Vérifie si un sous-domaine existe"""
        try:
            ip = socket.gethostbyname(domain)
            # Vérification HTTP
            url = f"http://{domain}"
            try:
                async with session.get(url, timeout=5) as response:
                    title = await self.get_title(response)
                    self.results['subdomains'].add(f"{domain} ({ip}) - {title}")
            except:
                self.results['subdomains'].add(f"{domain} ({ip})")
            self.results['ip_addresses'].add(ip)
        except:
            pass

    async def get_title(self, response):
        """Extrait le titre d'une page web"""
        try:
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            return soup.title.string.strip() if soup.title else "No title"
        except:
            return "No title"

    async def detect_technologies_and_versions(self, url):
        """Détecte les technologies et leurs versions"""
        try:
            async with httpx.AsyncClient(headers=self.headers, verify=False) as client:
                response = await client.get(url)
                webpage = WebPage(url, html=response.text, headers=dict(response.headers))
                techs = self.wappalyzer.analyze_with_versions(webpage)
                
                for tech, data in techs.items():
                    version = data.get('version', ['Unknown'])[0]
                    self.results['technologies'][tech] = version
                    
                    # Recherche de vulnérabilités si une version est détectée
                    if version != 'Unknown':
                        try:
                            vulns = self.vulners_api.software_vulnerabilities(tech, version)
                            if vulns:
                                for vuln in vulns:
                                    self.results['vulnerabilities'].append({
                                        'technology': tech,
                                        'version': version,
                                        'cve': vuln.get('id'),
                                        'cvss': vuln.get('cvss', {}).get('score', 'N/A'),
                                        'description': vuln.get('description')
                                    })
                        except:
                            pass
        except Exception as e:
            print(f"Erreur lors de la détection des technologies: {str(e)}")

    async def enhanced_social_media_search(self):
        """Recherche avancée de profils sociaux"""
        social_patterns = {
            'Facebook': [
                r'facebook\.com/[\w\.-]+',
                r'fb\.com/[\w\.-]+',
                r'facebook\.com/people/[\w\.-]+',
                r'facebook\.com/groups/[\w\.-]+'
            ],
            'Twitter': [
                r'twitter\.com/[\w\.-]+',
                r'x\.com/[\w\.-]+',
                r't\.co/[\w\.-]+'
            ],
            'LinkedIn': [
                r'linkedin\.com/company/[\w\.-]+',
                r'linkedin\.com/in/[\w\.-]+',
                r'linkedin\.com/school/[\w\.-]+'
            ],
            'Instagram': [
                r'instagram\.com/[\w\.-]+',
                r'instagr\.am/[\w\.-]+'
            ],
            'YouTube': [
                r'youtube\.com/channel/[\w\.-]+',
                r'youtube\.com/c/[\w\.-]+',
                r'youtube\.com/user/[\w\.-]+'
            ],
            'GitHub': [
                r'github\.com/[\w\.-]+',
                r'raw\.githubusercontent\.com/[\w\.-]+'
            ],
            'Medium': [
                r'medium\.com/@[\w\.-]+',
                r'medium\.com/[\w\.-]+'
            ]
        }

        # Recherche dans la Wayback Machine
        try:
            wayback = WaybackMachineURLs(self.target)
            urls = await wayback.get_snapshot_urls()
            for url in urls:
                for platform, patterns in social_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, url)
                        for match in matches:
                            self.results['social_media'].add(f"{platform}: {match}")
        except:
            pass

        # Recherche via socid_extractor
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://{self.target}")
                items = extract(response.text)
                for item in items:
                    self.results['social_media'].add(f"{item['type']}: {item['value']}")
        except:
            pass

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
        await self.advanced_port_scan(self.target)

        # Découverte des répertoires
        await self.discover_directories()

        # Découverte avancée des sous-domaines
        await self.discover_subdomains()

        # Récupération et analyse de la page web
        url = f"http://{self.target}"
        await self.detect_technologies_and_versions(url)

        # Recherche avancée de profils sociaux
        await self.enhanced_social_media_search()

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
            'Réseaux sociaux': self.results['social_media'],
            'Répertoires': self.results['directories'],
            'Vulnérabilités': self.results['vulnerabilities']
        }

        for title, items in sections.items():
            if items:
                print(f"\n{Fore.GREEN}{title}:{Style.RESET_ALL}")
                if title == 'Vulnérabilités':
                    for item in items:
                        print(f"  - Technologie: {item['technology']}")
                        print(f"    Version: {item['version']}")
                        print(f"    CVE: {item['cve']}")
                        print(f"    CVSS: {item['cvss']}")
                        print(f"    Description: {item['description']}\n")
                else:
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
