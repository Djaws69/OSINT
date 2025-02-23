#!/usr/bin/env python3

import sys
import socket
import asyncio
import aiohttp
import httpx
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
from fake_useragent import UserAgent
from wappalyzer import Wappalyzer, WebPage
from vulners import Vulners

init()  # Initialize colorama

class OsintToolkit:
    def __init__(self):
        self.ua = UserAgent()
        self.headers = {'User-Agent': self.ua.random}
        self.target = None
        self.vulners_api = None  # Will be initialized if API key is provided
        self.wappalyzer = Wappalyzer.latest()
        self.results = {
            'ip_addresses': set(),
            'open_ports': set(),
            'subdomains': set(),
            'technologies': {},
            'vulnerabilities': []
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

    def basic_port_scan(self, target):
        """Scan de ports basique"""
        ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        
        for port in tqdm(ports, desc="Scanning ports"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        self.results['open_ports'].add(f"{port}/tcp ({service})")
                    except:
                        self.results['open_ports'].add(f"{port}/tcp (unknown)")
                sock.close()
            except:
                continue

    async def check_subdomain(self, session, domain):
        """Vérifie si un sous-domaine existe"""
        try:
            ip = socket.gethostbyname(domain)
            # Vérification HTTP
            url = f"http://{domain}"
            try:
                async with session.get(url, timeout=5) as response:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    title = soup.title.string.strip() if soup.title else "No title"
                    self.results['subdomains'].add(f"{domain} ({ip}) - {title}")
            except:
                self.results['subdomains'].add(f"{domain} ({ip})")
            self.results['ip_addresses'].add(ip)
        except:
            pass

    async def discover_subdomains(self):
        """Découverte des sous-domains"""
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'staging', 'api', 'cdn', 'shop', 'store', 'remote',
            'vpn', 'ns1', 'ns2', 'smtp', 'webmail', 'portal',
            'support', 'cloud', 'mx', 'email', 'app', 'apps'
        ]

        async with aiohttp.ClientSession() as session:
            tasks = []
            for subdomain in wordlist:
                full_domain = f"{subdomain}.{self.target}"
                task = asyncio.create_task(self.check_subdomain(session, full_domain))
                tasks.append(task)
            
            with tqdm(total=len(tasks), desc="Checking subdomains") as pbar:
                for coro in asyncio.as_completed(tasks):
                    await coro
                    pbar.update(1)

    async def detect_technologies(self, url):
        """Détecte les technologies utilisées"""
        try:
            async with httpx.AsyncClient(headers=self.headers, verify=False) as client:
                response = await client.get(url)
                webpage = WebPage(url, html=response.text, headers=dict(response.headers))
                techs = self.wappalyzer.analyze_with_versions(webpage)
                
                for tech, data in techs.items():
                    version = data.get('version', ['Unknown'])[0]
                    self.results['technologies'][tech] = version

                    # Recherche de vulnérabilités si une clé API Vulners est configurée
                    if self.vulners_api and version != 'Unknown':
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

    async def gather_info(self):
        """Collecte les informations de base"""
        try:
            # Résolution DNS initiale
            ip = socket.gethostbyname(self.target)
            self.results['ip_addresses'].add(ip)

            # Découverte des sous-domaines
            print("\nRecherche des sous-domaines...")
            await self.discover_subdomains()

            # Scan des ports
            print("\nScan des ports en cours...")
            self.basic_port_scan(ip)

            # Détection des technologies
            print("\nDétection des technologies...")
            await self.detect_technologies(f"http://{self.target}")
            await self.detect_technologies(f"https://{self.target}")

        except Exception as e:
            print(f"Erreur lors de la résolution DNS: {str(e)}")
            return

        # Affichage des résultats
        self.print_results()

    def print_results(self):
        """Affiche les résultats de manière organisée"""
        print("\n" + "="*50)
        print(f"Résultats pour {self.target}")
        print("="*50 + "\n")

        sections = {
            'Adresses IP': self.results['ip_addresses'],
            'Sous-domaines': self.results['subdomains'],
            'Ports ouverts': self.results['open_ports']
        }

        for title, items in sections.items():
            if items:
                print(f"\n{Fore.GREEN}{title}:{Style.RESET_ALL}")
                for item in items:
                    print(f"  - {item}")

        if self.results['technologies']:
            print(f"\n{Fore.GREEN}Technologies détectées:{Style.RESET_ALL}")
            for tech, version in self.results['technologies'].items():
                print(f"  - {tech}: {version}")

        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}Vulnérabilités détectées:{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  - {vuln['technology']} {vuln['version']}")
                print(f"    CVE: {vuln['cve']}")
                print(f"    CVSS: {vuln['cvss']}")
                print(f"    Description: {vuln['description']}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python osint_scanner.py <domaine>")
        sys.exit(1)

    toolkit = OsintToolkit()
    toolkit.target = sys.argv[1]
    toolkit.print_banner()
    print(f"\n[*] Cible: {sys.argv[1]}")
    asyncio.run(toolkit.gather_info())
