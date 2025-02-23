import asyncio
import socket
import aiohttp
from bs4 import BeautifulSoup
from tqdm import tqdm
import sys
from colorama import Fore, Style, init

# Initialize colorama
init()

ascii_art = """
    ____     _ _____ _ _ _ _____ 
    |    \ ___ |  _  | | | |   __|
    |  |  |   ||     | | | |__   |
    |____/|___||__|__|_____|\_____|
    =====================================================
             Secret OSINT Tool
    =====================================================
"""

class OsintScanner:
    def __init__(self):
        self.target = None
        self.results = {
            'ip_addresses': set(),
            'subdomains': set(),
            'open_ports': set(),
            'technologies': set(),
            'sensitive_paths': set()
        }

    async def check_subdomain(self, session, domain):
        """Vérifie si un sous-domaine existe"""
        try:
            ip = socket.gethostbyname(domain)
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}"
                try:
                    async with session.get(url, timeout=5, ssl=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            soup = BeautifulSoup(text, 'html.parser')
                            title = soup.title.string.strip() if soup.title else "No title"
                            self.results['subdomains'].add(f"{domain} ({ip}) - {title} [{protocol}]")
                            break
                except:
                    continue
            
            if domain not in [s.split()[0] for s in self.results['subdomains']]:
                self.results['subdomains'].add(f"{domain} ({ip})")
            self.results['ip_addresses'].add(ip)
        except:
            pass

    async def discover_subdomains(self):
        """Découverte des sous-domains"""
        wordlist = [
            # Liste des sous-domaines comme avant...
            'www', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
            'remote', 'blog', 'test', 'dev', 'beta', 'secure', 'vpn',
            'ns1', 'ns2', 'dns1', 'dns2', 'dns', 'mx', 'mx1', 'mx2'
        ]

        print(f"\n{Fore.CYAN}Démarrage de l'énumération des sous-domaines...{Style.RESET_ALL}")
        print(f"Tentative sur {len(wordlist)} sous-domaines potentiels")

        async with aiohttp.ClientSession() as session:
            tasks = []
            for subdomain in wordlist:
                full_domain = f"{subdomain}.{self.target}"
                task = asyncio.create_task(self.check_subdomain(session, full_domain))
                tasks.append(task)
            
            with tqdm(total=len(tasks), desc="Vérification des sous-domaines") as pbar:
                for coro in asyncio.as_completed(tasks):
                    await coro
                    pbar.update(1)

    async def check_path(self, session, base_url, path):
        """Vérifie si un chemin existe"""
        url = f"{base_url.rstrip('/')}{path}"
        try:
            async with session.get(url, timeout=5, ssl=False) as response:
                if response.status != 404:
                    status = response.status
                    if status == 200:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        title = soup.title.string.strip() if soup.title else "No title"
                        self.results['sensitive_paths'].add(f"{path} ({status}) - {title}")
                    else:
                        self.results['sensitive_paths'].add(f"{path} ({status})")
        except:
            pass

    async def enumerate_paths(self, session, base_url):
        """Énumération des chemins sensibles"""
        paths = [
            # WordPress
            '/wp-login.php',
            '/wp-admin',
            '/wp-content',
            '/wp-includes',
            '/wp-content/plugins',
            '/wp-content/themes',
            '/wp-content/uploads',
            '/wp-json/wp/v2/users',
            '/author/1',
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.php~',
            '/wp-admin/install.php',
            '/wp-admin/setup-config.php',
            '/wp-admin/admin-ajax.php',
            
            # Admin et Login
            '/admin',
            '/administrator',
            '/login',
            '/panel',
            
            # Fichiers sensibles
            '/robots.txt',
            '/sitemap.xml',
            '/.env',
            '/.git',
            '/readme.html',
            '/license.txt',
            
            # Éducation
            '/moodle',
            '/contact',
            '/about',
            '/news',
            '/events',
            '/calendar',
            '/students',
            '/teachers',
            '/parents',
            '/library',
            '/resources',
            '/emploi-du-temps',
            '/pronote',
            '/ent',
            '/cdi',
            '/vie-scolaire',
            '/actualites',
            '/mentions-legales',
            '/plan-du-site'
        ]

        print(f"\n{Fore.CYAN}Énumération des chemins sensibles sur {base_url}...{Style.RESET_ALL}")
        print(f"Test de {len(paths)} chemins potentiels")

        tasks = []
        for path in paths:
            task = asyncio.create_task(self.check_path(session, base_url, path))
            tasks.append(task)
        
        with tqdm(total=len(tasks), desc="Vérification des chemins") as pbar:
            for coro in asyncio.as_completed(tasks):
                await coro
                pbar.update(1)

    async def scan_ports(self, ip):
        """Scan des ports courants"""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-proxy",
            8443: "https-alt"
        }

        print(f"\n{Fore.CYAN}Scan des ports en cours...{Style.RESET_ALL}")
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.results['open_ports'].add(f"{port}/tcp ({service})")
                sock.close()
            except:
                pass

    async def detect_technologies(self, session, url):
        """Détecte les technologies utilisées"""
        try:
            async with session.get(url, timeout=5, ssl=False) as response:
                if response.status == 200:
                    text = await response.text()
                    # WordPress
                    if 'wp-content' in text:
                        self.results['technologies'].add("WordPress: Detected")
                    # PHP
                    if 'PHP' in response.headers.get('X-Powered-By', ''):
                        self.results['technologies'].add(f"PHP: {response.headers['X-Powered-By']}")
                    # jQuery
                    if 'jquery' in text.lower():
                        self.results['technologies'].add("jQuery: Detected")
                    # Bootstrap
                    if 'bootstrap' in text.lower():
                        self.results['technologies'].add("Bootstrap: Detected")
        except:
            pass

    async def gather_info(self):
        """Collecte toutes les informations"""
        print(f"{Fore.GREEN}{ascii_art}{Style.RESET_ALL}")
        print(f"Cible: {self.target}")
        
        # Résolution DNS initiale
        try:
            main_ip = socket.gethostbyname(self.target)
            self.results['ip_addresses'].add(main_ip)
        except:
            print(f"{Fore.RED}Impossible de résoudre le domaine{Style.RESET_ALL}")
            return

        async with aiohttp.ClientSession() as session:
            # Découverte des sous-domaines
            await self.discover_subdomains()
            
            # Scan des ports
            await self.scan_ports(main_ip)
            
            # Détection des technologies
            await self.detect_technologies(session, f"https://{self.target}")
            
            # Énumération des chemins pour le domaine principal
            await self.enumerate_paths(session, f"https://{self.target}")

        self.display_results()

    def display_results(self):
        """Affiche les résultats"""
        print(f"\n{Fore.GREEN}================================================")
        print(f"Résultats pour {self.target}")
        print(f"================================================{Style.RESET_ALL}\n")

        if self.results['ip_addresses']:
            print(f"{Fore.YELLOW}Adresses IP:{Style.RESET_ALL}")
            for ip in sorted(self.results['ip_addresses']):
                print(f"  - {ip}")
            print()

        if self.results['subdomains']:
            print(f"{Fore.YELLOW}Sous-domaines:{Style.RESET_ALL}")
            for subdomain in sorted(self.results['subdomains']):
                print(f"  - {subdomain}")
            print()

        if self.results['open_ports']:
            print(f"{Fore.YELLOW}Ports ouverts:{Style.RESET_ALL}")
            for port in sorted(self.results['open_ports']):
                print(f"  - {port}")
            print()

        if self.results['technologies']:
            print(f"{Fore.YELLOW}Technologies détectées:{Style.RESET_ALL}")
            for tech in sorted(self.results['technologies']):
                print(f"  - {tech}")
            print()

        if self.results['sensitive_paths']:
            print(f"{Fore.YELLOW}Chemins sensibles découverts:{Style.RESET_ALL}")
            for path in sorted(self.results['sensitive_paths']):
                print(f"  - {path}")
            print()

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python {sys.argv[0]} <domain>{Style.RESET_ALL}")
        sys.exit(1)

    scanner = OsintScanner()
    scanner.target = sys.argv[1]
    asyncio.run(scanner.gather_info())

if __name__ == "__main__":
    main()
