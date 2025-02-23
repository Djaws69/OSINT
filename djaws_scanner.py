import asyncio
import socket
import aiohttp
from bs4 import BeautifulSoup
from tqdm import tqdm
import sys
import re
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
            
            # Chemins courants
            '/api',
            '/api/v1',
            '/api/v2',
            '/docs',
            '/documentation',
            '/backup',
            '/bak',
            '/old',
            '/dev',
            '/test',
            '/temp',
            '/tmp',
            '/files',
            '/upload',
            '/uploads',
            '/media',
            '/static',
            '/assets',
            '/images',
            '/img',
            '/css',
            '/js',
            '/javascript',
            '/config',
            '/settings',
            '/setup',
            '/install',
            '/database',
            '/db',
            '/sql',
            '/mysql',
            '/phpmyadmin',
            '/phpinfo.php',
            '/info.php',
            '/.htaccess',
            '/.htpasswd',
            '/web.config',
            '/server-status',
            '/server-info',
            '/.well-known',
            '/security.txt',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.vscode',
            '/.idea',
            '/.git/config',
            '/.gitignore',
            '/.env.backup',
            '/.env.example',
            '/composer.json',
            '/composer.lock',
            '/package.json',
            '/package-lock.json',
            '/node_modules',
            '/vendor',
            '/log',
            '/logs',
            '/error_log',
            '/debug',
            '/console',
            '/status',
            '/health',
            '/metrics',
            '/swagger',
            '/swagger-ui',
            '/api-docs'
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
        ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPCBind
            135,   # MSRPC
            139,   # NetBIOS
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            993,   # IMAPS
            995,   # POP3S
            1433,  # MSSQL
            1521,  # Oracle
            2049,  # NFS
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            5985,  # WinRM HTTP
            5986,  # WinRM HTTPS
            6379,  # Redis
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
            8888,  # Alternative HTTP
            9090,  # Alternative HTTP
            9200,  # Elasticsearch
            27017, # MongoDB
            27018, # MongoDB Alternative
            27019, # MongoDB Web
            3000,  # Node.js / React
            4444,  # Metasploit
            6000,  # X11
            7001,  # WebLogic
            8081,  # Alternative HTTP
            8082,  # Alternative HTTP
            8083,  # Alternative HTTP
            8084,  # Alternative HTTP
            8085,  # Alternative HTTP
            8086,  # InfluxDB
            8087,  # Alternative HTTP
            8088,  # Alternative HTTP
            8089,  # Splunk
            8161,  # ActiveMQ Admin
            8443,  # Alternative HTTPS
            8880,  # Alternative HTTP
            9000,  # SonarQube
            9001,  # Alternative HTTP
            9042,  # Cassandra
            9043,  # Alternative HTTP
            9092,  # Kafka
            9200,  # Elasticsearch HTTP
            9300,  # Elasticsearch Transport
            10000, # Webmin
            11211, # Memcached
            15672, # RabbitMQ Management
            27017, # MongoDB
            50000, # SAP
            50070, # Hadoop
            50075, # Hadoop
            50090  # Hadoop
        ]

        print(f"\n{Fore.CYAN}Scan des ports en cours...{Style.RESET_ALL}")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.results['open_ports'].add(f"{port}/tcp")
                sock.close()
            except:
                pass

    async def detect_technologies(self, response):
        """Détection des technologies utilisées"""
        headers = response.headers
        html_content = await response.text()
        soup = BeautifulSoup(html_content, 'html.parser')

        # Dictionnaire pour stocker les technologies et leurs versions
        techs = {}

        # Détection via les en-têtes HTTP
        server = headers.get('Server', '')
        if server:
            # Détection Apache avec version
            if 'apache' in server.lower():
                apache_version = re.search(r'Apache/([0-9.]+)', server)
                if apache_version:
                    techs['Apache'] = apache_version.group(1)
                    # Détection des modules Apache
                    modules = []
                    if 'mod_ssl' in server.lower():
                        modules.append('mod_ssl')
                    if 'mod_perl' in server.lower():
                        modules.append('mod_perl')
                    if 'mod_python' in server.lower():
                        modules.append('mod_python')
                    if modules:
                        techs['Apache_Modules'] = ', '.join(modules)
                else:
                    techs['Apache'] = 'Version non détectée'

            # Détection Nginx avec version
            elif 'nginx' in server.lower():
                nginx_version = re.search(r'nginx/([0-9.]+)', server)
                if nginx_version:
                    techs['Nginx'] = nginx_version.group(1)
                else:
                    techs['Nginx'] = 'Version non détectée'

            # Détection IIS avec version
            elif 'iis' in server.lower():
                iis_version = re.search(r'IIS/([0-9.]+)', server)
                if iis_version:
                    techs['IIS'] = iis_version.group(1)
                else:
                    techs['IIS'] = 'Version non détectée'

            # Détection LiteSpeed avec version
            elif 'litespeed' in server.lower():
                ls_version = re.search(r'LiteSpeed/([0-9.]+)', server)
                if ls_version:
                    techs['LiteSpeed'] = ls_version.group(1)
                else:
                    techs['LiteSpeed'] = 'Version non détectée'

            # Autres serveurs
            else:
                techs['Server'] = server

        # Détection via les autres en-têtes
        if 'X-Powered-By' in headers:
            techs['Powered-By'] = headers['X-Powered-By']

        # Détection via les en-têtes spécifiques aux serveurs
        if 'X-AspNet-Version' in headers:
            techs['ASP.NET'] = headers['X-AspNet-Version']
        if 'X-AspNetMvc-Version' in headers:
            techs['ASP.NET MVC'] = headers['X-AspNetMvc-Version']

        # Détection du framework PHP
        if 'PHP' in server or ('X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']):
            php_version = re.search(r'PHP/([0-9.]+)', server + headers.get('X-Powered-By', ''))
            if php_version:
                techs['PHP'] = php_version.group(1)

        # Détection de WordPress et sa version
        if soup.find('meta', {'name': 'generator', 'content': re.compile(r'WordPress')}):
            wp_version = soup.find('meta', {'name': 'generator'})
            if wp_version:
                version = re.search(r'WordPress ([0-9.]+)', wp_version['content'])
                if version:
                    techs['WordPress'] = version.group(1)
                else:
                    techs['WordPress'] = 'Detected'

        # Détection des frameworks JavaScript
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            
            # jQuery
            if 'jquery' in src:
                jquery_version = re.search(r'jquery[.-]([0-9.]+)', src)
                if jquery_version:
                    techs['jQuery'] = jquery_version.group(1)
                else:
                    techs['jQuery'] = 'Detected'
            
            # React
            if 'react' in src:
                react_version = re.search(r'react[.-]([0-9.]+)', src)
                if react_version:
                    techs['React'] = react_version.group(1)
                else:
                    techs['React'] = 'Detected'
            
            # Vue.js
            if 'vue' in src:
                vue_version = re.search(r'vue[.-]([0-9.]+)', src)
                if vue_version:
                    techs['Vue.js'] = vue_version.group(1)
                else:
                    techs['Vue.js'] = 'Detected'
            
            # Angular
            if 'angular' in src:
                angular_version = re.search(r'angular[.-]([0-9.]+)', src)
                if angular_version:
                    techs['Angular'] = angular_version.group(1)
                else:
                    techs['Angular'] = 'Detected'

        # Détection des frameworks CSS
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '').lower()
            
            # Bootstrap
            if 'bootstrap' in href:
                bootstrap_version = re.search(r'bootstrap[.-]([0-9.]+)', href)
                if bootstrap_version:
                    techs['Bootstrap'] = bootstrap_version.group(1)
                else:
                    techs['Bootstrap'] = 'Detected'
            
            # Tailwind
            if 'tailwind' in href:
                tailwind_version = re.search(r'tailwind[.-]([0-9.]+)', href)
                if tailwind_version:
                    techs['Tailwind'] = tailwind_version.group(1)
                else:
                    techs['Tailwind'] = 'Detected'

        # Détection des CMS
        # Drupal
        if soup.find('meta', {'name': 'Generator', 'content': re.compile(r'Drupal')}):
            drupal_version = soup.find('meta', {'name': 'Generator'})
            if drupal_version:
                version = re.search(r'Drupal ([0-9.]+)', drupal_version['content'])
                if version:
                    techs['Drupal'] = version.group(1)
                else:
                    techs['Drupal'] = 'Detected'

        # Joomla
        if soup.find('meta', {'name': 'generator', 'content': re.compile(r'Joomla')}):
            joomla_version = soup.find('meta', {'name': 'generator'})
            if joomla_version:
                version = re.search(r'Joomla! ([0-9.]+)', joomla_version['content'])
                if version:
                    techs['Joomla'] = version.group(1)
                else:
                    techs['Joomla'] = 'Detected'

        # Détection des serveurs web via les en-têtes
        if 'nginx' in server.lower():
            nginx_version = re.search(r'nginx/([0-9.]+)', server)
            if nginx_version:
                techs['Nginx'] = nginx_version.group(1)
            else:
                techs['Nginx'] = 'Detected'

        if 'apache' in server.lower():
            apache_version = re.search(r'Apache/([0-9.]+)', server)
            if apache_version:
                techs['Apache'] = apache_version.group(1)
            else:
                techs['Apache'] = 'Detected'

        # Détection des langages backend via les cookies et en-têtes
        if 'PHPSESSID' in headers.get('Set-Cookie', ''):
            if 'PHP' not in techs:
                techs['PHP'] = 'Detected'

        if 'ASP.NET' in headers.get('X-Powered-By', ''):
            aspnet_version = re.search(r'ASP\.NET[_ ]([0-9.]+)', headers.get('X-AspNet-Version', ''))
            if aspnet_version:
                techs['ASP.NET'] = aspnet_version.group(1)
            else:
                techs['ASP.NET'] = 'Detected'

        # Détection des frameworks backend
        if 'laravel' in headers.get('Set-Cookie', '').lower():
            techs['Laravel'] = 'Detected'

        if 'django' in headers.get('X-Framework', '').lower():
            techs['Django'] = 'Detected'

        if 'rails' in headers.get('X-Powered-By', '').lower():
            techs['Ruby on Rails'] = 'Detected'

        # Mise à jour des résultats
        for tech, version in techs.items():
            self.results['technologies'].add(f"{tech}: {version}")

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
            try:
                async with session.get(f"https://{self.target}", timeout=5, ssl=False) as response:
                    await self.detect_technologies(response)
            except:
                pass
            
            # Énumération des chemins pour le domaine principal
            await self.enumerate_paths(session, f"https://{self.target}")

        self.display_results()

    def display_results(self):
        """Affiche les résultats"""
        print(f"\n{Fore.GREEN}================================================")
        print(f"Résultats pour {self.target}")
        print(f"================================================{Style.RESET_ALL}\n")

        # Affichage des adresses IP
        if self.results['ip_addresses']:
            print(f"{Fore.YELLOW}[+] Adresses IP:{Style.RESET_ALL}")
            for ip in sorted(self.results['ip_addresses']):
                print(f"  - {ip}")
            print()

        # Affichage des sous-domaines
        if self.results['subdomains']:
            print(f"{Fore.YELLOW}[+] Sous-domaines découverts:{Style.RESET_ALL}")
            for subdomain in sorted(self.results['subdomains']):
                print(f"  - {subdomain}")
            print()

        # Affichage des ports ouverts
        if self.results['open_ports']:
            print(f"{Fore.YELLOW}[+] Ports ouverts:{Style.RESET_ALL}")
            for port in sorted(self.results['open_ports']):
                print(f"  - {port}")
            print()

        # Affichage des technologies
        if self.results['technologies']:
            print(f"{Fore.YELLOW}[+] Technologies détectées:{Style.RESET_ALL}")
            
            # Grouper les technologies par catégorie
            server_techs = []
            framework_techs = []
            cms_techs = []
            other_techs = []
            
            for tech in sorted(self.results['technologies']):
                if any(s in tech.lower() for s in ['apache', 'nginx', 'iis', 'litespeed']):
                    server_techs.append(tech)
                elif any(s in tech.lower() for s in ['php', 'asp.net', 'django', 'rails']):
                    framework_techs.append(tech)
                elif any(s in tech.lower() for s in ['wordpress', 'drupal', 'joomla']):
                    cms_techs.append(tech)
                else:
                    other_techs.append(tech)
            
            if server_techs:
                print("  [Serveurs Web]")
                for tech in server_techs:
                    print(f"  - {tech}")
            
            if framework_techs:
                print("\n  [Frameworks]")
                for tech in framework_techs:
                    print(f"  - {tech}")
            
            if cms_techs:
                print("\n  [CMS]")
                for tech in cms_techs:
                    print(f"  - {tech}")
            
            if other_techs:
                print("\n  [Autres Technologies]")
                for tech in other_techs:
                    print(f"  - {tech}")
            print()

        # Affichage des chemins sensibles
        if self.results['sensitive_paths']:
            print(f"{Fore.YELLOW}[+] Chemins sensibles découverts:{Style.RESET_ALL}")
            
            # Grouper les chemins par catégorie
            admin_paths = []
            config_paths = []
            sensitive_files = []
            other_paths = []
            
            for path in sorted(self.results['sensitive_paths']):
                if any(s in path.lower() for s in ['admin', 'login', 'wp-admin']):
                    admin_paths.append(path)
                elif any(s in path.lower() for s in ['.env', 'config', '.htaccess', '.git']):
                    config_paths.append(path)
                elif any(s in path.lower() for s in ['.php', '.json', '.xml', '.txt']):
                    sensitive_files.append(path)
                else:
                    other_paths.append(path)
            
            if config_paths:
                print("  [Fichiers de Configuration]")
                for path in config_paths:
                    print(f"  - {path}")
            
            if admin_paths:
                print("\n  [Interfaces d'Administration]")
                for path in admin_paths:
                    print(f"  - {path}")
            
            if sensitive_files:
                print("\n  [Fichiers Sensibles]")
                for path in sensitive_files:
                    print(f"  - {path}")
            
            if other_paths:
                print("\n  [Autres Chemins]")
                for path in other_paths:
                    print(f"  - {path}")
            print()

        print(f"{Fore.YELLOW}Note: Ces résultats sont fournis à titre informatif uniquement.{Style.RESET_ALL}\n")

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python {sys.argv[0]} <domain>{Style.RESET_ALL}")
        sys.exit(1)

    scanner = OsintScanner()
    scanner.target = sys.argv[1]
    asyncio.run(scanner.gather_info())

if __name__ == "__main__":
    main()
