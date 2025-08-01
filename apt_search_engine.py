import requests
from bs4 import BeautifulSoup
import re
import sys
import json
import os
import urllib.parse
from urllib.parse import quote, urljoin

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BEBEBLUE = '\033[94m'
VIOLET = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
ENDC = '\033[0m'
BOLD = '\033[1m'

def display_banner():
    print(f"{BEBEBLUE}" + "="*80 + f"{ENDC}")
    print(f"{VIOLET}{BOLD} █████╗ ██████╗ ████████╗      ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗{ENDC}")
    print(f"{VIOLET}{BOLD}██╔══██╗██╔══██╗╚══██╔══╝      ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝{ENDC}")
    print(f"{VIOLET}{BOLD}███████║██████╔╝   ██║         █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  {ENDC}")
    print(f"{VIOLET}{BOLD}██╔══██║██╔═══╝    ██║         ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  {ENDC}")
    print(f"{VIOLET}{BOLD}██║  ██║██║        ██║         ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗{ENDC}")
    print(f"{VIOLET}{BOLD}╚═╝  ╚═╝╚═╝        ╚═╝         ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝{ENDC}")
    print()
    print(f"{YELLOW}Advanced APT Search Engine for Comprehensive Threat Intelligence{ENDC}")
    print(f"{YELLOW}Searches multiple databases for detailed APT group information and analysis{ENDC}")
    print()
    print(f"{GREEN}{BOLD}Created by Muhap Yahia{ENDC}")
    print(f"{BEBEBLUE}" + "="*80 + f"{ENDC}")

class APTSearcher:
    def __init__(self):
        self.base_url = "https://apt.etda.or.th"
        self.search_url = "https://apt.etda.or.th/cgi-bin/aptsearch.cgi"
        self.listgroups_url = "https://apt.etda.or.th/cgi-bin/listgroups.cgi"
        self.aptnotes_url = "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json"
        self.malpedia_base = "https://malpedia.caad.fkie.fraunhofer.de"
        self.mitre_base = "https://attack.mitre.org"
        self.mitre_groups_url = "https://attack.mitre.org/groups/"
        self.pulsedive_base = "https://pulsedive.com"
        self.qianxin_base = "https://ti.qianxin.com"
        self.qianxin_apt_url = "https://ti.qianxin.com/apt/apt"
        self.socradar_base = "https://socradar.io"
        self.socradar_search_url = "https://socradar.io/"
        self.google_cloud_apt_url = "https://cloud.google.com/security/resources/insights/apt-groups"
        self.netenrich_base = "https://know.netenrich.com"
        self.netenrich_search_url = "https://know.netenrich.com/content/search"
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def search_google_cloud_apt(self, apt_name):
        try:
            print(f"{CYAN}Searching Google Cloud APT Groups database...{ENDC}")
            
            response = self.session.get(self.google_cloud_apt_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            apt_sections = []
            
            for section in soup.find_all(['div', 'section', 'article']):
                section_text = section.get_text().lower()
                if apt_name.lower() in section_text:
                    apt_info = {
                        'name': apt_name,
                        'description': '',
                        'attribution': '',
                        'targets': '',
                        'malware': '',
                        'source_url': self.google_cloud_apt_url
                    }
                    
                    paragraphs = section.find_all('p')
                    for p in paragraphs:
                        text = p.get_text(strip=True)
                        if apt_name.lower() in text.lower():
                            apt_info['description'] = text[:500] + '...' if len(text) > 500 else text
                            break
                    
                    if apt_info['description']:
                        apt_sections.append(apt_info)
            
            return apt_sections
        except:
            return []

    def search_netenrich(self, apt_name):
        try:
            print(f"{CYAN}Searching NetEnrich Knowledge Base...{ENDC}")
            
            search_params = {'query': apt_name}
            response = self.session.get(self.netenrich_search_url, params=search_params)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            netenrich_links = []
            
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                link_text = link.get_text(strip=True)
                
                if apt_name.lower() in link_text.lower() or apt_name.lower() in href.lower():
                    if href.startswith('/'):
                        full_url = urljoin(self.netenrich_base, href)
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        continue
                    
                    netenrich_links.append({
                        'title': link_text or 'NetEnrich Resource',
                        'url': full_url,
                        'snippet': ''
                    })
            
            for result in soup.find_all(['div', 'article'], class_=['result', 'search-result', 'content-item']):
                title_elem = result.find(['h1', 'h2', 'h3', 'h4', 'a'])
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    if apt_name.lower() in title.lower():
                        link_elem = result.find('a', href=True)
                        if link_elem:
                            href = link_elem.get('href')
                            full_url = urljoin(self.netenrich_base, href) if href.startswith('/') else href
                            
                            snippet_elem = result.find('p') or result.find('div', class_=['snippet', 'excerpt'])
                            snippet = snippet_elem.get_text(strip=True)[:200] + '...' if snippet_elem else ''
                            
                            netenrich_links.append({
                                'title': title,
                                'url': full_url,
                                'snippet': snippet
                            })
            
            seen_urls = set()
            unique_links = []
            for link in netenrich_links:
                if link['url'] not in seen_urls:
                    seen_urls.add(link['url'])
                    unique_links.append(link)
            
            return unique_links[:10]
        except:
            return []

    def search_socradar(self, apt_name):
        try:
            print(f"{CYAN}Searching SOCRadar Threat Intelligence...{ENDC}")
            
            search_query = apt_name.lower().replace(" ", "+")
            search_url = f"{self.socradar_search_url}?s={search_query}"
            
            response = self.session.get(search_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            socradar_articles = []
            
            articles = soup.find_all('article') or soup.find_all('div', class_=['post', 'entry', 'search-result'])
            
            for article in articles:
                article_data = {
                    'title': 'Unknown Title',
                    'url': '',
                    'excerpt': '',
                    'date': '',
                    'category': ''
                }
                
                title_elem = article.find(['h1', 'h2', 'h3', 'h4']) or article.find('a')
                if title_elem:
                    article_data['title'] = title_elem.get_text(strip=True)
                
                link_elem = article.find('a', href=True)
                if link_elem:
                    href = link_elem.get('href')
                    if href.startswith('/'):
                        article_data['url'] = urljoin(self.socradar_base, href)
                    elif href.startswith('http'):
                        article_data['url'] = href
                
                excerpt_elem = article.find(['p', 'div'], class_=['excerpt', 'summary', 'description'])
                if not excerpt_elem:
                    paragraphs = article.find_all('p')
                    for p in paragraphs:
                        text = p.get_text(strip=True)
                        if len(text) > 50:
                            excerpt_elem = p
                            break
                
                if excerpt_elem:
                    article_data['excerpt'] = excerpt_elem.get_text(strip=True)[:300] + '...' if len(excerpt_elem.get_text(strip=True)) > 300 else excerpt_elem.get_text(strip=True)
                
                date_elem = article.find(['time', 'span'], class_=['date', 'published', 'post-date'])
                if date_elem:
                    article_data['date'] = date_elem.get_text(strip=True)
                
                if article_data['url'] and apt_name.lower() in article_data['title'].lower():
                    socradar_articles.append(article_data)
            
            if not socradar_articles:
                socradar_articles = self.search_socradar_alternative(apt_name)
            
            return socradar_articles[:10]
        except:
            return []

    def search_socradar_alternative(self, apt_name):
        try:
            articles = []
            category_url = f"{self.socradar_base}/category/threat-actor-profiles/"
            response = self.session.get(category_url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    link_text = link.get_text(strip=True).lower()
                    href = link.get('href')
                    
                    if apt_name.lower() in link_text and 'dark-web-profile' in href:
                        articles.append({
                            'title': link.get_text(strip=True),
                            'url': href if href.startswith('http') else urljoin(self.socradar_base, href),
                            'excerpt': f'Threat actor profile for {apt_name}',
                            'date': 'Unknown',
                            'category': 'Threat Actor Profiles'
                        })
            
            return articles
        except:
            return []

    def search_qianxin(self, apt_name):
        try:
            print(f"{CYAN}Searching QiAnXin Threat Intelligence...{ENDC}")
            
            response = self.session.get(self.qianxin_apt_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            apt_links = []
            
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                link_text = link.get_text(strip=True).lower()
                
                if '/apt/detail/' in href and apt_name.lower() in link_text:
                    full_url = urljoin(self.qianxin_base, href)
                    apt_links.append(full_url)
                elif '/apt/detail/' in href and apt_name.lower() in href.lower():
                    full_url = urljoin(self.qianxin_base, href)
                    apt_links.append(full_url)
            
            if not apt_links:
                page_text = soup.get_text().lower()
                if apt_name.lower() in page_text:
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        if '/apt/detail/' in href:
                            full_url = urljoin(self.qianxin_base, href)
                            try:
                                test_response = self.session.head(full_url, allow_redirects=True)
                                if test_response.status_code == 200:
                                    apt_links.append(full_url)
                            except:
                                continue
            
            return list(set(apt_links))
        except:
            return []

    def search_pulsedive(self, apt_name):
        try:
            print(f"{CYAN}Searching Pulsedive database...{ENDC}")
            
            search_variations = [
                apt_name.lower().replace(" ", ""),
                apt_name.lower().replace(" ", "-"),
                apt_name.lower(),
                apt_name.replace(" ", ""),
                apt_name.replace(" ", "_"),
            ]
            
            pulsedive_url = None
            
            for variant in search_variations:
                threat_url = f"{self.pulsedive_base}/threat/{variant}"
                try:
                    response = self.session.get(threat_url)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        if self.is_valid_pulsedive_page(soup):
                            pulsedive_url = threat_url
                            break
                except:
                    continue
                
                try:
                    search_url = f"{self.pulsedive_base}/search"
                    search_params = {'q': apt_name, 'type': 'threat'}
                    response = self.session.get(search_url, params=search_params)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        search_results = self.extract_pulsedive_search_results(soup, apt_name)
                        if search_results:
                            pulsedive_url = search_results[0]
                            break
                except:
                    continue
            
            return pulsedive_url
        except:
            return None

    def is_valid_pulsedive_page(self, soup):
        indicators = [
            soup.find('div', class_='threat-header'),
            soup.find('h1', string=lambda text: text and 'threat' in text.lower()),
            soup.find('div', class_='threat-info'),
            soup.find('section', class_='threat-details')
        ]
        return any(indicators) or "threat intelligence" in soup.get_text().lower()

    def extract_pulsedive_search_results(self, soup, apt_name):
        results = []
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if '/threat/' in href and apt_name.lower() in href.lower():
                full_url = urljoin(self.pulsedive_base, href)
                results.append(full_url)
        return results

    def search_mitre_attack(self, apt_name):
        try:
            print(f"{CYAN}Searching MITRE ATT&CK database...{ENDC}")
            
            response = self.session.get(self.mitre_groups_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            matching_groups = []
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 4:
                        group_id = cells[0].get_text(strip=True)
                        group_name = cells[1].get_text(strip=True)
                        associated_groups = cells[2].get_text(strip=True)
                        description = cells[3].get_text(strip=True)
                        
                        search_text = f"{group_name} {associated_groups}".lower()
                        if apt_name.lower() in search_text:
                            matching_groups.append({
                                'id': group_id,
                                'name': group_name,
                                'associated_groups': associated_groups,
                                'description': description
                            })
            
            mitre_data = []
            for group in matching_groups:
                detailed_info = self.get_mitre_group_details(group['id'])
                if detailed_info:
                    detailed_info.update(group)
                    mitre_data.append(detailed_info)
            
            return mitre_data
        except:
            return []

    def get_mitre_group_details(self, group_id):
        try:
            group_url = f"{self.mitre_base}/groups/{group_id}/"
            response = self.session.get(group_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            techniques = []
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 4:
                        domain = cells[0].get_text(strip=True)
                        tech_id = cells[1].get_text(strip=True)
                        tech_name = cells[2].get_text(strip=True)
                        tech_use = cells[3].get_text(strip=True)
                        
                        if tech_id.startswith('T') and domain:
                            techniques.append({
                                'domain': domain,
                                'id': tech_id,
                                'name': tech_name,
                                'use': tech_use
                            })
            
            return {
                'url': group_url,
                'techniques': techniques
            }
        except:
            return None

    def save_mitre_navigator_file(self, apt_name, mitre_data):
        if not mitre_data:
            return None
            
        try:
            navigator_data = {
                "name": f"{apt_name} - MITRE ATT&CK Techniques",
                "description": f"Techniques used by {apt_name} according to MITRE ATT&CK",
                "domain": "enterprise-attack",
                "version": "4.5",
                "techniques": []
            }
            
            all_techniques = []
            for group in mitre_data:
                all_techniques.extend(group.get('techniques', []))
            
            for tech in all_techniques:
                navigator_data["techniques"].append({
                    "techniqueID": tech['id'],
                    "color": "#ff6666",
                    "score": 1,
                    "comment": tech['use']
                })
            
            navigator_filename = f"{apt_name.replace(' ', '_')}_MITRE_Navigator.json"
            with open(navigator_filename, 'w', encoding='utf-8') as f:
                json.dump(navigator_data, f, indent=2, ensure_ascii=False)
            
            report_filename = f"{apt_name.replace(' ', '_')}_MITRE_Techniques_Report.txt"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(f"MITRE ATT&CK Analysis Report\n")
                f.write(f"=" * 50 + "\n\n")
                f.write(f"APT Group: {apt_name}\n")
                f.write(f"Generated from: MITRE ATT&CK Database\n")
                f.write(f"Report Date: {self.get_current_date()}\n\n")
                
                for group in mitre_data:
                    f.write(f"Group ID: {group.get('id', 'Unknown')}\n")
                    f.write(f"Name: {group.get('name', 'Unknown')}\n")
                    f.write(f"Associated Groups: {group.get('associated_groups', 'None')}\n")
                    f.write(f"Description: {group.get('description', 'No description available')}\n")
                    f.write(f"Source URL: {group.get('url', 'Unknown')}\n\n")
                    
                    techniques = group.get('techniques', [])
                    if techniques:
                        f.write(f"Techniques Used ({len(techniques)} total):\n")
                        f.write("-" * 50 + "\n")
                        
                        for tech in techniques:
                            f.write(f"• {tech['id']} - {tech['name']}\n")
                            f.write(f"  Domain: {tech['domain']}\n")
                            f.write(f"  Usage: {tech['use']}\n\n")
                    else:
                        f.write("No techniques found for this group.\n\n")
            
            return navigator_filename, report_filename
        except:
            return None

    def get_current_date(self):
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def load_aptnotes_data(self):
        try:
            print(f"{CYAN}Loading APTnotes database...{ENDC}")
            response = self.session.get(self.aptnotes_url)
            response.raise_for_status()
            return json.loads(response.text)
        except:
            return []

    def search_malpedia(self, apt_name):
        try:
            print(f"{CYAN}Searching Malpedia database...{ENDC}")
            
            search_variations = [
                apt_name.lower().replace(" ", "_"),
                apt_name.lower().replace(" ", ""),
                apt_name.lower(),
                apt_name.replace(" ", "_"),
            ]
            
            malpedia_data = []
            
            for variant in search_variations:
                actor_url = f"{self.malpedia_base}/actor/{variant}"
                try:
                    response = self.session.get(actor_url)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        actor_data = self.extract_malpedia_actor_info(soup, actor_url)
                        if actor_data:
                            malpedia_data.append(actor_data)
                            break
                except:
                    continue
                
                library_url = f"{self.malpedia_base}/library"
                search_params = {'search': apt_name}
                try:
                    response = self.session.get(library_url, params=search_params)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        library_data = self.extract_malpedia_library_info(soup, apt_name)
                        if library_data:
                            malpedia_data.extend(library_data)
                            break
                except:
                    continue
            
            return malpedia_data
        except:
            return []

    def extract_malpedia_actor_info(self, soup, url):
        try:
            actor_info = {
                'type': 'actor',
                'url': url,
                'description': '',
                'resources': []
            }
            
            text_content = soup.get_text()
            lines = text_content.split('\n')
            for line in lines:
                line = line.strip()
                if line and len(line) > 20 and not line.startswith('|') and 'threat actor' in line.lower():
                    actor_info['description'] = line
                    break
            
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 3:
                        date = cells[0].get_text(strip=True)
                        source = cells[1].get_text(strip=True)
                        title = cells[2].get_text(strip=True)
                        
                        links = row.find_all('a', href=True)
                        resource_url = ''
                        for link in links:
                            href = link.get('href')
                            if href.startswith('http'):
                                resource_url = href
                                break
                        
                        if date and source and title:
                            actor_info['resources'].append({
                                'date': date,
                                'source': source,
                                'title': title,
                                'url': resource_url
                            })
            
            return actor_info if actor_info['resources'] else None
        except:
            return None

    def extract_malpedia_library_info(self, soup, apt_name):
        try:
            library_data = []
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        text = row.get_text().lower()
                        if apt_name.lower() in text:
                            resource_info = {
                                'type': 'library',
                                'title': '',
                                'source': '',
                                'date': '',
                                'url': ''
                            }
                            
                            full_text = row.get_text(strip=True)
                            parts = full_text.split('⋅')
                            
                            if len(parts) >= 3:
                                resource_info['date'] = parts[0].strip()
                                resource_info['source'] = parts[1].strip()
                                resource_info['title'] = parts[2].strip()
                            
                            links = row.find_all('a', href=True)
                            for link in links:
                                href = link.get('href')
                                if href.startswith('http'):
                                    resource_info['url'] = href
                                    break
                            
                            if resource_info['title']:
                                library_data.append(resource_info)
            
            return library_data
        except:
            return []

    def search_aptnotes(self, apt_name, aptnotes_data):
        matches = []
        search_terms = [
            apt_name.lower(),
            apt_name.replace(" ", "").lower(),
            apt_name.replace(" ", "_").lower(),
            apt_name.replace("apt", "").strip().lower(),
        ]
        
        for entry in aptnotes_data:
            title = entry.get("Title", "").lower()
            filename = entry.get("Filename", "").lower()
            
            for term in search_terms:
                if term in title or term in filename or any(word in title for word in term.split()) or any(word in filename for word in term.split()):
                    matches.append(entry)
                    break
                    
        return matches

    def search_apt_etda(self, apt_name):
        try:
            print(f"{CYAN}Searching ETDA database...{ENDC}")
            
            search_params = {
                'c': '',
                'v': '',
                's': '',
                'm': '',
                'x': f' {apt_name} '
            }
            
            response = self.session.get(self.listgroups_url, params=search_params)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            apt_groups = self.extract_apt_groups_from_list(soup, apt_name)
            
            if apt_groups:
                print(f"{GREEN}Found {len(apt_groups)} ETDA result(s){ENDC}")
                return [apt_groups[0]['url']]
            else:
                print(f"{RED}No ETDA results found{ENDC}")
                return []
        except:
            return []

    def extract_apt_groups_from_list(self, soup, apt_name):
        apt_groups = []
        
        try:
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                
                for row in rows:
                    links = row.find_all('a', href=True)
                    
                    for link in links:
                        href = link.get('href')
                        link_text = link.get_text(strip=True)
                        
                        if 'showcard.cgi' in href:
                            relevance_score = self.calculate_relevance(link_text, apt_name)
                            
                            if relevance_score > 0:
                                full_url = urljoin(self.base_url, href)
                                apt_groups.append({
                                    'name': link_text,
                                    'url': full_url,
                                    'relevance': relevance_score
                                })
            
            if not apt_groups:
                all_links = soup.find_all('a', href=True)
                for link in all_links:
                    href = link.get('href')
                    link_text = link.get_text(strip=True)
                    
                    if 'showcard.cgi' in href and link_text:
                        relevance_score = self.calculate_relevance(link_text, apt_name)
                        if relevance_score > 0:
                            full_url = urljoin(self.base_url, href)
                            apt_groups.append({
                                'name': link_text,
                                'url': full_url,
                                'relevance': relevance_score
                            })
            
            apt_groups.sort(key=lambda x: x['relevance'], reverse=True)
            return apt_groups
        except:
            return []

    def calculate_relevance(self, link_text, search_term):
        if not link_text or not search_term:
            return 0
        
        link_lower = link_text.lower()
        search_lower = search_term.lower()
        score = 0
        
        if search_lower == link_lower:
            score += 100
        elif search_lower in link_lower:
            score += 50
        
        search_words = search_lower.split()
        link_words = link_lower.split()
        
        for search_word in search_words:
            for link_word in link_words:
                if search_word == link_word:
                    score += 20
                elif search_word in link_word or link_word in search_word:
                    score += 10
        
        if 'apt' in search_lower and 'apt' in link_lower:
            score += 5
        
        if 'group' in search_lower and 'group' in link_lower:
            score += 5
            
        return score

    def extract_apt_info_etda(self, apt_url):
        try:
            response = self.session.get(apt_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            apt_data = {
                'name': 'Not found',
                'names': 'Not found',
                'country': 'Not found',
                'motivation': 'Not found',
                'first_seen': 'Not found',
                'description': 'Not found',
                'observed_sectors': [],
                'observed_countries': [],
                'tools_used': [],
                'information': 'Not found',
                'source_url': apt_url,
                'additional_links': [],
                'operations': []
            }
            
            tables = soup.find_all('table')
            
            main_table = None
            for table in tables:
                if self.is_apt_info_table(table):
                    main_table = table
                    break
            
            if main_table:
                self.parse_etda_table(main_table, apt_data)
            else:
                self.parse_etda_fallback(soup, apt_data)
            
            apt_data['operations'] = self.extract_etda_operations(soup)
            apt_data['additional_links'] = self.extract_etda_links(soup)
            
            return apt_data
        except:
            return None

    def is_apt_info_table(self, table):
        table_text = table.get_text().lower()
        indicators = ['names', 'country', 'motivation', 'first seen', 'description', 'observed sectors']
        return any(indicator in table_text for indicator in indicators)

    def parse_etda_table(self, table, apt_data):
        try:
            rows = table.find_all('tr')
            
            for row in rows:
                cells = row.find_all(['td', 'th'])
                
                if len(cells) >= 2:
                    field_cell = cells[0]
                    value_cell = cells[1]
                    
                    field_name = field_cell.get_text(strip=True).lower()
                    field_name = field_name.replace(':', '').strip()
                    
                    if field_name == 'names' or 'name' in field_name:
                        apt_data['names'] = self.extract_clean_text(value_cell)
                        if apt_data['names'] != 'Not found':
                            apt_data['name'] = apt_data['names']
                    elif field_name == 'country' or 'countries' in field_name:
                        country_text = self.extract_clean_text(value_cell)
                        apt_data['country'] = country_text
                    elif field_name == 'motivation':
                        apt_data['motivation'] = self.extract_clean_text(value_cell)
                    elif 'first seen' in field_name or 'first' in field_name:
                        apt_data['first_seen'] = self.extract_clean_text(value_cell)
                    elif field_name == 'description':
                        apt_data['description'] = self.extract_clean_text(value_cell)
                    elif 'observed sectors' in field_name or 'sectors' in field_name:
                        apt_data['observed_sectors'] = self.extract_list_items(value_cell)
                    elif 'observed countries' in field_name or 'target countries' in field_name:
                        apt_data['observed_countries'] = self.extract_list_items(value_cell)
                    elif 'tools used' in field_name or 'tools' in field_name or 'malware' in field_name:
                        apt_data['tools_used'] = self.extract_list_items(value_cell)
                    elif 'information' in field_name or 'details' in field_name:
                        apt_data['information'] = self.extract_clean_text(value_cell)
        except:
            pass

    def parse_etda_fallback(self, soup, apt_data):
        try:
            text_content = soup.get_text()
            
            patterns = {
                'names': r'names?:?\s*(.+?)(?:\n|$)',
                'country': r'country:?\s*(.+?)(?:\n|$)',
                'motivation': r'motivation:?\s*(.+?)(?:\n|$)',
                'first_seen': r'first\s+seen:?\s*(.+?)(?:\n|$)',
                'description': r'description:?\s*(.+?)(?:\n|$)'
            }
            
            for field, pattern in patterns.items():
                match = re.search(pattern, text_content, re.IGNORECASE | re.MULTILINE)
                if match:
                    value = match.group(1).strip()
                    if value and len(value) > 0:
                        if field == 'names':
                            apt_data['names'] = value
                            apt_data['name'] = value
                        elif field == 'country':
                            apt_data['country'] = value
                        elif field == 'motivation':
                            apt_data['motivation'] = value
                        elif field == 'first_seen':
                            apt_data['first_seen'] = value
                        elif field == 'description':
                            apt_data['description'] = value
        except:
            pass

    def extract_clean_text(self, cell):
        if not cell:
            return 'Not found'
        
        try:
            text = cell.get_text(separator=' ', strip=True)
            text = re.sub(r'\s+', ' ', text)
            text = text.replace('\n', ' ').replace('\r', ' ')
            text = text.strip()
            
            return text if text else 'Not found'
        except:
            return 'Not found'

    def extract_list_items(self, cell):
        if not cell:
            return []
        
        try:
            items = []
            
            lists = cell.find_all(['ul', 'ol'])
            for list_elem in lists:
                list_items = list_elem.find_all('li')
                for item in list_items:
                    text = item.get_text(strip=True)
                    if text:
                        items.append(text)
            
            if not items:
                links = cell.find_all('a')
                for link in links:
                    text = link.get_text(strip=True)
                    if text and text not in items:
                        items.append(text)
                
                spans = cell.find_all('span')
                for span in spans:
                    text = span.get_text(strip=True)
                    if text and text not in items:
                        items.append(text)
            
            if not items:
                text = cell.get_text(strip=True)
                if text and text != 'Not found':
                    separators = [',', ';', '|', '\n', '•', '-']
                    for sep in separators:
                        if sep in text:
                            parts = text.split(sep)
                            items = [part.strip() for part in parts if part.strip()]
                            break
                    
                    if not items and text:
                        items = [text]
            
            cleaned_items = []
            for item in items:
                item = item.strip()
                if item and item not in cleaned_items and item != 'Not found':
                    cleaned_items.append(item)
            
            return cleaned_items
        except:
            return []

    def extract_etda_operations(self, soup):
        operations = []
        
        try:
            text = soup.get_text()
            lines = text.split('\n')
            
            for line in lines:
                line = line.strip()
                if re.search(r'\d{4}', line) and len(line) > 20 and ('operation' in line.lower() or 'attack' in line.lower() or 'campaign' in line.lower()):
                    operations.append(line)
            
            return operations[:5]
        except:
            return []

    def extract_etda_links(self, soup):
        links = []
        
        try:
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                
                if href.startswith('http') and 'etda.or.th' not in href and 'javascript:' not in href.lower():
                    link_text = link.get_text(strip=True)
                    if link_text:
                        links.append({
                            'url': href,
                            'text': link_text
                        })
            
            seen_urls = set()
            unique_links = []
            for link in links:
                if link['url'] not in seen_urls:
                    seen_urls.add(link['url'])
                    unique_links.append(link)
            
            return unique_links[:10]
        except:
            return []

    def format_etda_output(self, apt_data):
        if not apt_data:
            return ""
        
        output = []
        output.append(f"{YELLOW}{'='*70}{ENDC}")
        output.append(f"{YELLOW}ETDA APT GROUP INFORMATION{ENDC}")
        output.append(f"{YELLOW}{'='*70}{ENDC}")
        
        output.append(f"\n{GREEN}{BOLD}Basic Information:{ENDC}")
        output.append(f"{CYAN}{BOLD}Names:{ENDC} {WHITE}{apt_data.get('names', 'Not found')}{ENDC}")
        output.append(f"{VIOLET}{BOLD}Country:{ENDC} {WHITE}{apt_data.get('country', 'Not found')}{ENDC}")
        output.append(f"{BEBEBLUE}{BOLD}Motivation:{ENDC} {WHITE}{apt_data.get('motivation', 'Not found')}{ENDC}")
        output.append(f"{RED}{BOLD}First seen:{ENDC} {WHITE}{apt_data.get('first_seen', 'Not found')}{ENDC}")
        
        if apt_data.get('description', 'Not found') != 'Not found':
            output.append(f"\n{GREEN}{BOLD}Description:{ENDC}")
            description = apt_data['description']
            if len(description) > 200:
                output.append(f"{WHITE}{description[:200]}...{ENDC}")
            else:
                output.append(f"{WHITE}{description}{ENDC}")
        
        if apt_data.get('observed_sectors'):
            output.append(f"\n{YELLOW}{BOLD}Observed Sectors:{ENDC}")
            sectors = apt_data['observed_sectors']
            if len(sectors) <= 5:
                output.append(f"{WHITE}{', '.join(sectors)}{ENDC}")
            else:
                output.append(f"{WHITE}{', '.join(sectors[:5])} and {len(sectors)-5} more{ENDC}")
        
        if apt_data.get('observed_countries'):
            output.append(f"\n{CYAN}{BOLD}Observed Countries:{ENDC}")
            countries = apt_data['observed_countries']
            if len(countries) <= 5:
                output.append(f"{WHITE}{', '.join(countries)}{ENDC}")
            else:
                output.append(f"{WHITE}{', '.join(countries[:5])} and {len(countries)-5} more{ENDC}")
        
        if apt_data.get('tools_used'):
            output.append(f"\n{VIOLET}{BOLD}Tools Used:{ENDC}")
            tools = apt_data['tools_used']
            if len(tools) <= 5:
                for tool in tools:
                    output.append(f"{WHITE}  • {tool}{ENDC}")
            else:
                for tool in tools[:5]:
                    output.append(f"{WHITE}  • {tool}{ENDC}")
                output.append(f"{WHITE}  • ... and {len(tools)-5} more tools{ENDC}")
        
        if apt_data.get('information', 'Not found') != 'Not found':
            output.append(f"\n{BEBEBLUE}{BOLD}Additional Information:{ENDC}")
            output.append(f"{WHITE}{apt_data['information']}{ENDC}")
        
        if apt_data.get('operations'):
            output.append(f"\n{RED}{BOLD}Known Operations:{ENDC}")
            for i, operation in enumerate(apt_data['operations'][:3], 1):
                output.append(f"{WHITE}  {i}. {operation}{ENDC}")
        
        output.append(f"\n{CYAN}{BOLD}Sources and References:{ENDC}")
        output.append(f"{CYAN}ETDA Source: {apt_data.get('source_url', 'Unknown')}{ENDC}")
        
        if apt_data.get('additional_links'):
            output.append(f"\n{CYAN}Additional References:{ENDC}")
            for i, link in enumerate(apt_data['additional_links'][:5], 1):
                output.append(f"{CYAN}  {i}. {link['text'][:50]}{'...' if len(link['text']) > 50 else ''}{ENDC}")
                output.append(f"{CYAN}     {link['url']}{ENDC}")
        
        return "\n".join(output)

    def format_aptnotes_output(self, aptnotes_matches):
        if not aptnotes_matches:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}APTNOTES RESEARCH REPORTS{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        output.append(f"\nFound {len(aptnotes_matches)} related research reports:")
        
        for i, match in enumerate(aptnotes_matches[:15], 1):
            output.append(f"\nReport #{i}:")
            output.append(f"   Title: {match.get('Title', 'N/A')}")
            output.append(f"   Source: {match.get('Source', 'N/A')}")
            output.append(f"   Date: {match.get('Date', 'N/A')} ({match.get('Year', 'N/A')})")
            output.append(f"   Filename: {match.get('Filename', 'N/A')}")
            
            link = match.get('Link', '')
            if link:
                output.append(f"   Report Link: {link}")
            
            sha1 = match.get('SHA-1', '')
            if sha1:
                output.append(f"   SHA-1: {sha1}")
            output.append("")
        
        if len(aptnotes_matches) > 15:
            output.append(f"\n... and {len(aptnotes_matches) - 15} more reports")
        
        return "\n".join(output)

    def format_malpedia_output(self, malpedia_data):
        if not malpedia_data:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}MALPEDIA THREAT INTELLIGENCE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        
        for item in malpedia_data:
            if item['type'] == 'actor':
                output.append(f"\nThreat Actor Profile:")
                if item['description']:
                    output.append(f"   Description: {item['description']}")
                output.append(f"   Source URL: {item['url']}")
                
                if item['resources']:
                    output.append(f"\nResearch Reports ({len(item['resources'])} found):")
                    for i, resource in enumerate(item['resources'][:10], 1):
                        output.append(f"   Report #{i}:")
                        output.append(f"      Date: {resource['date']}")
                        output.append(f"      Source: {resource['source']}")
                        output.append(f"      Title: {resource['title']}")
                        if resource['url']:
                            output.append(f"      Link: {resource['url']}")
                        output.append("")
                    
                    if len(item['resources']) > 10:
                        output.append(f"   ... and {len(item['resources']) - 10} more reports")
            
            elif item['type'] == 'library':
                output.append(f"\nLibrary Entry:")
                output.append(f"   Title: {item['title']}")
                output.append(f"   Source: {item['source']}")
                output.append(f"   Date: {item['date']}")
                if item['url']:
                    output.append(f"   Link: {item['url']}")
        
        return "\n".join(output)

    def format_mitre_output(self, mitre_data, saved_files):
        if not mitre_data:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}MITRE ATT&CK FRAMEWORK ANALYSIS{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        
        total_techniques = 0
        for group in mitre_data:
            output.append(f"\nGroup ID: {group.get('id', 'Unknown')}")
            output.append(f"Name: {group.get('name', 'Unknown')}")
            output.append(f"Associated Groups: {group.get('associated_groups', 'None')}")
            output.append(f"Description: {group.get('description', 'No description available')}")
            output.append(f"Source URL: {group.get('url', 'Unknown')}")
            
            techniques = group.get('techniques', [])
            total_techniques += len(techniques)
            
            if techniques:
                output.append(f"\nTechniques Used ({len(techniques)} total):")
                
                domains = {}
                for tech in techniques:
                    domain = tech['domain']
                    if domain not in domains:
                        domains[domain] = []
                    domains[domain].append(tech)
                
                for domain, domain_techniques in domains.items():
                    output.append(f"\n   {domain} Domain ({len(domain_techniques)} techniques):")
                    for tech in domain_techniques[:10]:
                        output.append(f"     • {tech['id']} - {tech['name']}")
                        if tech['use']:
                            output.append(f"       Usage: {tech['use'][:100]}...")
                    
                    if len(domain_techniques) > 10:
                        output.append(f"     ... and {len(domain_techniques) - 10} more techniques")
            else:
                output.append("\n   No techniques found for this group.")
        
        if saved_files:
            output.append(f"\nFiles Saved to Device:")
            for filename in saved_files:
                if filename:
                    output.append(f"   {filename}")
        
        output.append(f"\nMITRE Summary: {len(mitre_data)} group(s) found with {total_techniques} total techniques")
        
        return "\n".join(output)

    def format_socradar_output(self, socradar_articles):
        if not socradar_articles:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}SOCRADAR THREAT INTELLIGENCE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        output.append(f"\nFound {len(socradar_articles)} related articles:")
        
        for i, article in enumerate(socradar_articles, 1):
            output.append(f"\nArticle #{i}:")
            output.append(f"   Title: {article['title']}")
            output.append(f"   URL: {article['url']}")
            
            if article['date']:
                output.append(f"   Date: {article['date']}")
            
            if article['category']:
                output.append(f"   Category: {article['category']}")
            
            if article['excerpt']:
                output.append(f"   Excerpt: {article['excerpt']}")
            
            output.append("")
        
        return "\n".join(output)

    def format_pulsedive_output(self, pulsedive_url):
        if not pulsedive_url:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}PULSEDIVE THREAT INTELLIGENCE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        output.append(f"\nSource URL: {pulsedive_url}")
        
        return "\n".join(output)

    def format_qianxin_output(self, qianxin_links):
        if not qianxin_links:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}QIANXIN THREAT INTELLIGENCE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        
        if len(qianxin_links) == 1:
            output.append(f"\nSource URL: {qianxin_links[0]}")
        else:
            output.append(f"\nSource URLs ({len(qianxin_links)} found):")
            for i, link in enumerate(qianxin_links, 1):
                output.append(f"   {i}. {link}")
        
        return "\n".join(output)

    def format_google_cloud_output(self, google_cloud_data):
        if not google_cloud_data:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}GOOGLE CLOUD APT GROUPS DATABASE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        
        for i, apt_info in enumerate(google_cloud_data, 1):
            output.append(f"\nAPT Profile #{i}:")
            output.append(f"   Name: {apt_info['name']}")
            output.append(f"   Source URL: {apt_info['source_url']}")
            
            if apt_info['description']:
                output.append(f"   Description: {apt_info['description']}")
            
            if apt_info['attribution']:
                output.append(f"   Attribution: {apt_info['attribution']}")
            
            if apt_info['targets']:
                output.append(f"   Targets: {apt_info['targets']}")
            
            if apt_info['malware']:
                output.append(f"   Associated Malware: {apt_info['malware']}")
            
            output.append("")
        
        return "\n".join(output)

    def format_netenrich_output(self, netenrich_links):
        if not netenrich_links:
            return ""
        
        output = []
        output.append(f"\n{YELLOW}{'='*60}{ENDC}")
        output.append(f"{YELLOW}NETENRICH KNOWLEDGE BASE{ENDC}")
        output.append(f"{YELLOW}{'='*60}{ENDC}")
        output.append(f"\nFound {len(netenrich_links)} related resources:")
        
        for i, link in enumerate(netenrich_links, 1):
            output.append(f"\nResource #{i}:")
            output.append(f"   Title: {link['title']}")
            output.append(f"   URL: {link['url']}")
            
            if link['snippet']:
                output.append(f"   Snippet: {link['snippet']}")
            
            output.append("")
        
        return "\n".join(output)

    def search_comprehensive(self, apt_name):
        print(f"\n{CYAN}Comprehensive APT Search for: {apt_name}{ENDC}")
        print(f"{BEBEBLUE}{'='*50}{ENDC}")
        
        print(f"{CYAN}Searching ETDA database...{ENDC}")
        etda_links = self.search_apt_etda(apt_name)
        etda_data = None
        
        if etda_links:
            print(f"{GREEN}Found ETDA result{ENDC}")
            etda_data = self.extract_apt_info_etda(etda_links[0])
        
        mitre_data = self.search_mitre_attack(apt_name)
        saved_files = []
        
        if mitre_data:
            techniques_count = sum(len(group.get('techniques', [])) for group in mitre_data)
            print(f"{GREEN}Found MITRE ATT&CK data with {techniques_count} techniques{ENDC}")
            
            files = self.save_mitre_navigator_file(apt_name, mitre_data)
            if files:
                saved_files.extend(files)
                print(f"{GREEN}Saved MITRE files to device: {', '.join(files)}{ENDC}")
        
        google_cloud_data = self.search_google_cloud_apt(apt_name)
        if google_cloud_data:
            print(f"{GREEN}Found {len(google_cloud_data)} Google Cloud APT profiles{ENDC}")
        
        netenrich_links = self.search_netenrich(apt_name)
        if netenrich_links:
            print(f"{GREEN}Found {len(netenrich_links)} NetEnrich resources{ENDC}")
        
        socradar_articles = self.search_socradar(apt_name)
        if socradar_articles:
            print(f"{GREEN}Found {len(socradar_articles)} SOCRadar articles{ENDC}")
        
        pulsedive_url = self.search_pulsedive(apt_name)
        if pulsedive_url:
            print(f"{GREEN}Found Pulsedive threat intelligence{ENDC}")
        
        qianxin_links = self.search_qianxin(apt_name)
        if qianxin_links:
            print(f"{GREEN}Found {len(qianxin_links)} QiAnXin link(s){ENDC}")
        
        malpedia_data = self.search_malpedia(apt_name)
        if malpedia_data:
            total_resources = sum(len(item.get('resources', [])) for item in malpedia_data)
            print(f"{GREEN}Found Malpedia data with {total_resources} resources{ENDC}")
        
        print(f"{CYAN}Searching APTnotes database...{ENDC}")
        aptnotes_data = self.load_aptnotes_data()
        aptnotes_matches = []
        
        if aptnotes_data:
            aptnotes_matches = self.search_aptnotes(apt_name, aptnotes_data)
            if aptnotes_matches:
                print(f"{GREEN}Found {len(aptnotes_matches)} APTnotes reports{ENDC}")
        
        return etda_data, mitre_data, google_cloud_data, netenrich_links, socradar_articles, pulsedive_url, qianxin_links, malpedia_data, aptnotes_matches, saved_files

def main():
    display_banner()
    
    searcher = APTSearcher()
    
    apt_name = input(f"{WHITE}Enter APT group name to search: {ENDC}").strip()
    
    if not apt_name:
        print(f"{RED}Please enter a valid APT name.{ENDC}")
        return
    
    etda_data, mitre_data, google_cloud_data, netenrich_links, socradar_articles, pulsedive_url, qianxin_links, malpedia_data, aptnotes_matches, saved_files = searcher.search_comprehensive(apt_name)
    
    if etda_data or mitre_data or google_cloud_data or netenrich_links or socradar_articles or pulsedive_url or qianxin_links or malpedia_data or aptnotes_matches:
        print(f"\n{VIOLET}{BOLD}SEARCH RESULTS{ENDC}\n")
        
        if etda_data:
            etda_output = searcher.format_etda_output(etda_data)
            print(etda_output)
        
        if mitre_data:
            mitre_output = searcher.format_mitre_output(mitre_data, saved_files)
            print(mitre_output)
        
        if google_cloud_data:
            google_cloud_output = searcher.format_google_cloud_output(google_cloud_data)
            print(google_cloud_output)
        
        if netenrich_links:
            netenrich_output = searcher.format_netenrich_output(netenrich_links)
            print(netenrich_output)
        
        if socradar_articles:
            socradar_output = searcher.format_socradar_output(socradar_articles)
            print(socradar_output)
        
        if pulsedive_url:
            pulsedive_output = searcher.format_pulsedive_output(pulsedive_url)
            print(pulsedive_output)
        
        if qianxin_links:
            qianxin_output = searcher.format_qianxin_output(qianxin_links)
            print(qianxin_output)
        
        if malpedia_data:
            malpedia_output = searcher.format_malpedia_output(malpedia_data)
            print(malpedia_output)
        
        if aptnotes_matches:
            aptnotes_output = searcher.format_aptnotes_output(aptnotes_matches)
            print(aptnotes_output)
        
        print(f"\n{VIOLET}{BOLD}{'='*110}{ENDC}")
        print(f"{VIOLET}{BOLD}COMPREHENSIVE SEARCH SUMMARY{ENDC}")
        print(f"{VIOLET}{BOLD}{'='*110}{ENDC}")
        print(f"ETDA Database: {GREEN + 'Found' + ENDC if etda_data else RED + 'Not found' + ENDC}")
        print(f"MITRE ATT&CK: {GREEN + 'Found' + ENDC if mitre_data else RED + 'Not found' + ENDC}")
        print(f"Google Cloud APT: {GREEN + str(len(google_cloud_data)) + ' profiles found' + ENDC if google_cloud_data else RED + 'Not available' + ENDC}")
        print(f"NetEnrich: {GREEN + str(len(netenrich_links)) + ' resources found' + ENDC if netenrich_links else RED + 'Not available' + ENDC}")
        print(f"SOCRadar: {GREEN + str(len(socradar_articles)) + ' articles found' + ENDC if socradar_articles else RED + 'Not available' + ENDC}")
        print(f"Pulsedive: {GREEN + 'Found' + ENDC if pulsedive_url else RED + 'Not found' + ENDC}")
        print(f"QiAnXin: {GREEN + 'Found' + ENDC if qianxin_links else RED + 'Not found' + ENDC}")
        print(f"Malpedia Database: {GREEN + 'Found' + ENDC if malpedia_data else RED + 'Not found' + ENDC}")
        print(f"APTnotes Reports: {GREEN + str(len(aptnotes_matches)) + ' reports found' + ENDC if aptnotes_matches else RED + 'Not found' + ENDC}")
        
        total_resources = 0
        if etda_data:
            total_resources += len(etda_data.get('additional_links', []))
        if mitre_data:
            total_resources += sum(len(group.get('techniques', [])) for group in mitre_data)
        if google_cloud_data:
            total_resources += len(google_cloud_data)
        if netenrich_links:
            total_resources += len(netenrich_links)
        if socradar_articles:
            total_resources += len(socradar_articles)
        if pulsedive_url:
            total_resources += 1
        if qianxin_links:
            total_resources += len(qianxin_links)
        if malpedia_data:
            total_resources += sum(len(item.get('resources', [])) for item in malpedia_data)
        total_resources += len(aptnotes_matches)
        
        print(f"{YELLOW}Total Resources Found: {total_resources}{ENDC}")
        
        if saved_files:
            print(f"\n{GREEN}Files Saved to Device:{ENDC}")
            for filename in saved_files:
                if filename and os.path.exists(filename):
                    print(f"   {filename} ({os.path.getsize(filename)} bytes)")
        
    else:
        print(f"\n{RED}No results found for '{apt_name}' in any database.{ENDC}")
        print(f"{YELLOW}Try using:{ENDC}")
        print(f"{YELLOW}   • Alternative names or aliases{ENDC}")
        print(f"{YELLOW}   • Numbers instead of text (e.g., 'APT1' instead of 'APT One'){ENDC}")
        print(f"{YELLOW}   • Partial names (e.g., 'Lazarus' instead of 'Lazarus Group'){ENDC}")

if __name__ == "__main__":
    main()
