#!/usr/bin/python3

import mimetypes
import argparse
import requests
import hashlib
import json
import codecs
from colorama import Fore, Style, init
from alive_progress import alive_bar
import concurrent.futures
import favicon
import sys
import re
import os

# fetchers
import shodan
import netlas

# tinyurl
from urllib.parse import urlencode, uses_netloc
from contextlib import closing
from urllib.request import urlopen

requests.packages.urllib3.disable_warnings()
init(autoreset=True)


try:
    import dns.resolver, mmh3
except ImportError as e:
    #print("Error -> ", e)
    print("[-] {}. Please, install all required dependencies!".format(e))
    sys.exit(1)


def make_url_tiny(url):
    request_url = f"http://tinyurl.com/api-create.php?{urlencode({'url':url})}"
    with closing(urlopen(request_url)) as response:
        return response.read().decode("utf-8")

class Favicon:
    def __init__(self, content, source=None, type=None, tinyurl=False):
        """Initialize Favicon object"""
        self.content = content
        self.source = source
        self.type = type
        self.tinyurl = tinyurl

        base64_favicon = codecs.encode(content, 'base64')

        self.murmur_hash = mmh3.hash(base64_favicon)
        self.md5_hash = hashlib.md5(content).hexdigest()
        self.sha256_hash = hashlib.sha256(content).hexdigest()
        self.base64_hash = codecs.encode('icon_hash="{}"'.format(self.murmur_hash).encode('utf-8'), 'base64').decode('utf-8').strip()
        self.hex_hash = hex(self.murmur_hash).replace('0x', '', 1)

    def __eq__(self, other):
        if isinstance(other, Favicon):
            return self.murmur_hash == other.murmur_hash
        return False

    def __hash__(self):
        return hash(self.murmur_hash)

    def name(self):
        return f'favicon from {self.type}: {self.source}'

    @classmethod
    def from_url(cls, url, custom_type="direct link"):
        """Create Favicon object from a URL"""
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            favi_words = ['image', 'icon']
            content_type = response.headers['Content-Type']

            if not any(re.findall('|'.join(favi_words) , content_type)):
                raise Exception(f"Invalid content-type {str(content_type)} for URL: {url}")

            content = response.content
            return cls(content, source=url, type=custom_type)
        else:
            raise Exception(f"Failed to fetch favicon from URL: {url}")

    @classmethod
    def from_file(cls, filepath):
        """Create Favicon object from a file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type and mime_type.startswith('image'):
            with open(filepath, 'rb') as file:
                content = file.read()
                return cls(content, source=os.path.abspath(filepath), type="file")
        else:
            raise ValueError(f"'{filepath}' is not a valid image file")

    def generate_links_dict(self):
        links_dict = {
            'ZoomEye': f'https://www.zoomeye.org/searchResult?q=iconhash%3A%22{self.murmur_hash}%22',
            'Shodan': f'https://www.shodan.io/search?query=http.favicon.hash:{self.murmur_hash}',
            'Fofa': f'https://en.fofa.info/result?qbase64={self.base64_hash}',
            'VirusTotal': f'https://www.virustotal.com/gui/search/entity:url%20main_icon_md5:{self.md5_hash}',
            'BinaryEdge': f'https://app.binaryedge.io/services/query?query=web.favicon.md5:{self.md5_hash}&page=1',
            'Netlas': f'https://app.netlas.io/responses/?q=http.favicon.hash_sha256:{self.sha256_hash}&page=1',
            'Censys': f'https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=services.http.response.favicons.md5_hash:{self.md5_hash}',
            'ODIN': f'https://getodin.com/search/hosts?query=services.modules.http.favicon.murmur_hash%3A%22{self.murmur_hash}%22',
            'CriminalIP': f'https://www.criminalip.io/asset/search?query=favicon:+{self.hex_hash}',
            'HunterHow': f'https://hunter.how/list?searchValue=favicon_hash%3A%22{self.murmur_hash}%22'
        }

        if self.tinyurl:
            for p, l in links_dict.items():
                links_dict[p] = make_url_tiny(l)

        return links_dict

    def get_platform_names(self):
        """Return a list of all platform names"""
        links_dict = self.generate_links_dict()
        return list(links_dict.keys())

    def make_links(self):
        """Generate the same text output as the original function with aligned columns"""
        links_dict = self.generate_links_dict()
        
        # Find the longest platform name to adjust alignment
        max_platform_length = max(len(platform) for platform in links_dict.keys())
        
        # Format links with colored platform names and links
        links_bundle = '\n'.join([
            f'{Style.BRIGHT}{Fore.CYAN}{(platform+":").ljust(max_platform_length + 5)}'
            f'{Fore.GREEN}{link}' 
            for platform, link in links_dict.items()
        ])
        return links_bundle + '\n'


class Fetcher:
    """Base fetcher class"""
    @classmethod
    def _load_response_from_file(cls, murmur_hash):
        filename = f"{murmur_hash}_{cls.get_platform()}.json"
        output_dir = "api_responses"
        file_path = os.path.join(output_dir, filename)
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as file:
                return json.load(file)
        return None

    @classmethod
    def _save_response_to_file(cls, data, murmur_hash):
        """Save the API response data to a JSON file with a formatted filename."""
        filename = f"{murmur_hash}_{cls.get_platform()}.json"
        output_dir = "api_responses"
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

    @classmethod
    def get_platform(cls):
        """Method to return the platform name. This should be overridden in subclasses."""
        raise NotImplementedError("Subclasses should implement this method to return the platform name.")

    @classmethod
    def _format_output(cls, total_results_count, domains, ip_addresses_by_waf, murmur_hash, favicon_name):
        """Format the output to display the total results count, domains, and IP addresses."""
        if not total_results_count:
                return f"\n{Style.BRIGHT}{Fore.BLUE}No results found in {cls.get_platform()} for {favicon_name}"

        def make_header(header):
            return f'{Fore.CYAN}{Style.BRIGHT}{header}{Style.NORMAL}'

        result = f"\n{Style.BRIGHT}{Fore.BLUE}{cls.get_platform()} Results Preview{Style.NORMAL}\n"
        result += f"{make_header('Total results:')} {Fore.GREEN}{total_results_count}\n"
        result += f"{make_header('Domains:')} {Fore.YELLOW}{', '.join(domains)}\n"
        for waf, ips in ip_addresses_by_waf.items():
            result += f"{make_header(f'IP Addresses [{waf}]:')} {Fore.MAGENTA}{', '.join(ips)}\n"
        result += f"\n{Fore.GREEN}{cls.get_platform()} JSON response saved to {murmur_hash}_{cls.get_platform()}.json"
        return result


class ShodanPreviewAPIKeyFetcher(Fetcher):
    """Stateless fetcher for getting results from Shodan based on favicon hash."""
    def __init__(self, api_key, use_cache=True):
        self.api_key = api_key
        self.use_cache = use_cache

    @classmethod
    def get_platform(self):
        return 'Shodan'

    def get_info(self, favicon):
        """Fetch information from Shodan based on the favicon object using its API key."""
        api = shodan.Shodan(self.api_key)
        murmur_hash = favicon.murmur_hash
        try:
            result = None
            if self.use_cache:
                result = ShodanPreviewAPIKeyFetcher._load_response_from_file(favicon.murmur_hash) # cached

            if not result:
                result = api.search(f'http.favicon.hash:{murmur_hash}')
                ShodanPreviewAPIKeyFetcher._save_response_to_file(result, favicon.murmur_hash)

            total_results_count, domains, ip_addresses_by_waf = ShodanPreviewAPIKeyFetcher._parse_response(result)
            output = ShodanPreviewAPIKeyFetcher._format_output(total_results_count, domains, ip_addresses_by_waf, murmur_hash, favicon.name())
            return domains, ip_addresses_by_waf, output

        except shodan.APIError as e:
            return f"Shodan API request failed: {str(e)}"

    @staticmethod
    def _parse_response(data):
        """Extracts the total results count, domains, and IP addresses from the Shodan response."""
        total_results_count = data.get('total', 0)
        domains = []
        ip_addresses_by_waf = {}

        matches = data.get('matches', [])
        for match in matches:
            # Extract domain (if available)
            hostnames = match.get('hostnames', [])
            if hostnames:
                domains.append(f"{hostnames[0]}:{match.get('port')}")

            # Extract IP addresses
            ip = match.get('ip_str', '')
            if ip:
                ips = [ip]  # Wrap in list to unify with other methods
            else:
                ips = []

            waf_name = match.get('http', {}).get('waf', 'No CDN/WAF')

            if waf_name not in ip_addresses_by_waf:
                ip_addresses_by_waf[waf_name] = []
            ip_addresses_by_waf[waf_name].extend(ips)

        return total_results_count, domains, ip_addresses_by_waf


class ZoomEyePreviewFetcher(Fetcher):
    """Stateless fetcher for getting results preview from ZoomEye based on favicon hash."""
    def __init__(self, use_cache):
        self.use_cache = use_cache

    @classmethod
    def get_platform(self):
        return 'ZoomEye'

    def get_info(self, favicon):
        """Fetch information from ZoomEye based on the favicon object."""
        base_url = 'https://www.zoomeye.hk/api/search'
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9,ru-RU;q=0.8,ru;q=0.7,pt;q=0.6',
            'Connection': 'keep-alive',
            'Cookie': '__jsluid_s=b7c2017087e12824248295feed7dfdb1',
            'Cube-Authorization': 'undefined',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
        }
        
        url = f'{base_url}?q=iconhash%3A%22{favicon.murmur_hash}%22&page=1&t=v4%2Bv6%2Bweb'
        referer = f'https://www.zoomeye.hk/searchResult?q=iconhash%3A%22{favicon.murmur_hash}%22'
        headers['Referer'] = referer
        
        response = None
        data = {}

        if self.use_cache:
            data = ZoomEyePreviewFetcher._load_response_from_file(favicon.murmur_hash) # cached
            response = data

        if not response:
            response = requests.get(url, headers=headers)
            data = response.json()
            if response.status_code != 200:
                return f"ZoomEye Web API request failed: {response.status_code}"
            ZoomEyePreviewFetcher._save_response_to_file(data, favicon.murmur_hash)

        if data.get('status') == 429:
            return f"ZoomEye Web API request failed: Ratelimit"

        total_results_count, domains, ip_addresses_by_waf = ZoomEyePreviewFetcher._parse_response(data)
        output = ZoomEyePreviewFetcher._format_output(total_results_count, domains, ip_addresses_by_waf, favicon.murmur_hash, favicon.name())
        return domains, ip_addresses_by_waf, output

    @staticmethod
    def _parse_response(data):
        """Extracts the total results count, domains, and IP addresses from the response."""
        total_results_count = data.get('total', 0)
        domains = []
        ip_addresses_by_waf = {}

        matches = data.get('matches', [])
        for match in matches:
            site = match.get('site', '')
            port = match.get('portinfo', {}).get('port', '')
            if site and port:
                domains.append(f"{site}:{port}")

            ips = match.get('ip', [])
            if isinstance(ips, str):
                ips = [ips]

            waf_list = match.get('waf', [])
            if waf_list:
                waf_name = waf_list[0].get('name', {}).get('en', 'Unknown WAF')
            else:
                waf_name = 'No WAF'

            if waf_name not in ip_addresses_by_waf:
                ip_addresses_by_waf[waf_name] = []
            ip_addresses_by_waf[waf_name].extend(ips)

        return total_results_count, domains, ip_addresses_by_waf


class NetlasPreviewAPIKeyFetcher(Fetcher):
    """Stateless fetcher for getting results from Netlas based on favicon hash."""
    
    def __init__(self, api_key, use_cache=True):
        self.api_key = api_key
        self.use_cache = use_cache

    @classmethod
    def get_platform(cls):
        return 'Netlas'

    def get_info(self, favicon):
        """Fetch information from Netlas based on the favicon object using its API key."""
        netlas_connection = netlas.Netlas(api_key=self.api_key)
        murmur_hash = favicon.murmur_hash

        try:
            result = None
            if self.use_cache:
                result = NetlasPreviewAPIKeyFetcher._load_response_from_file(murmur_hash)  # cached response

            if not result:
                query_string = f'http.favicon.hash_sha256:{favicon.sha256_hash}'
                result = netlas_connection.query(query=query_string)
                NetlasPreviewAPIKeyFetcher._save_response_to_file(result, murmur_hash)

            total_results_count, domains, ip_addresses_by_waf = NetlasPreviewAPIKeyFetcher._parse_response(result)
            output = NetlasPreviewAPIKeyFetcher._format_output(total_results_count, domains, ip_addresses_by_waf, murmur_hash, favicon.name())
            return domains, ip_addresses_by_waf, output

        except Exception as e:
            return [], {}, f"Netlas API request failed: {str(e)}"

    @staticmethod
    def _parse_response(data):
        """Extracts the total results count, domains, and IP addresses from the response."""
        domains = []
        ip_addresses_by_waf = {'No WAF': []}

        matches = data.get('items', [])
        total_results_count = len(matches)

        for match in matches:
            match_data = match.get('data', {})
            site = match_data.get('host', '')
            port = match_data.get('port', '')
            if site:
                domains.append(f"{site}:{port}")

            ip = match_data.get('ip')
            if ip and not ip in ip_addresses_by_waf['No WAF']:
                ip_addresses_by_waf['No WAF'].append(ip)

        domains = list(set(domains))

        return total_results_count, domains, ip_addresses_by_waf


def run_fetchers(favicons, fetchers):
    """Run fetchers in parallel with a spinning progress bar and print results sequentially."""
    results = []

    # Prepare a list of tasks (fetchers for each favicon)
    tasks = [(fetcher, favicon) for favicon in favicons for fetcher in fetchers]

    with alive_bar(len(tasks), title="Fetching some results...") as bar:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(fetcher.get_info, favicon) for fetcher, favicon in tasks]

            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append(([], {}, f"Error occurred: {e}"))
                bar()  # Update the progress bar

    return results


def make_se_links(domain):
    links_bundle = [
        ('Google 16x16', f'https://www.google.com/s2/favicons?domain={domain}&size=16'),
        ('Google 32x32', f'https://www.google.com/s2/favicons?domain={domain}&size=32'),
        ('DuckDuckGo', f'https://icons.duckduckgo.com/ip3/{domain}.ico'),
        ('Unavatar', f'https://unavatar.io/{domain}'),
    ]
    return links_bundle


def resolve_domain(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4',
                                '1.1.1.1', '1.0.0.1']
        dns_answer = resolver.resolve(domain, 'A')
        ip_list = [ ip.to_text() for ip in dns_answer ]
        return ip_list

    except Exception as e:
        print(f'[-] {e}')
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get favicon hashes from multiple sources"
    )

    parser.add_argument("-f", "--file", help="Get favicon hash from a specific file")
    parser.add_argument("-e", "--add-from-search-engines", action="store_true", help="Get additional favicon versions using search engines")
    parser.add_argument("-u", "--uri", help="Get favicon hash from WEB")
    parser.add_argument("-d", "--domain", help="Get favicon hash from resolved domain")
    parser.add_argument("--tinyurl", action="store_true", help="Get short links for results with TinyURL")
    parser.add_argument("--no-fetch", action="store_true", default=False, help="Don't fetch results from engines")
    args = parser.parse_args()

    selist = []
    favicons = []

    fetchers = [
        ZoomEyePreviewFetcher(use_cache=True),
    ]

    from settings import SHODAN_KEY, NETLAS_KEY
    if SHODAN_KEY:
        fetchers.append(ShodanPreviewAPIKeyFetcher(SHODAN_KEY))
    fetchers.append(NetlasPreviewAPIKeyFetcher(NETLAS_KEY))

    if args.uri:
        if args.uri.count('/') >= 3 and not args.uri.endswith('/'):
            try:
                favicon = Favicon.from_url(args.uri)
                favicons.append(favicon)
            except Exception as e:
                print(f"[-] Failed to fetch favicon: {e}")
        else:
            print(f"[-] Is it correct or full URI: '{args.uri}'?")

    elif args.file:
        try:
            favicon = Favicon.from_file(args.file)
            favicons.append(favicon)
        except Exception as e:
            print(f"[-] Failed to load favicon from file: {e}")

    elif args.domain:
        # Try to find favicons on domain
        icons = favicon.get(f"http://{args.domain}")
        if icons:
            print(f'[-] Found {len(icons)} favicons for {args.domain}: {', '.join([icon.url for icon in icons])}')
            unique_favicons = set(favicons)
            for icon in icons:
                print(icon)
                if icon.width not in (32, 0):
                    continue
                try:
                    new_favicon = Favicon.from_url(icon.url, custom_type=f'guessed favicons of {args.domain}')
                    if new_favicon not in unique_favicons:
                        favicons.append(new_favicon)
                        unique_favicons.add(new_favicon)
                except Exception as e:
                    print(f"Error processing found favicon from URL {icon.url} for {args.domain}: {e}")

        # Try to get favicons from all related IPs
        ips = resolve_domain(args.domain)
        for ip in ips:
            try:
                favicon = Favicon.from_url(f"http://{ip}/favicon.ico", custom_type=f"resolved domain '{args.domain}'")
                unique_favicons = set(favicons)
                if favicon and not favicon in unique_favicons:
                    favicons.append(favicon)
            except Exception as e:
                print(f'[-] Error {e} for {ip}')

    if args.add_from_search_engines and args.domain:
        unique_favicons = set(favicons)
        urls = make_se_links(args.domain)
        for url in urls:
            try:
                new_favicon = Favicon.from_url(url[1], custom_type=f'search engine {url[0]}')
                if new_favicon not in unique_favicons:
                    favicons.append(new_favicon)
                    unique_favicons.add(new_favicon)
            except Exception as e:
                print(f"Error processing favicon from URL {url} from search engine {url[0]}: {e}")

    preview_results = []
    preview_file = '_preview_results.txt'

    if favicons:
        for favicon in favicons:
            favicon.tinyurl = args.tinyurl
            print(f"\nResults for favicon from {favicon.type}: {favicon.source}\n")
            print(favicon.make_links())

        if args.no_fetch:
            print("Fetching of results is disabled, exiting.")
        else:
            all_domains = set()
            all_ips = set()
            results = run_fetchers(favicons, fetchers)
            for r in results:
                domains, ips_dict, output = r
                all_domains |= set(domains)
                for name, ips in ips_dict.items():
                    if 'cloudflare' in name.lower():
                        continue
                    all_ips |= set(ips)

                print(output)

            preview_results = sorted(list(all_domains)) + sorted(list(all_ips))
            filename = f'{favicon.murmur_hash}{preview_file}'.replace('-', '_')
            with open(filename, 'w') as file:
                file.write('\n'.join(preview_results))
                print(f'{Fore.GREEN}Preview results for favicon with MurmurHash {favicon.murmur_hash} was saved to {filename}')
    else:
        print("No results found.")


# Тут нашел способ поиска фавиконок через поисковики, есть еще другие но не вижу смысла добавлять их, это самые большие
# Зачем это нужно? Тут может быть другая фавиконка можно потом по ней поискать и найти много другой инфы, может это надо указать при выдаче
### https://dev.to/derlin/get-favicons-from-any-website-using-a-hidden-google-api-3p1e
# https://www.google.com/s2/favicons?domain=${domain}&sz=${size}
# https://icons.duckduckgo.com/ip3/dev.to.ico
# https://icon.horse/icon/bi.zone

# Это описано в PDF, для автопоиска иконок надо заморочиться, вдохну в себя мотивацию только....
# search icon: curl -skL https://bi.zone | grep "link rel="


# Это нечто похожее, но наше будет отцом для этого!
# https://github.com/eremit4/favihunter/blob/main/favihunter.py
# https://github.com/elihypoo414/favfound/blob/main/favfound.py

#
# https://stackoverflow.com/questions/64526263/how-to-show-my-website-favicon-in-bings-search-engine

