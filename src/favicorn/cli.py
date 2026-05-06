"""favicorn CLI entry point."""

import argparse
import os
import random
import sys
import time

import favicon as _favicon_lib
import requests
from colorama import Fore, Style

from . import (
    OUTPUT_DIR,
    Favicon,
    NetlasPreviewAPIKeyFetcher,
    ShodanPreviewAPIKeyFetcher,
    ZoomEyePreviewFetcher,
    make_se_links,
    resolve_domain,
    run_fetchers,
)

requests.packages.urllib3.disable_warnings()


def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_ascii_art():
    clear_terminal()
    ascii_art = [['\033[33m+\033[0m' if char == '+' else '\033[1;35m' + char + '\033[0m' for char in line.ljust(45)]
                 for line in r"""             +           +
                                  +
             +     /                   +
                  /       +
                 +                  +
          +                ,               +
                          /|
                \        / ->         \
        +        \,_    /  ->     +    \
                 /0(``  \  ->           \
                (, /"(``-\_/_--_         +
                      \ )___(  )\\.
                      |/     \/  \\\
                      \\     /\
                      o o   o  o
                                            """.split("\n")]
    dim_x, dim_y = len(ascii_art[0]), len(ascii_art)
    mask = [['O' for _ in range(dim_x)] for _ in range(dim_y)]
    available_positions = [(y, x) for y in range(dim_y) for x in range(dim_x)]
    while available_positions:
        for _ in ascii_art:
            print("\033[F", end='')
        y, x = random.choice(available_positions)
        available_positions.remove((y, x))
        mask[y][x] = 0
        for dy, line in enumerate(ascii_art):
            print(''.join(mask[dy][dx] or line[dx] for dx in range(dim_x)), flush=os.name != 'nt')
        time.sleep(0.001)


def main():
    parser = argparse.ArgumentParser(
        description="Get favicon hashes from multiple sources"
    )

    search_modes = parser.add_mutually_exclusive_group(required=True)
    search_modes.add_argument("-u", "--uri", help="Get favicon hash from WEB")
    search_modes.add_argument("-f", "--file", help="Get favicon hash from a specific file")
    search_modes.add_argument("-d", "--domain", help="Get favicon hash from resolved domain")

    parser.add_argument("-e", "--add-from-search-engines", action="store_true",
                        help="Get additional favicon versions using search engines")
    parser.add_argument("--tinyurl", action="store_true",
                        help="Get short links for results with TinyURL")
    parser.add_argument("--no-fetch", action="store_true", default=False,
                        help="Don't fetch results from engines")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Verbose (show hashes)")
    parser.add_argument("--no-logo", action="store_true", default=False,
                        help="Disable unicorn animation (dangerous option, use with caution!)")
    parser.add_argument("-s", "--save-links-filename", type=str, help="Save links to a text file")
    args = parser.parse_args()

    if not args.no_logo:
        print_ascii_art()

    favicons = []

    fetchers = [
        ZoomEyePreviewFetcher(use_cache=True),
    ]

    SHODAN_KEY = os.getenv('SHODAN_KEY')
    NETLAS_KEY = os.getenv('NETLAS_KEY')
    if SHODAN_KEY:
        fetchers.append(ShodanPreviewAPIKeyFetcher(SHODAN_KEY))
    fetchers.append(NetlasPreviewAPIKeyFetcher(NETLAS_KEY))

    if args.uri:
        if args.uri.count('/') >= 3 and not args.uri.endswith('/'):
            print(f"Searching by favicon from direct link {args.uri}...")
            try:
                fav = Favicon.from_url(args.uri)
                favicons.append(fav)
            except Exception as e:
                print(f"[-] Failed to fetch favicon: {e}")
        else:
            print(f"[-] Is it correct or full URI: '{args.uri}'?")

    elif args.file:
        print(f"Searching by favicon from file {os.path.abspath(args.file)}...")
        try:
            fav = Favicon.from_file(args.file)
            favicons.append(fav)
        except Exception as e:
            print(f"[-] Failed to load favicon from file: {e}")

    elif args.domain:
        print(f"Searching by possible favicons from domain {args.domain}...")
        icons = []
        try:
            icons = _favicon_lib.get(f"http://{args.domain}")
        except Exception as e:
            print(f'[!] Unable to guess favicons for {args.domain}: {e}')
        if icons:
            icon_urls = ', '.join([icon.url for icon in icons])
            print(f'[-] Found {len(icons)} favicons for {args.domain}: {icon_urls}')
            unique_favicons = set(favicons)
            for icon in icons:
                if icon.width not in (32, 0):
                    continue
                try:
                    new_favicon = Favicon.from_url(icon.url, custom_type=f'guessed favicons of {args.domain}')
                    if new_favicon not in unique_favicons:
                        favicons.append(new_favicon)
                        unique_favicons.add(new_favicon)
                except Exception as e:
                    print(f"Error processing found favicon from URL {icon.url} for {args.domain}: {e}")

        ips = resolve_domain(args.domain)
        for ip in ips:
            try:
                fav = Favicon.from_url(f"http://{ip}/favicon.ico", custom_type=f"resolved domain '{args.domain}'")
                unique_favicons = set(favicons)
                if fav and fav not in unique_favicons:
                    favicons.append(fav)
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
    were_links_saved = False
    no_results = False
    last_favicon = None

    if favicons:
        for fav in favicons:
            last_favicon = fav
            fav.tinyurl = args.tinyurl
            print(f"Results for favicon from {fav.type}: {fav.source}\n")
            if args.verbose:
                print(fav.hashes_text() + '\n')
            print(fav.links_categorized_text())
            if args.save_links_filename:
                with open(args.save_links_filename, "a") as f:
                    were_links_saved = True
                    f.write(fav.links_only_text())

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
            if preview_results:
                filename = f'{last_favicon.murmur_hash}{preview_file}'.replace('-', '_')
                path = os.path.join(OUTPUT_DIR, filename)
                with open(filename, 'w') as file:
                    file.write('\n'.join(preview_results))
                    print(f'{Fore.GREEN}Preview results for favicon with MurmurHash {last_favicon.murmur_hash} saved to {path}')
            else:
                no_results = True
    else:
        print("No results.")
        no_results = True

    if no_results:
        if args.file:
            print(f'{Fore.YELLOW}Try to specify as an input a domain with -d or an url of favicon with -u!')
        elif args.uri:
            print(f'{Fore.YELLOW}Try to specify as an input a domain with -d or a PNG/ICO file of favicon with -f!')
        elif args.domain:
            print(f'{Fore.YELLOW}Try to specify as an input an url of favicon with -u or a PNG/ICO file of favicon with -f!')

    if were_links_saved:
        print(f'{Fore.GREEN}All links saved to {os.path.abspath(args.save_links_filename)}')


if __name__ == "__main__":
    main()
