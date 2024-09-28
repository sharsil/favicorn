#!/usr/bin/python3

import mimetypes
import argparse
import requests
import hashlib
import codecs
import sys
import re
import os

requests.packages.urllib3.disable_warnings()

try:
    import dns.resolver, mmh3
except ImportError as e:
    #print("Error -> ", e)
    print("[-] {}. Use pip...".format(e))
    sys.exit(1)

def make_links(hash, md5h, sha256h, b64h, hexh):
    links_bundle = '\n'.join((f'ZoomEye:      https://www.zoomeye.org/searchResult?q=iconhash%3A%22{hash}%22',
                              f'Shodan:       https://www.shodan.io/search?query=http.favicon.hash:{hash}',
                              f'Fofa:         https://en.fofa.info/result?qbase64={b64h}',
                              f'VirusTotal:   https://www.virustotal.com/gui/search/entity:url%20main_icon_md5:{md5h}',
                              f'BinaryEdge:   https://app.binaryedge.io/services/query?query=web.favicon.md5:{md5h}&page=1',
                              f'Netlas:       https://app.netlas.io/responses/?q=http.favicon.hash_sha256:{sha256h}&page=1',
                              f'Censys:       https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=services.http.response.favicons.md5_hash:{md5h}',
                              f'ODIN:         https://getodin.com/search/hosts?query=services.modules.http.favicon.murmur_hash%3A%22{hash}%22',
                              f'CriminalIP:   https://www.criminalip.io/asset/search?query=favicon:+{hexh}',
                              f'HunterHow:    https://hunter.how/list?searchValue=favicon_hash%3A%22{hash}%22'))
    return links_bundle

def make_se_links(domain):
    links_bundle = '\n'.join((f'Google:      https://www.google.com/s2/favicons?domain={domain}&size=32',
                              f'DuckDuckGo:  https://icons.duckduckgo.com/ip3/{domain}.ico',
                              f'Unavatar:    https://unavatar.io/{domain}'))

    return links_bundle

def get_favicon(source, type):
    try:
        get_favicon = sess.get(source, verify=False)

        if get_favicon.status_code == 200:
            faviWords = ['image', 'icon']
            cont = get_favicon.headers['Content-Type']

            if any(re.findall('|'.join(faviWords) , cont)):
                _favicon = get_favicon.content
                _favilst = [{'source': source, 'favicon': _favicon, 'type': type}]

                return _favilst

    except Exception as e:
        print(e)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get favicon hashes from multiple sources"
    )

    parser.add_argument("-f", "--file", help="Get favicon hash from a specific file")
    parser.add_argument("-e", "--engines", help="Get favicon version using search engines")
    parser.add_argument("-u", "--uri", help="Get favicon hash from WEB")
    parser.add_argument("-r", "--resolve", help="Get favicon hash from resolved IP address")
    args = parser.parse_args()

    selist = []
    favilst = []

    if args.uri is not None:
        if args.uri.count('/') >= 3 and not args.uri.endswith('/'):
            try:
                sess = requests.Session()
                favilst = get_favicon(args.uri, "direct link")

                #else:
                #    print(f"[-] Can't fetch anything from '{args.uri}'. Status code is: '{get_favicon.status_code}'")
                #    sys.exit(1)
            except Exception as e:
                print(e)
        else:
            print(f"[-] Is it correct or full URI: '{args.uri}'?")
            sys.exit(1)

    elif args.file is not None:
        try:
            check_file = os.stat(args.file).st_size

            if check_file == 0:
                 print(f"[-] File '{args.file}' is empty")
                 sys.exit(1)
            else:
                mime_type, _ = mimetypes.guess_type(args.file)

                if mime_type.startswith('image'):
                    with open(args.file, 'rb') as _favicon:
                        _favicon = _favicon.read()
                        favilst = [{'source': os.path.abspath(args.file), 'favicon': _favicon, 'type': 'file'}]

                else:
                    print(f"[-] Is '{args.file}' an image file?")

        except Exception as e:
            print(e)

    elif args.resolve is not None:

        # CloudFlare
        cf_ranges = ['103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13',
                     '104.24.0.0/14', '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18',
                     '162.158.0.0/15', '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
                     '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17']

        '''for cf_range in cf_ranges:
            IP = ipaddress.ip_address(zs)
            CIDR = ipaddress.ip_network(cf_range)
            if IP in CIDR:
                print(cf_range)'''

        ips = resolve_domain(args.resolve)

        if ips is not None:
            try:
                sess = requests.Session()
                favilst = []

                for ip in ips:
                    ipdata = get_favicon(f"http://{ip}/favicon.ico", f"resolved domain '{args.resolve}'") # ?????????
                    if ipdata is not None:
                        favilst.append(ipdata[0])

            except Exception as e:
                print(f'[-] Resolve: {e}')

    elif args.engines is not None:
        selist = make_se_links(args.engines)
        favilst = None

    #if favilst is not None:
    if favilst:
        for favidata in favilst:
            favicon = codecs.encode(favidata['favicon'], 'base64')
            hash = mmh3.hash(favicon)

            if hash:
                md5h = hashlib.md5(favidata['favicon']).hexdigest()
                sha256h = hashlib.sha256(favidata['favicon']).hexdigest()
                b64h = codecs.encode('icon_hash="{}"'.format(hash).encode('utf-8'), 'base64').decode('utf-8').strip()
                hexh = hex(hash).replace('0x', '', 1)

                show_links = make_links(hash, md5h, sha256h, b64h, hexh)
                print(f'\nResults from {favidata["type"]}: {favidata["source"]}\n')
                print(show_links)

    elif selist:
        print("[INFO] That icons might be different from favicon on the target! May be old copy or alternative?!")
        print("[NOTE] Try to extend the scope with that results or just look at another image ;)\n")
        print(selist)

    else:
        print("Nothing is found...")

# КОММЕНТЫ
# Не знаю надо ли добавить поиск при помощи API-ключей? Не избыточно ли это
# https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=http.favicon.hash:{favicon_hash}
# https://github.com/truda8/Favicon-Search/blob/main/Favicon_Api/Collect.py


# Некоторые сервисы просят авторизации (они ниже), я просто думал этот печатать при генерации ссылок, типа так:
# Shodan (need login):
# https://www.shodan.io/search?query=http.favicon.hash:948997205

# Вот кто просит авторизацию:
# shodan: log in to use search filters.
# vtotal: Unlock the power of advanced search with VT ENTERPRISE 
# edge: login
# Criminal : Log in to your Criminal IP account to access
# hunter: sign with google

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

