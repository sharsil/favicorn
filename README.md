# FAVICORN 💖🦄

All-sources tool to search websites by favicons.

## The mechanism

Favicorn takes favicon (url, filename) as an input, and gives you links to search results in 10 platforms. 

Put ⭐ to the repo, so we'll implement automatic scraping of all sources!

## Usage

Search by a specific favicon URL (`--uri`, `-u`):
```sh
$ favicorn.py -u https://emojipedia.org/images/favicon-32x32.png
```

Search by a favicon file (`--file`, `-f`):
```sh
$ favicorn.py -f test-favicon.png
```

Search by a domain (`--domain`, `-d`):
```sh
$ favicorn.py -d google.com
```

Show favicon hashes for a search (`--verbose`):
```sh
$ favicorn.py -d google.com -v
```

Get additional favicon versions using search engines (`--add-from-search-engines`, `-e`):
```sh
$ favicorn.py -d google.com -e
```

Give tinyurl links instead of full links for platforms (`--tinyurl`):
```sh
$ favicorn.py -d google.com --tinyurl
```

Show only links to platforms, don't extract preview of results (`--no-fetch`):
```sh
$ favicorn.py -d google.com --no-fetch
```

## Preview results

By default, Favicorn generates links to search for websites by their favicon across all known platforms,
and then retrieves the first pages of results from some of them.

Currently, ZoomEye, Shodan (key required), and Netlas (key required) are supported.

Export API keys in the following way:
```
export SHODAN_KEY=...
export NETLAS_KEY=...
```

## Supported platforms

| Name        | Login required | Approx quality |
|-------------|----------------|----------------|
| ZoomEye     |      yes       |      good      |
| Shodan      |      yes       |                |
| Fofa        |       no       |      low       |
| VirusTotal  |      yes       |                |
| BinaryEdge  |      yes       |                |
| Netlas      |       no       |                |
| Censys      |       no       |                |
| ODIN        |       no       |                |
| CriminalIP  |      yes       |                |
| HunterHow   |      yes       |                |

## Use cases

- Search for C2 (command and control) servers of hackers
- Search for phishing domains
 - [Andrea Fortuna: Favicon Forensics: hunting phishing sites with Shodan](https://andreafortuna.org/2024/09/18/unmasking-digital-deception-leveraging-shodan-and-favicon-hashes-to-detect-phishing-sites)
- Extend your scope for pentesting
 - [Devansh batham: Weaponizing favicon.ico for BugBounties , OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- Research purposes

## Other relevant tools

- [Favicon-Search](https://github.com/truda8/Favicon-Search)
- [favihunter](https://github.com/eremit4/favihunter)
- [favfound](https://github.com/elihypoo414/favfound)
- [favicon](https://github.com/scottwernervt/favicon)
- [pyfav](https://github.com/phillipsm/pyfav)
- [besticon (favicon-service)](https://github.com/mat/besticon/)
- [favicongrabber.com](https://github.com/antongunov/favicongrabber.com)
- [favicheck](https://github.com/szTheory/favicheck)
- [favicon-hash](https://favicon-hash.kmsec.uk/)

## Testing

```sh
$ python3 -m unittest test_favicorn.py
```