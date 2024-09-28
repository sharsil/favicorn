# FAVICORN 💖🦄

All-sources tool to search websites by favicons.

## The mechanism

Favicorn takes favicon (url, filename) as an input, and gives you links to search results in 10 platforms. 

Put ⭐ to the repo, so we'll implement automatic scraping of all sources!

## Usage

```sh
$ favicorn.py -u https://emojipedia.org/images/favicon-32x32.png
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

## Testing

```sh
$ python3 -m unittest test_favicorn.py
```