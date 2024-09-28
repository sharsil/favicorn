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
- Extend your scope for pentesting
- Research purposes

## Other relevant tools

- [Favicon-Search](https://github.com/truda8/Favicon-Search)
- [favihunter](https://github.com/eremit4/favihunter)
- [favfound](https://github.com/elihypoo414/favfound)

## Testing

```sh
$ python3 -m unittest test_favicorn.py
```