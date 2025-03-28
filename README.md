# SubLens

![GitHub](https://img.shields.io/github/license/0xd3sp0/SubLens) ![GitHub issues](https://img.shields.io/github/issues/0xd3sp0/SubLens)

A comprehensive Bash-based tool for passive subdomain enumeration using multiple sources such as Assetfinder, Subfinder, Findomain, CRT.SH, and more. The tool supports both single-domain and bulk scanning with parallel execution for faster results.

## Features

- Collects subdomains from multiple sources:
  - Assetfinder
  - Subfinder
  - Findomain
  - CRT.SH
  - Anubis
  - RapidDNS
  - Wayback Machine
  - AbuseIPDB
  - Amass
- Supports parallel execution for faster results.
- Resolves live subdomains using `httpx`.
- Aggregates results into a single output file.
- Supports bulk scanning via a domain list file.
- Gracefully handles missing tools and skips related tasks.

## Installation

### Prerequisites

Ensure the following tools are installed on your system:

- `assetfinder`
- `subfinder`
- `findomain`
- `sublist3r`
- `curl`
- `jq`
- `httpx`
- `amass`
- `parallel` (optional, for parallel execution)

You can install these tools using package managers like `apt`, `brew`, or by downloading them from their respective repositories.

### Clone the Repository

```bash
git clone https://github.com/0xd3sp0/SubLens.git
cd SubLens
```

### Make the Script Executable
```bash
chmod +x subl3ns.sh
```
---
### Usage

Run the script with the target domain or a file containing a list of domains:

```bash
./subl3ns.sh -d example.com
```
Or scan multiple domains from a file:
```bash
./subl3ns.sh -l domains.txt
```
---

### Options
|-d |--domain   |Target domain to enumerate (required)       |N/A                  |
|---|-----------|--------------------------------------------|---------------------|
|-l | --list    |File containing list of domains to enumerate|N/A                  |
|-o | --output  |Output directory                            |~/HUNT/&lt;DOMAIN&gt;|
|-s | --silent  |Silent mode (only show results)             |Disabled             |
|-r | --resolve |Resolve live subdomains                     |Disabled             |
|-t | --thread  |Threads for resolution                      |40                   |
|-p | --parallel|Run tools in parallel                       |Disabled             |
|-h | --help    |Show help                                   |                     |
|-v | --version |Show version                                |                     |
---
### Examples
Basic usage for a single domain:
```bash
./subl3ns.sh -d example.com
```
Run tools in parallel and resolve live subdomains:
```bash
./subl3ns.sh -d example.com -p -r
```
Scan multiple domains from a file:
```bash

./subl3ns.sh -l domains.txt -o /custom/path
```
Specify a custom output directory:
```bash

./subl3ns.sh -d example.com -o /custom/path
```
---
## Example Output
```bash
[+] Enumerating subdomains for: example.com
[+] Creating directory structure...
[+] Parallel execution started
[*] Assetfinder: 15
[*] Subfinder: 25
[*] Findomain: 20
[*] CRT.SH: 30
[+] Aggregating results...
[+] Total unique subdomains: 75
[+] Results saved to: ~/HUNT/example.com/subs.txt
```

### Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
