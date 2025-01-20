# Asset Discovery Tool

This tool helps in discovering assets related to a specific domain. It performs various tasks such as retrieving the IP address, finding subdomains, scanning ports, and retrieving CVE information.

## Features

1. **IP Address Retrieval**: Fetches the IP address for the given domain.
2. **Subdomain Discovery**: Uses `assetfinder` to find subdomains and lists their corresponding IP addresses.
3. **Port Scanning**: Scans a range of ports on the target domain using `nmap`.
4. **CVE Retrieval**: Fetches possible CVEs related to the domain from the NVD (National Vulnerability Database).

## Usage

1. **Run the Script**
   ```bash
   python asset_discovery_tool.py
   ```

2. **Input the Domain Name**
   ```
   Enter the domain name: example.com
   ```

3. **Subdomain Scanning**
   The script will automatically scan and list subdomains with their IP addresses.

4. **Port Scanning**
   You will be prompted to enter a range of ports to scan (e.g., `60-120`). The script will then scan the specified range for open ports and display detailed information about each port.

5. **CVE Retrieval**
   The script retrieves and lists possible CVEs related to the target domain from the NVD.

## Dependencies

- `subprocess`
- `requests`
- `json`
- `xmltodict`
- `socket`
- `nmap`
- `re`
- `pyfiglet`
- `datetime`
- `tabulate`

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/asset_discovery_tool.git
   cd asset_discovery_tool
   ```

2. **Install the Required Python Packages**
   ```bash
   pip install -r requirements.txt
   ```

## Example Output

```bash
Asset Discovery Tool
--------------------------------------------------
Enter the domain name: example.com
IP address for example.com: 93.184.216.34
--------------------------------------------------
Sub-Domain Scanning started at: 2025-01-20 10:00:00
Please Wait
- - - - - - - - - - - - - - - - - - - - - - - - - 
Subdomains for example.com:
+-----------------------+----------------+
| Subdomain             | IP Address     |
+-----------------------+----------------+
| www.example.com       | 93.184.216.34  |
| api.example.com       | 93.184.216.35  |
+-----------------------+----------------+

Total Subdomains found: 2
--------------------------------------------------
Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)
Enter port range: 80-90
Port Scanning started at: 2025-01-20 10:05:00
Please Wait
- - - - - - - - - - - - - - - - - - - - - - - - - 
Host : example.com (93.184.216.34)
State : up
----------
Protocol : tcp

Port : 80
Port_state : open
Service : http
Product : Apache
Version: 2.4.41

--------------------------------------------------
Retrieving CVE at nist.gov start at: 2025-01-20 10:10:00
Please Wait
- - - - - - - - - - - - - - - - - - - - - - - - - 
Possible CVEs for example.com:
CVE-2021-12345
CVE-2021-12346
```

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
