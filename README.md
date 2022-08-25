# pinger
tiny ping application in python

The script `pinger.py` takes two command-line arguments: first argument should be a valid IP address or a FQDN and the second argument should be an integer indicating the number of ICMP echo request the script should send out.

## Usage
1. install requirements using the requirements.txt file (mainly just contain scapy)
2. run the script. example below:
```sh
py pinger.py google.com 4
```
