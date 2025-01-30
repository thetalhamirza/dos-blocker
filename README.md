# DoS Detection & Prevention Script

## Overview

This Python script monitors network traffic using `scapy` and detects potential DoS (Denial of Service) attacks by tracking packet rates per IP. If an IP exceeds the defined threshold, it is automatically blocked using `iptables`. When the script exits, all `iptables` rules added during execution are removed to restore normal connectivity. 

This is a proof-of-concept script as it shows practically how traffic can be blocked if there is an abnormal amount of packets sent per unit time. For this reason, the script restores the iptables to its previous state before execution, to avoid disruption in legitimate network traffic.

## Features

- Monitors incoming packets and detects high packet rates per IP.
- Blocks IPs exceeding the threshold using `iptables`.
- Automatically restores `iptables` rules on script exit to avoid unintentional disruptions.
- Uses colored console output for better readability.
- Requires root privileges to run.

## Requirements

Ensure you have the following dependencies installed:

```bash
pip install scapy colorama termcolor
```

## Usage

Run the script with root privileges:

```bash
sudo python3 dos_blocker.py
```

### Stopping the Script

- Press `Ctrl+C` or close the terminal.
- The script will automatically **restore all ************************************************************************`iptables`************************************************************************ rules** upon exit.

## Contributions

This script was built using a tutorial by **faanross**.

### **My Contributions:**

- Implemented **iptables rule restoring** to restore network connectivity on exit.
- Improved code structure by refactoring logic into `main()`.
- Added **colored output** for better visibility.
- Adjusted the threshold system for better clarity.

## Disclaimer

Use this script responsibly. Blocking legitimate traffic may cause network disruptions. Ensure you understand how `iptables` works before deploying it in a production environment.

## License

MIT License.