# Network Packet Analyzer

This project is a simple packet analyzer built using Python, Scapy, and Tkinter. It captures network packets and displays their source and destination IP addresses, protocol, and payload data in a GUI window.

## Features

- Captures network packets and displays:
  - Source IP address
  - Destination IP address
  - Protocol
  - Payload data
- User-friendly GUI built with Tkinter
- Automatically detects the current user's home directory to locate the Wireshark `manuf` file

## Prerequisites

- Python 3.x
- Scapy library
- Tkinter (comes with Python's standard library)
- Wireshark installed (for the `manuf` file)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/IamCOD3X/network-packet-analyzer.git
   cd network-packet-analyzer
   ```

2. **Install the required Python packages:**

   ```bash
   pip install scapy
   ```

3. **Ensure Wireshark is installed:**

   Download and install Wireshark from [wireshark.org](https://www.wireshark.org/).

4. **Download the `manuf` file:**

   If you can't find the `manuf` file in the Wireshark installation directory, download it from the [Wireshark GitLab repository](https://gitlab.com/wireshark/wireshark/-/raw/master/manuf) and place it in the `Wireshark` directory within your home directory:
   
   - On Windows: `C:\Users\<YourUsername>\Wireshark\manuf`
   - On Unix-like systems: `/home/<YourUsername>/Wireshark/manuf`

## Usage

1. **Run the script with necessary permissions:**

   On Unix-like systems, you might need to use `sudo` to capture packets:

   ```bash
   sudo python packet_analyzer.py
   ```

2. **Start capturing packets:**

   Click the "Start Capture" button in the GUI to begin capturing and displaying network packets.

## Script Overview

```python
from scapy.all import *
import tkinter as tk
import os

# Get the current user's username
username = os.getlogin()

# Construct the path to the manuf file
manuf_path = f"C:\\Users\\{username}\\Wireshark\\manuf"

# Specify the path to the manuf file
conf.manufdb = manuf_path

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[IP].payload
        listbox.insert(tk.END, f"IP Source: {ip_src} -> IP Destination: {ip_dst}, Protocol: {proto}, Payload: {payload}")

def start_capture():
    sniff(filter="ip", prn=packet_callback, count=10)

# Create the main window
root = tk.Tk()
root.title("Network Packet Analyzer")

# Create a listbox to display captured packets
listbox = tk.Listbox(root, width=120, height=20)
listbox.pack(padx=10, pady=10)

# Create a start button
start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.pack(pady=5)

# Run the GUI main loop
root.mainloop()
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgments

- [Scapy](https://scapy.net/)
- [Wireshark](https://www.wireshark.org/)
