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
listbox = tk.Listbox(root, width=180, height=20)
listbox.pack(padx=10, pady=10)

# Create a start button
start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.pack(pady=5)

# Run the GUI main loop
root.mainloop()
