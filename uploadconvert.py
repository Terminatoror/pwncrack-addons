import os
import subprocess
import requests

# Variables
server_url = 'https://pwncrack.org/upload_handshake'
key = 'your_key_here'
combined_file = 'combined.hc22000'

# Convert all .pcap files to .hc22000
pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap') or f.endswith('.pcapng')]
for pcap_file in pcap_files:
    subprocess.run(['hcxpcapngtool', '-o', combined_file, pcap_file])

# Upload the combined .hc22000 file
with open(combined_file, 'rb') as file:
    files = {'handshake': file}
    data = {'key': key}
    response = requests.post(server_url, files=files, data=data)

# Print the response
print(response.json())
