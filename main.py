#!/usr/bin/env python3
# SQLDorker-SAFE main (no real attacks) — copy into SQLDorker/sqldorker_safe.py

import os, sys, json, time, random, hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# third-party
try:
    import requests
    from bs4 import BeautifulSoup
    import pyfiglet
    from colorama import Fore, Style, init as colorama_init
except Exception:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

colorama_init(autoreset=True)

# CONFIG
API_KEY = ""   # optional: Google API key
CSE_ID  = ""   # optional: Google CSE/CX id
USERS_FILE = "users.json"
OUTPUT_DIR = "results"
PREVIEW_FILE = "preview_commands.txt"

# limits
DEFAULTS = {
    "user": {"max_pages": 10, "max_threads": 2, "can_tamper": False, "can_save": False},
    "premium": {"max_pages": 200, "max_threads": 10, "can_tamper": True, "can_save": True},
    "owner": {"max_pages": 1000, "max_threads": 20, "can_tamper": True, "can_save": True}
}

TAMPER_OPTIONS = {
    1: "between",
    2: "randomcase",
    3: "space2comment",
    4: "space2plus",
    5: "space2randomblank",
    6: "equaltolike",
    7: "modsecurityversioned",
    8: "modsecurityzeroversion",
    9: "apostrophenullencode",
    10: "charunicodeencode",
    11: "unmagicquotes",
    99: "ALL"
}

SIMULATED_VULN_PROB = 0.08  # 8% base vuln chance

# helpers
def now():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, status=None, color=Fore.WHITE):
    stamp = now()
    status_text = f"[{status}]" if status else ""
    print(f"{Fore.BLUE}{stamp} [INFO]{Style.RESET_ALL} {color}{status_text}{Style.RESET_ALL} : {msg}")

def ensure_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

def load_users():
    ensure_users()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(u):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(u, f, indent=2)

def hash_pw(pw):
    salt = os.urandom(8).hex()
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}${h}"

def check_pw(stored, pw):
    try:
        salt, h = stored.split("$")
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except:
        return False

def first_owner_setup():
    users = load_users()
    if any(v.get("role")=="owner" for v in users.values()):
        return
    print("\n== First-time setup: create OWNER account ==")
    while True:
        u = input("Owner username: ").strip()
        p = input("Owner password: ").strip()
        if not u or not p:
            print("Invalid.")
            continue
        users[u] = {
            "password": hash_pw(p),
            "role": "owner",
            "premium_until": None,
            "limits": {"max_pages": DEFAULTS["owner"]["max_pages"], "max_threads": DEFAULTS["owner"]["max_threads"]}
        }
        save_users(users)
        print("Owner created.")
        break

# auth
def register():
    users = load_users()
    print("\n== Register ==")
    uname = input("Username: ").strip()
    if not uname or uname in users:
        print("Invalid or exists.")
        return
    pw = input("Password: ").strip()
    users[uname] = {
        "password": hash_pw(pw),
        "role": "user",
        "premium_until": None,
        "limits": {"max_pages": DEFAULTS["user"]["max_pages"], "max_threads": DEFAULTS["user"]["max_threads"]}
    }
    save_users(users)
    print("Registered.")

def login():
    users = load_users()
    print("\n== Login ==")
    uname = input("Username: ").strip()
    if uname not in users:
        print("No such user.")
        return None
    pw = input("Password: ").strip()
    if check_pw(users[uname]["password"], pw):
        print("Login success.")
        return uname
    else:
        print("Wrong password.")
        return None

# owner actions
def list_users():
    users = load_users()
    print("\n-- Users --")
    for k,v in users.items():
        print(f"{k:15} role={v.get('role')} premium_until={v.get('premium_until')} limits={v.get('limits')}")
    print("--")

def grant_premium():
    users = load_users()
    target = input("Target username: ").strip()
    if target not in users:
        print("Not found.")
        return
    days = int(input("Days of premium: ").strip() or "0")
    mp = int(input("Set max_pages (e.g. 200): ").strip() or str(DEFAULTS["premium"]["max_pages"]))
    mt = int(input("Set max_threads (e.g. 10): ").strip() or str(DEFAULTS["premium"]["max_threads"]))
    until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d") if days>0 else None
    users[target]["role"] = "premium"
    users[target]["premium_until"] = until
    users[target]["limits"] = {"max_pages": mp, "max_threads": mt}
    save_users(users)
    print("Granted.")

def remove_user():
    users = load_users()
    target = input("Username to remove: ").strip()
    if target not in users:
        print("Not found.")
        return
    if input(f"Delete {target}? (y/n): ").strip().lower()=="y":
        del users[target]
        save_users(users)
        print("Deleted.")

# UI
def clear():
    os.system("cls" if os.name=="nt" else "clear")

def show_banner():
    art = pyfiglet.figlet_format("SQLDorker")
    print(Fore.CYAN + art + Style.RESET_ALL)

def show_user_panel(username):
    users = load_users()
    info = users.get(username, {})
    role = info.get("role","user")
    pu = info.get("premium_until") or "never"
    color = Fore.CYAN if role=="owner" else (Fore.YELLOW if role=="premium" else Fore.RED)
    print("="*60)
    print(f"{color}User   : {username}{Style.RESET_ALL}")
    print(f"{color}Role   : {role.upper()}{Style.RESET_ALL}")
    print(f"{color}Expiry : {pu}{Style.RESET_ALL}")
    print("="*60)

# search
def fetch_cse(query, pages):
    urls=[]
    if not API_KEY or not CSE_ID:
        return fetch_scrape(query, pages)
    for p in range(pages):
        start = p*10 + 1
        try:
            r = requests.get("https://www.googleapis.com/customsearch/v1", params={"key":API_KEY,"cx":CSE_ID,"q":query,"start":start}, timeout=10)
            data = r.json()
            for it in data.get("items",[]):
                if it.get("link"):
                    urls.append(it.get("link"))
        except Exception as e:
            log(f"CSE error: {e}", status="ERROR", color=Fore.RED)
    return list(dict.fromkeys(urls))

def fetch_scrape(query, pages):
    urls=[]
    headers={"User-Agent":"Mozilla/5.0"}
    for p in range(pages):
        start = p*10
        q = query.replace(" ", "+")
        url = f"https://www.google.com/search?q={q}&start={start}"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href=a['href']
                if href.startswith("/url?q="):
                    link = href.split("/url?q=")[1].split("&")[0]
                    urls.append(link)
        except Exception as e:
            log(f"Scrape error: {e}", status="ERROR", color=Fore.RED)
    return list(dict.fromkeys(urls))

# tamper listing (reads local plugin/sqlmap-dev/tamper)
def list_local_tampers():
    tdir = os.path.join("plugin","sqlmap-dev","tamper")
    tampers=[]
    if os.path.isdir(tdir):
        for f in os.listdir(tdir):
            if f.endswith(".py") and not f.startswith("__"):
                tampers.append(f[:-3])
    return sorted(tampers)

def choose_tamper(role):
    if role not in ("owner","premium"):
        return None
    local = list_local_tampers()
    print("\nTamper options (local sqlmap tamper folder):")
    if local:
        for i,t in enumerate(local, start=1):
            print(f"{i}. {t}")
    else:
        print("(no tamper scripts found locally)")
    print("99. curated popular list")
    sel=input("Choice (comma list or 99): ").strip()
    if not sel:
        return None
    if sel=="99":
        chosen=[v for k,v in TAMPER_OPTIONS.items() if k!=99]
    else:
        try:
            idxs=[int(x) for x in sel.split(",") if x.strip().isdigit()]
            chosen=[local[i-1] for i in idxs if 1<=i<=len(local)]
        except:
            chosen=[]
    return chosen if chosen else None

# simulate scan
def simulate_url_vuln(url, tamper_opt=None):
    base=SIMULATED_VULN_PROB
    l=url.lower()
    if "vuln" in l or "test" in l:
        prob=min(0.7, base+0.4)
    else:
        prob=base
    if tamper_opt:
        prob=min(0.95, prob+0.05)
    time.sleep(random.uniform(0.5,1.2))
    return random.random()<prob

def worker_scan(url, tamper_opt, outfile):
    log(url, status="SCANNING", color=Fore.YELLOW)
    try:
        vuln = simulate_url_vuln(url, tamper_opt)
        if vuln:
            log(url, status="VULN", color=Fore.GREEN)
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            with open(outfile,"a",encoding="utf-8") as f:
                f.write(url+"\n")
        else:
            log(url, status="SAFE", color=Fore.RED)
    except Exception as e:
        log(f"Scan error {e}", status="ERROR", color=Fore.RED)

# preview command builder (safe)
def build_preview_command(url, tamper_list=None, extra_flags=None):
    parts=["python3","plugin/sqlmap-dev/sqlmap.py","-u",f"\"{url}\"","--batch","--random-agent"]
    if extra_flags:
        parts+=extra_flags
    if tamper_list:
        parts.append("--tamper=" + ",".join(tamper_list))
    return " ".join(parts)

def preview_and_save(url, tamper_list, extra_flags=None):
    cmd = build_preview_command(url, tamper_list, extra_flags)
    print("\n[COMMAND PREVIEW] (do NOT run against non-lab targets):")
    print(cmd)
    if input("Save preview to preview_commands.txt? (y/N): ").strip().lower()=="y":
        with open(PREVIEW_FILE,"a",encoding="utf-8") as f:
            f.write(cmd+"\n")
        print("Saved.")

# scan flow
def scan_flow(username, is_owner=False):
    users=load_users()
    info=users.get(username)
    role=info.get("role","user")
    limits=info.get("limits", DEFAULTS[role])
    if is_owner:
        limits={"max_pages":DEFAULTS["owner"]["max_pages"],"max_threads":DEFAULTS["owner"]["max_threads"]}
    clear(); show_banner(); show_user_panel(username)
    dork=input("Masukkan Google Dork: ").strip()
    pages=int(input(f"Berapa page (max {limits['max_pages']}): ").strip() or "1")
    if pages>limits['max_pages']:
        print("Anda harus premium.")
        return
    threads=int(input(f"Berapa thread (max {limits['max_threads']}): ").strip() or "1")
    if threads>limits['max_threads']:
        print("Anda harus premium.")
        return
    tamper_choice = choose_tamper(role)
    outfile = input("Nama file output (vuln only): ").strip() or "vuln_results.txt"
    # fetch urls
    log("Fetching URLs...", status="INFO", color=Fore.CYAN)
    urls = fetch_cse(dork, pages)
    log(f"Found {len(urls)} URLs", status="FOUND", color=Fore.CYAN)
    if not urls:
        print("No urls found.")
        return
    # ask preview for each if user wants
    do_preview = input("Show preview commands instead of auto-scan? (y/N): ").strip().lower()=="y"
    extra_flags = []
    if do_preview:
        for u in urls:
            preview_and_save(u, tamper_choice, extra_flags)
        print("Preview commands saved. Run manually in lab if needed.")
        return
    # simulated scanning (safe)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures=[ex.submit(worker_scan,u,tamper_choice,outfile) for u in urls]
        for fut in as_completed(futures):
            try: fut.result()
            except Exception as e:
                log(f"Worker error: {e}", status="ERROR", color=Fore.RED)
    log(f"Scan complete. Vuln saved to {outfile}", status="DONE", color=Fore.CYAN)
    input("Enter to continue...")

# dashboards
def owner_dashboard(username):
    while True:
        clear(); show_banner(); show_user_panel(username)
        print("1) Start scan")
        print("2) List users")
        print("3) Grant premium")
        print("4) Remove user")
        print("5) Logout")
        c=input("Choice: ").strip()
        if c=="1": scan_flow(username, is_owner=True)
        elif c=="2": list_users(); input("Enter...")
        elif c=="3": grant_premium(); input("Enter...")
        elif c=="4": remove_user(); input("Enter...")
        elif c=="5": break
        else: print("Invalid.")

def user_dashboard(username):
    while True:
        clear(); show_banner(); show_user_panel(username)
        print("1) Start scan")
        print("2) Logout")
        c=input("Choice: ").strip()
        if c=="1": scan_flow(username)
        elif c=="2": break
        else: print("Invalid.")

# main
def main():
    ensure_users()
    first_owner_setup()
    while True:
        clear(); show_banner()
        print("1) Login")
        print("2) Register")
        print("3) Exit")
        ch=input("Choice: ").strip()
        if ch=="1":
            user=login()
            if not user: input("Enter..."); continue
            info=load_users().get(user)
            role=info.get("role","user")
            # expire check
            pu=info.get("premium_until")
            if pu:
                try:
                    dt=datetime.strptime(pu,"%Y-%m-%d")
                    if dt < datetime.now():
                        info["role"]="user"
                        info["premium_until"]=None
                        info["limits"]=DEFAULTS["user"]
                        save_users(load_users())
                        role="user"
                except:
                    pass
            if role=="owner":
                owner_dashboard(user)
            else:
                user_dashboard(user)
        elif ch=="2":
            register(); input("Enter...")
        elif ch=="3":
            print("Bye."); break
        else:
            print("Invalid."); input("Enter...")

if __name__=="__main__":
    main()
