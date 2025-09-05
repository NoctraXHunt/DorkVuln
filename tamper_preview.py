#!/usr/bin/env python3
"""
tamper_preview.py
- list local tamper scripts (plugin/sqlmap-dev/tamper/)
- let user pick tamper(s)
- build preview sqlmap command (saved to preview_commands.txt)
"""
import os, textwrap

TAMPER_DIR = os.path.join("plugin","sqlmap-dev","tamper")
CURATED = ["between","randomcase","space2comment","space2plus","equaltolike","charunicodeencode"]

def find_local():
    tampers=[]
    if os.path.isdir(TAMPER_DIR):
        for f in os.listdir(TAMPER_DIR):
            if f.endswith(".py") and not f.startswith("__"):
                tampers.append(f[:-3])
    return sorted(tampers)

def build_cmd(target, tampers=None, extra=None):
    parts=["python3","plugin/sqlmap-dev/sqlmap.py","-u",f"\"{target}\"","--batch","--random-agent"]
    if extra: parts+=extra
    if tampers:
        parts.append("--tamper=" + ",".join(tampers))
    return " ".join(parts)

def main():
    print("SQLMap Tamper Preview")
    local=find_local()
    if local:
        for i,t in enumerate(local,1):
            print(f"{i}. {t}")
    else:
        print("(no local tamper found)")
    print("99. curated popular")
    sel=input("Choice (comma list): ").strip()
    if sel=="99":
        chosen = [c for c in CURATED if c in local] or CURATED
    else:
        chosen=[]
        for p in sel.split(","):
            p=p.strip()
            if not p: continue
            if p.isdigit():
                idx=int(p)-1
                if 0<=idx<len(local): chosen.append(local[idx])
            else:
                if p in local or p in CURATED: chosen.append(p)
    target=input("Target URL (lab only): ").strip()
    extra=[]
    if input("Include example flags (--level=3 --risk=2)? (y/N): ").strip().lower()=="y":
        extra=["--level=3","--risk=2"]
    cmd=build_cmd(target, chosen, extra)
    print("\nPreview:\n")
    print(textwrap.fill(cmd,width=100))
    if input("Save to preview_commands.txt? (y/N): ").strip().lower()=="y":
        with open("preview_commands.txt","a",encoding="utf-8") as f:
            f.write(cmd+"\n")
        print("Saved.")

if __name__=="__main__":
    main()
