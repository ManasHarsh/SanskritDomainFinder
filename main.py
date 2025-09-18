#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
संस्कृते उप-डोमेनान्वेषकः
उपयोगः:
    python3 उपडोमेन_अन्वेषक.py लक्ष्य.com --wordlist शब्द.txt --threads 30

सूचना:
    Python-कीवर्ड् तथा मानक-लायब्ररी नामाः आङ्ग्लभाषायामेव सन्ति; अन्यं सर्वं संस्कृते प्रदत्तम्।
    केवलं स्वस्य वा परीक्षितप्रवेशेनाधिकारयुक्त-डोमेन् परीक्षणं कुर्वीत।
"""

import argparse as आर्गपार्स
import requests as अनुरोध
import socket as सॉकेट
import concurrent.futures as समवात
import sys as प्रणाली
import re as रे

आरम्भसंदेशः = "अन्वेषणारम्भः — उप-डोमेन् अन्वेषणं आरभ्यते..."
CRT_अन्वेषणसंदेशः = "प्रमाणपत्र-पारदर्शिता अन्वेषणं (crt.sh) आरभ्यते..."
ब्रूट्संदेशः = "ब्रूट्-बल् आरभ्यते — शब्दसूच्याः उपयोगेन..."
समाप्तिसंदेशः = "समाप्तम् — प्राप्ताः उप-डोमेन्स्:"
त्रुटिसूचनम् = "त्रुटिः:"
अनुमतिसूचनम् = ("सूचना: केवलं स्वस्य वा लेखेन अनुमत-डोमेन् उपरि परीक्षणं कुर्वीत।")

def crtsh_अन्वेषण(डोमेन: str):
    """crt.sh इत्यतः उप-डोमेन्स् एकत्रीकरणम्"""
    print(CRT_अन्वेषणसंदेशः)
    url = f"https://crt.sh/?q=%25.{डोमेन}&output=json"
    try:
        r = अनुरोध.get(url, timeout=15)
        if r.status_code != 200:
            print(f"{त्रुटिसूचनम्} crt.sh उत्तरे स्थिति: {r.status_code}")
            return set()
        data = r.json()
        उपs = set()
        for वस्तु in data:
            नाम = वस्तु.get('name_value', '')
            for न in रे.split(r"\n", नाम):
                न = न.strip()
                न = रे.sub(r"^\*\.", "", न)
                if न.endswith(डोमेन):
                    उपs.add(न.lower())
        return उपs
    except Exception as e:
        print(f"{त्रुटिसूचनम्} crt.sh: {e}")
        return set()

def DNS_समाधान(उपनाम: str):
    """उप-नामस्य DNS-समाधनं प्रयत्नं कुर्वन्तु"""
    try:
        ip = सॉकेट.gethostbyname(उपनाम)
        return उपनाम, ip
    except Exception:
        return उपनाम, None

def ब्रूट्बल_कर(डोमेन: str, शब्दपत्रिका: str, थ्रेड्_संख्या: int = 20):
    """शब्दपत्रिकया ब्रूट्-बल् उप-डोमेन्स् अन्वेष्टु"""
    print(ब्रूट्संदेशः)
    उपs = set()
    try:
        with open(शब्दपत्रिका, 'r', encoding='utf-8') as f:
            शब्दाः = [w.strip() for w in f if w.strip() and not w.strip().startswith('#')]
    except Exception as e:
        print(f"{त्रुटिसूचनम्} शब्दपत्रिका पठने: {e}")
        return उपs, {}

    प्रत्याशाः = [f"{w}.{डोमेन}".lower() for w in शब्दाः]
    समाहितानि = {}
    with समवात.ThreadPoolExecutor(max_workers=थ्रेड्_संख्या) as एग्जेक्यू:
        भविष्याः = {एग्जेक्यू.submit(DNS_समाधान, प्र): प्र for प्र in प्रत्याशाः}
        for fut in समवात.as_completed(भविष्याः):
            उप, ip = fut.result()
            if ip:
                समाहितानि[उप] = ip
    return set(समाहितानि.keys()), समाहितानि

def मुख्य():
    parser = आर्गपार्स.ArgumentParser(description="उप-डोमेन अन्वेषकः — संस्कृतम्")
    parser.add_argument('लक्ष्य', help='लक्ष्य-डोमेन (उदा: example.com)')
    parser.add_argument('--wordlist', '-w', default=None, help='ब्रूट्-बल् शब्दपत्रिका (पथः)')
    parser.add_argument('--threads', '-t', type=int, default=20, help='थ्रेड् संख्या')
    args = parser.parse_args()

    print(अनुमतिसूचनम्)
    print(आरम्भसंदेशः)

    डोमेन = args.लक्ष्य.strip().lower()
    सर्वे_उप = set()
    समाहितम्_map = {}

    crt_उप = crtsh_अन्वेषण(डोमेन)
    सर्वे_उप.update(crt_उप)

    if args.wordlist:
        bf_उप, bf_map = ब्रूट्बल_कर(डोमेन, args.wordlist, थ्रेड्_संख्या=args.threads)
        सर्वे_उप.update(bf_उप)
        समाहितम्_map.update(bf_map)

    अवशिष्टानि = [s for s in सर्वे_उप if s not in समाहितम्_map]
    if अवशिष्टानि:
        with समवात.ThreadPoolExecutor(max_workers=args.threads) as एग्जेक्यू:
            भविष्याः = {एग्जेक्यू.submit(DNS_समाधान, s): s for s in अवशिष्टानि}
            for fut in समवात.as_completed(भविष्याः):
                उप, ip = fut.result()
                if ip:
                    समाहितम्_map[उप] = ip

    print()
    print(समाप्तिसंदेशः)
    for s in sorted(सर्वे_उप):
        ip = समाहितम्_map.get(s)
        if ip:
            print(f" - {s}  →  समाधानः: {ip}")
        else:
            print(f" - {s}  →  समाधानः: (न समाहितम्)")

if __name__ == '__main__':
    try:
        मुख्य()
    except KeyboardInterrupt:
        print("\nपरिचालनम् रुद्धम् (उपयोक्ता विरामकृतवान्).")
        प्रणाली.exit(1)
