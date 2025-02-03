import requests
from bs4 import BeautifulSoup
import json
import re

OID_CACHE = {}

try:
    with open('oid_cache.json', 'r') as f:
        OID_CACHE.update(json.load(f))
except FileNotFoundError:
    pass

CODE_PATTERN = re.compile(r'(\w+)\(\d+\)')

def query_oid(oid: str):
    if oid in OID_CACHE:
        return OID_CACHE[oid]

    resp = requests.get(f'https://oid-base.com/get/{oid}')
    if resp.status_code != 200:
        return None

    soup = BeautifulSoup(resp.text, 'lxml')
    table = soup.css.select('body center table')[3]
    trs = table.css.select('tr')
    path = [a.text for a in trs[0].find_all('a')]
    code = [c.text for c in trs[1].find_all('code')]
    if len(code) == 0:
        return None

    if m := CODE_PATTERN.match(code[0]):
        code_name = m.group(1)
    else:
        code_name = code[0]

    path.append(code[0])
    record = {'path': path, 'name': code_name}
    if len(code) == 2:
        record['other_name'] = code[1]
    OID_CACHE[oid] = record

    try:
        with open('oid_cache.json', 'w') as cf:
            json.dump(OID_CACHE, fp=cf, ensure_ascii=False, indent=4)
    except FileNotFoundError:
        pass

    return record