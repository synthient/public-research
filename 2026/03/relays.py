import time
import requests
from arc4 import ARC4

USER_AGENT = "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)"
IPS = ["45.11.182.89"]
KEY = b"hi_few5i6ab&7#d3"
PARAMS_RAW = "gpt=510e2c0f&inc=1&advizor=0&box=0&hp=1&lp=a&line=49&os=10.0.1337&flag=1&itd=1765747045"

def crypt(data: bytes) -> bytes:
    return ARC4(KEY).encrypt(data)

def process_response(resp_text: str):
    try:
        decrypted = crypt(bytes.fromhex(resp_text.strip()))
        print(f"Decrypted: {decrypted.decode(errors='ignore')}")
    except (ValueError, Exception) as e:
        print(f"Decoding error: {e}")

def execute_request(session: requests.Session, ip: str, payload: str):
    url = f"https://{ip}/ai/"
    try:
        response = session.get(url, params={"key": payload}, timeout=10)
        print(f"Status: {response.status_code} | Raw: {response.text}")
        if response.status_code == 200:
            process_response(response.text)
    except requests.RequestException as e:
        print(f"Connection error: {e}")

def main():
    payload_hex = crypt(PARAMS_RAW.encode()).hex()
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    
    iteration = 0
    while True:
        execute_request(session, IPS[iteration % len(IPS)], payload_hex)
        iteration += 1
        time.sleep(1)

if __name__ == "__main__":
    main()