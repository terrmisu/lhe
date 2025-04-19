import sys
import json
import requests
import struct

API_KEY = "3d01f9c15e634dbb34370797c75f4ccc431ea5b1842027538b72c8267b85aa82"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"

def scan_file(file_path):
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            headers = {"x-apikey": API_KEY}

            print(f"🔍 Uploading {file_path} to VirusTotal...")
            response = requests.post(VIRUSTOTAL_URL, headers=headers, files=files)

            if response.status_code == 200:
                result = response.json()
                return {"status": "success", "analysis_id": result["data"]["id"]}
            else:
                return {"status": "error", "message": response.text}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def read_message():
    raw_length = sys.stdin.read(4)
    if not raw_length:
        sys.exit(0)
    
    message_length = struct.unpack("I", raw_length.encode("utf-8"))[0]
    message = sys.stdin.read(message_length)
    return json.loads(message)

def send_message(message):
    encoded_message = json.dumps(message).encode("utf-8")
    sys.stdout.write(struct.pack("I", len(encoded_message)))
    sys.stdout.write(encoded_message)
    sys.stdout.flush()

if __name__ == "__main__":
    data = read_message()
    
    file_path = data.get("path")
    if file_path:
        result = scan_file(file_path)
        send_message(result)
    else:
        send_message({"status": "error", "message": "No file path received"})
