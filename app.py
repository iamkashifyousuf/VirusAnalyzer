from flask import Flask, render_template, request
import requests
import json


app = Flask(__name__, template_folder='templates', static_folder='static')
url = "https://www.virustotal.com/api/v3/files"
headers = {
        "accept": "application/json",
        "x-apikey": "c035c79d060802fd45ec0fb4c9b8a81692ce70fba881e657611a4b87beec9c29"
    }
def upload_file(file):
    files = { "file": (file, open(file, "rb"), "application/octet-stream") }
    response_upload = requests.post(url, files=files, headers=headers)
    return response_upload

def scan_result(response_upload):
    link = json.loads(response_upload.text)['data']['links']['self']
    response = requests.get(link, headers=headers)
    get_result_to_var(response)

def get_result_to_var(response):
    python_obj = json.loads(response.text)
    sha1 = python_obj['meta']['file_info']['sha1']
    sha256 = python_obj['meta']['file_info']['sha256']
    md5 = python_obj['meta']['file_info']['md5']
    size = python_obj['meta']['file_info']['size']
    undetected = python_obj['data']['attributes']['stats']['undetected']
    malicious = python_obj['data']['attributes']['stats']['malicious']
    index(sha1, sha256, md5, size, undetected, malicious)
    print(sha1, sha256, md5, size, undetected, malicious)


#print(response.text)
@app.route('/')
def index(Sha1,Sha256,Md5,Size,Undetected,Malicious):
    return render_template('index.html',Sha1=Sha1,Sha256=Sha256,Md5=Md5,Size=Size,Undetected=Undetected,Malicious=Malicious)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    upload_file(file)

def get_size(file):
    return file.size


# Run the application
if __name__ == '__main__':
    app.run()
