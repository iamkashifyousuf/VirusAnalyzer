from flask import Flask, render_template, current_app, request, url_for, redirect
import requests
import json

app = Flask(__name__, template_folder='templates', static_folder='static')
url = "https://www.virustotal.com/api/v3/files"
url_get_report = "https://www.virustotal.com/api/v3/files/"

headers = {
        "accept": "application/json",
        "x-apikey": "" # VT API
    }

@app.route('/upload_file', methods=["POST"])
def upload_file():
    file_path = request.files['file'].filename
    files = { "file": (file_path, open(file_path, "rb"), "application/octet-stream")}
    response_upload = requests.post(url, files=files, headers=headers)
    link = json.loads(response_upload.text)['data']['links']['self']
    result = requests.get(link, headers=headers).json()
    sha1 = result['meta']['file_info']['sha1']
    sha256 = result['meta']['file_info']['sha256']
    md5 = result['meta']['file_info']['md5']
    file_size = result['meta']['file_info']['size']
    undetected = result['data']['attributes']['stats']['undetected']
    malicious = result['data']['attributes']['stats']['malicious']
    return redirect(url_for('index',sha1=sha1,sha256=sha256,md5=md5,file_size=file_size,undetected=undetected,malicious=malicious
))

@app.route('/')
def index():
    return render_template('index.html')


# Run the application
if __name__ == '__main__':
    app.run()
