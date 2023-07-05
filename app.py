import requests
from flask import Flask, request, redirect, url_for, render_template, jsonify
import vt

# Create a Flask application
app = Flask(__name__, template_folder='templates', static_folder='static')

# client = vt.Client("af11c1b89d0dd596ac59e6a138ee33dfe719e87fbf0394f87863a49d7aad0465")

# file = client.get_object("img.png")

url = "https://www.virustotal.com/api/v3/files"
files = {"file": ("img.png", open("img.png", "rb"), "image/png")}
headers = {
    "accept": "application/json",
    "x-apikey": "af11c1b89d0dd596ac59e6a138ee33dfe719e87fbf0394f87863a49d7aad0465",
}
response = requests.post(url, files=files, headers=headers)
print(response.text)
print(jsonify(response))


@app.route('/')
def index():
    return render_template('index.html')


def get_size(file):
    return file.size


# Run the application
if __name__ == '__main__':
    app.run()
