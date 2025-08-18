import os
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return {"msg": "Flask backend from GitHub 🚀"}
