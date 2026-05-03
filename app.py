from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Сайт работает 🚀”

if __name__ == "__name__":
    app.run(host="0.0.0.0", port=5000) 