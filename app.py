from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Сайт работает 🚀\nДобавить в закладки: надо потом сайти сделать :)\nP.S. Основан 2:12 04.05.2026"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
