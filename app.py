from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h1>Сайт работает 🚀</h1>
    <p>Добавить в закладки: надо потом сайты сделать :)</p>
    <p>P.S. Основан 2:12 04.05.2026</p>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
