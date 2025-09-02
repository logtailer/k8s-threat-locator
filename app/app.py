from flask import Flask, jsonify

app = Flask(__name__)

_items = []


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/items")
def get_items():
    return jsonify(_items)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
