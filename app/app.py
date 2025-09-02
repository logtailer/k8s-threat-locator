from flask import Flask, jsonify, request

app = Flask(__name__)

_items = []


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/items")
def get_items():
    return jsonify(_items)


@app.route("/items", methods=["POST"])
def create_item():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "")
    item = {"id": len(_items) + 1, "name": name}
    _items.append(item)
    return jsonify(item), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
