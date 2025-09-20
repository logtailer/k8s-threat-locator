import uuid
from flask import Flask, jsonify, request

app = Flask(__name__)

_items = []


@app.route("/health")
def health():
    return jsonify({"status": "ok", "items": len(_items)})


@app.route("/items")
def get_items():
    return jsonify(_items)


@app.route("/items/<item_id>")
def get_item(item_id):
    item = next((i for i in _items if i["id"] == item_id), None)
    if item is None:
        return jsonify({"error": "item not found"}), 404
    return jsonify(item)


@app.route("/items/<item_id>", methods=["DELETE"])
def delete_item(item_id):
    global _items
    before = len(_items)
    _items = [i for i in _items if i["id"] != item_id]
    if len(_items) == before:
        return jsonify({"error": "item not found"}), 404
    return "", 204


@app.route("/items", methods=["POST"])
def create_item():
    body = request.get_json(force=False, silent=True)
    if not body or "name" not in body:
        return jsonify({"error": "name is required"}), 400
    name = str(body["name"]).strip()
    if not name:
        return jsonify({"error": "name must not be blank"}), 400
    if len(name) > 200:
        return jsonify({"error": "name must not exceed 200 characters"}), 400
    item = {"id": str(uuid.uuid4()), "name": name}
    _items.append(item)
    return jsonify(item), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
