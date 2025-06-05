from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def read_root():
    return jsonify({"message": "Reverse Engineering API is running!", "status": "healthy"})

@app.route("/upload/", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        return jsonify({
            "filename": file.filename,
            "message": "File received successfully.",
            "status": "success"
        })
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
