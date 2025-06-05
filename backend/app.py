from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import tempfile

app = Flask(__name__)
CORS(app)  # Allow all origins for dev

@app.route("/", methods=["GET"])
def read_root():
    return jsonify({"message": "Reverse Engineering API is running!"})

@app.route("/upload/", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        # Save uploaded file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file.read())
            tmp_path = tmp.name

        # Example: Run binwalk on the file
        result = subprocess.run(
            ["binwalk", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Clean up temp file
        os.unlink(tmp_path)

        if result.returncode != 0:
            output = f"Error running binwalk:\n{result.stderr}"
        else:
            output = result.stdout

        return jsonify({
            "filename": file.filename,
            "message": "File received and analyzed.",
            "output": output
        })
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
