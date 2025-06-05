from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import tempfile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow all origins for dev

@app.route("/", methods=["GET"])
def read_root():
    try:
        return jsonify({"message": "Reverse Engineering API is running!", "status": "healthy"})
    except Exception as e:
        logger.error(f"Error in root endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

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
            logger.info(f"File saved temporarily at: {tmp_path}")

        # Example: Run binwalk on the file
        result = subprocess.run(
            ["binwalk", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Clean up temp file
        os.unlink(tmp_path)
        logger.info("Temporary file cleaned up")

        if result.returncode != 0:
            logger.error(f"Binwalk error: {result.stderr}")
            output = f"Error running binwalk:\n{result.stderr}"
        else:
            output = result.stdout
            logger.info("Binwalk analysis completed successfully")

        return jsonify({
            "filename": file.filename,
            "message": "File received and analyzed.",
            "output": output
        })
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
