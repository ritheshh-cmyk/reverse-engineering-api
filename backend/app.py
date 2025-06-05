from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import tempfile
import logging
import pefile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        # Save uploaded file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file.read())
            tmp_path = tmp.name
            logger.info(f"File saved temporarily at: {tmp_path}")

        analysis_results = {}

        # Run binwalk analysis
        binwalk_result = subprocess.run(
            ["binwalk", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        analysis_results['binwalk'] = binwalk_result.stdout if binwalk_result.returncode == 0 else f"Error: {binwalk_result.stderr}"

        # Try PE file analysis if it's a Windows executable
        try:
            pe = pefile.PE(tmp_path)
            analysis_results['pe_info'] = {
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'sections': [section.Name.decode().rstrip('\x00') for section in pe.sections]
            }
        except:
            pass

        # Clean up temp file
        os.unlink(tmp_path)
        logger.info("Temporary file cleaned up")

        return jsonify({
            "filename": file.filename,
            "message": "File analyzed successfully",
            "analysis": analysis_results
        })
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
