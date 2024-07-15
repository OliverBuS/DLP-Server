import os
from datetime import datetime

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = "uploads"  # Choose a suitable folder
ALLOWED_EXTENSIONS = {"txt", "pdf", "docx"}  # Limit allowed types
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload size


# Helper Functions
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_unique_filename(filename):
    ext = filename.rsplit(".", 1)[1].lower()  # Extract the file extension
    timestamp = datetime.now().strftime("%Y_%m_%d-%H_%M_%S")  # YYYYMMDD-HHMMSS
    return f"{timestamp}.{ext}"


# Routes
@app.route("/", methods=["POST"])
def handle_request():
    # Clear terminal before processing each request
    os.system("cls" if os.name == "nt" else "clear")

    headers = request.headers
    print("Received headers:")
    print(headers)

    if "file" in request.files:
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        if file and allowed_file(file.filename):
            filename = generate_unique_filename(secure_filename(file.filename))
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            # Process the uploaded file as needed
            with open(filepath, "rb") as f:
                content = f.read()
            print("Received file content:")
            print(content[:20])
            return (
                jsonify({"message": "File uploaded successfully", "filename": filename}),
                201,
            )

        return jsonify({"error": "File type not allowed"}), 400
    else:
        content = request.data.decode("utf-8")
        if content:
            # Process the received text as needed
            print("Received text content:")
            print(content)
            return (
                jsonify({"message": "Text received successfully", "content": content}),
                200,
            )
        else:
            return jsonify({"error": "No text content received"}), 400


# Error Handling (examples)
@app.errorhandler(413)  # Request Entity Too Large
def request_entity_too_large(error):
    return jsonify({"error": "File exceeds size limit"}), 413


# ... other error handlers (404, 500, etc.)

if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)  # Create if not exists
    app.run(host="0.0.0.0", port=5000)
