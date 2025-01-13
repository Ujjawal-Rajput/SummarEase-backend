import os
import requests
from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
from flask_cors import CORS  # Import CORS

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Enable CORS for all domains (for development purposes)
CORS(app)


# MongoDB URI
MONGO_URI = os.getenv('MONGO_URI')
client = MongoClient(MONGO_URI)
db = client['gemini_database']
collection = db['messages']

# Gemini API
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_API_URL = os.getenv('GEMINI_API_URL')

@app.route('/test', methods=['GET'])
def test():
    return "hello from python"

@app.route('/get-response', methods=['POST'])
def get_response():
    try:
        print(request.get_json())
        return request.get_json()
    except:
        print("error")

@app.route('/response', methods=['POST'])
def response():
    """
    Endpoint to send the user's message and files to Gemini API
    and return the response from Gemini API.
    """
    try:
        # Retrieve message and file from the request
        message = request.form.get('message')
        file = request.files.get('file')
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        
        # Prepare the data to send to the Gemini API
        headers = {
            'Authorization': f'Bearer {GEMINI_API_KEY}',
        }
        
        # Prepare the file for the API request (if any)
        files = {'file': (file.filename, file.stream)} if file else None
        data = {'message': message}
        
        # Send the request to Gemini API
        response = requests.post(GEMINI_API_URL, headers=headers, data=data, files=files)
        
        # Store the message in MongoDB (optional)
        collection.insert_one({'sessionId':1234,'message': {message}})

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({'error': 'Failed to get a response from Gemini API'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
