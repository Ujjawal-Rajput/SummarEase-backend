import os
import requests
from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
from flask_cors import CORS  # Import CORS
import google.generativeai as genai

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Enable CORS for all domains (for development purposes)
CORS(app)

# load env variables
genai.configure(api_key=os.environ["GEMINI_API_KEY"])
MONGO_URI = os.getenv('MONGO_URI')

# Create the model
generation_config = {
  "temperature": 1,
  "top_p": 0.95,
  "top_k": 40,
  "max_output_tokens": 8192,
  "response_mime_type": "text/plain",
}
model = genai.GenerativeModel(
  model_name="gemini-1.5-pro",
  generation_config=generation_config,
)

# connect to mongodb
# client = MongoClient(MONGO_URI)
# db = client['gemini_database']
# collection = db['messages']



@app.route('/test', methods=['GET'])
def test():
    return "Hello from SummarEase"



@app.route('/get-response', methods=['POST'])
def get_response():
    try:
        print(request.get_json())
        req = request.get_json()

        chat_session = model.start_chat()
        response = chat_session.send_message(req["message"])
        req["response"] = response.text
        # print(response.text)
        # OR
        # response = open("SampleAiResponse.txt",'r')
        # response = response.read()
        # req["response"] = response
       
        return jsonify(req)
    except:
        return 
        print("error")



if __name__ == '__main__':
    app.run(debug=True)

