import os
import requests
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
from flask_cors import CORS 
import google.generativeai as genai
import PyPDF2
from docx import Document
import uuid
import jwt
import datetime
# from itsdangerous import URLSafeTimedSerializer as Serializer
# from itsdangerous import URLSafeTimedSerializer


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Enable CORS for all domains (for development purposes)
CORS(app)

# load env variables
genai.configure(api_key=os.environ["GEMINI_API_KEY"])
MONGO_URI = os.getenv('MONGO_URI')

# Create the model
generation_config = genai.GenerationConfig(
    max_output_tokens=1000,
    temperature=0.1,
)
# generation_config = {
#   "temperature": 1,
#   "top_p": 0.95,
#   "top_k": 40,
#   "max_output_tokens": 8192,
#   "response_mime_type": "text/plain",
# }
model = genai.GenerativeModel("gemini-1.5-flash", generation_config = generation_config)
# model = genai.GenerativeModel(
#   model_name="gemini-1.5-pro",
#   generation_config=generation_config,
# )

# connect to mongodb
# client = MongoClient(MONGO_URI)
# db = client['gemini_database']
# collection = db['messages']

UPLOAD_FOLDER = 'static/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
SECRET_KEY = 'your_secret_key'
app.config['SECRET_KEY'] = SECRET_KEY






users = [
    {
        "name" : "ujjawal",
        "email" : "u@u.u",
        "password" : "1234",
        "sessions" : [
            {
                "sessionId" :"83891",
                "title" : "hello world"
            },
            {
                "sessionId" :"98467",
                "title" : "hello world 2"
            }
        ]
    }
]

sessions = [
    {
        "sessionId" : "83891",
        "email" : "u@u.u",
        "title" : "hello world", 
        "message":[
            {"id":1, "message": "what is ur name ?", "response": "i am ai", "files": ['yes']},
            {"id":2, "message": "hello", "response": "hey there !", "files": []}
        ]
    },
    {
        "sessionId" : "98467", 
        "email" : "u@u.u",
        "title" : "hello world 2", 
        "message":[
            {"id":1, "message": "ok", "response": "please give context", "files": []},
            {"id":2, "message": "keep quite...", "response": "ok, i will !", "files": []}
        ]
    }
]

# Serializer instance
# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
# =======ROUTES=========================================================================


@app.route('/api/test', methods=['GET'])
def test():
    return "Hello from SummarEase"

# --------------AUTH------------------------
def generate_token(email):
    expiration_time = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)  # Token expiration time (1 hour)
    payload = {
        "email": email,
        "exp": expiration_time  # Expiration time field
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")  # Encode the payload with the secret key
    return token

def verify_token_and_get_user(token):
    try:
        # Decode the token using the SECRET_KEY
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded_payload["email"]  # Return the email from the decoded payload
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"
  
    
# Generate a token
# def generate_token(email):
#     token = serializer.dumps(email, salt='email-confirm-salt')
#     print(f"Generated token: {token}")
#     return token

# # Verify a token
# def verify_token_and_get_user(token, expiration=3600):
#     try:
#         print(f"Verifying token: {token}")
#         email = serializer.loads(token, salt='email-confirm-salt', max_age=expiration)
#         return email
#     except Exception as e:
#         print(e)
#         return None
# ImFAYS5hIg.Z4aGZQ.cyZwSxTe-p-lJTDrhA1FJlaZDzk
# ImFAYS5hIg.Z4aGZQ.cyZwSxTe-p-lJTDrhA1FJlaZDzk

# Signup Endpoint
@app.route('/api/signup', methods=['POST'])
def signup():
    # print(request.headers)
    data = request.json
    for user in users:
        if user['email'] == data['email']:
            import time
            time.sleep(3)
            return jsonify({'message': 'Email already exists'}), 400
    users.append({
        'name': data['name'],
        'email': data['email'],
        'password': data['password'],
        'sessions' : []
    })
    token = generate_token(data['email'])

    print("all users : ")
    for user in users:
        print(user)
    return jsonify({'message': 'User registered', 'token': token, 'user': {'name': data['name'], 'email': data['email']}}), 201

# Login Endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    print(data)
    for user in users:
        print(user)
        if user['email'] == data['email'] and user['password'] == data['password']:
            token = generate_token(data['email'])
            return jsonify({'message': 'Login successful', 'token': token, 'user': {'name': user['name'], 'email': user['email']}}) ,201
    import time
    time.sleep(3)
    return jsonify({'message': 'Invalid email or password'}), 400


# Protected Endpoint to Verify Token
# @app.route('/verify-token', methods=['POST'])
# def verify():
#     token = request.json.get('token')
#     email = verify_token_and_get_user(token)
#     if email:
#         return jsonify({'message': 'Token is valid', 'email': email})
#     return jsonify({'message': 'Invalid or expired token'}), 401

# @app.route('/', methods=['POST'])
# def verify():
#     token = request.json.get('token')
#     email = verify_token_and_get_user(token)
#     if email:
#         return jsonify({'message': 'Token is valid', 'email': email})
#     return jsonify({'message': 'Invalid or expired token'}), 401


@app.route('/api/get-sessions', methods=['POST'])
def get_sessions():
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)
    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401

    # Fetch session from email
    user = next((u for u in users if u['email'] == email), None)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({"sessions": user['sessions']}), 200


# Endpoint to create a new session
@app.route('/api/create-session', methods=['POST'])
def create_session():
    token = request.headers.get('Authorization')
    print(token)
    email = verify_token_and_get_user(token)
    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401

    # Fetch session from email
    print(email)
    for user in users:
        print(user)
        if (user['email'] == email):
            # session_id = uuid.uuid4().int >> 64  # Generate a unique session ID
            session_id = str(uuid.uuid4())
            user['sessions'].append({"sessionId": session_id, "title": 'new chat'})
            sessions.append({
                "sessionId" : session_id, 
                "email" : email,
                "title" : "new chat", 
                "message":[]
            })
            print("\ncreated sessionId " + session_id)
            return jsonify({"allSessions":user["sessions"],"newSession":{"sessionId": session_id, "title": 'new chat'}}), 201
        
    return jsonify({'message': 'User not found'}), 404



# Endpoint to get messages for a session
@app.route('/c/<session_id>', methods=['POST'])
def get_messages(session_id):
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)
    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401
    
    session = next((s for s in sessions if (s['sessionId'] == session_id and s["email"] == email)), None)

    if not session:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(session), 200
    # return jsonify({"messages": session['message']}), 200














# -----------------------------



def Ask_me_anything(prompt):
    chat_session = model.start_chat()
    response = chat_session.send_message(prompt)
    return response.text

def Chapter_summarizer(context, prompt):
    response = model.generate_content(f"Summarize the following content and highlight all the important points, based on this message - \n {context} : \n{prompt}")
    return response.text

def Generate_flashcards(prompt, file):
    pass

def Quiz_generator(prompt, file):
    pass



@app.route('/new-session', methods=['GET'])
def new_session():
    if not verify_token(token):
        return jsonify({'Error': "Unauthorized access"})
    session_id = str(uuid.uuid4())  # Generate a unique session ID
    return jsonify({'session_id': session_id})



@app.route('/api/get-response', methods=['POST'])
def get_response():
    message = request.form.get("message")
    files = request.files.getlist('file')
    try:
        print(files)
        if len(files) > 0:
            content = upload_files_and_get_content(files)
            first_file = list(content.keys())[0]  
            print(first_file + " : " + content[first_file]) 

            answer = Chapter_summarizer(message, content[first_file])
            response = {'id':1234, 'message':message, 'response':answer.text, 'files':list(content.keys())}
            return jsonify(response)
        
        
        answer = Ask_me_anything(message)
        response = {'id':1234, 'message':message, 'response':answer, 'files':[]}
        return jsonify(response)

        # response = open("SampleAiResponse.txt",'r')
        # response = response.read()

    except Exception as e:
        print(e)
        return jsonify({'id':1234, 'message':message, 'response':"some error occured", 'files':[]}), 500

def upload_files_and_get_content(files):
    print("here")
    print(files)
    file_content = {}

    for file in files:
        if file.filename == '':
            continue
        print("here2")
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        extracted_text = None
        if filename.endswith('.pdf'):
            extracted_text = extract_text_from_pdf(filepath)
        elif filename.endswith('.docx'):
            extracted_text = extract_text_from_docx(filepath)
        
        file_content[filename] = extracted_text

    return file_content
    # return jsonify({'message': 'Files uploaded successfully', 'files': saved_files}), 200

def extract_text_from_pdf(filepath):
    """Extract text from a PDF file."""
    with open(filepath, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ''
        for page in reader.pages:
            text += page.extract_text() + '\n'
    return text

def extract_text_from_docx(filepath):
    """Extract text from a DOCX file."""
    doc = Document(filepath)
    text = ''
    for paragraph in doc.paragraphs:
        text += paragraph.text + '\n'
    return text


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
    # app.run(debug=True)

