import os, random, string, requests
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
import time
import pymongo
import bcrypt
# from itsdangerous import URLSafeTimedSerializer as Serializer
# from itsdangerous import URLSafeTimedSerializer


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Enable CORS for all domains (for development purposes)
CORS(app)

# load gemini env variable
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

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
model = genai.GenerativeModel("gemini-1.5-flash", 
                              generation_config = generation_config,
                              system_instruction="""
                                You are an intelligent educational assistant designed to help students and users in their learning journey. Your primary goals are:
                                Summarization: Provide clear, concise, and informative summaries of content while preserving the key points.
                                Quiz Generation: Create engaging and challenging quizzes that test comprehension and reinforce learning, ensuring the difficulty matches the topic and context.
                                Flashcards: Generate flashcards with concise, question-answer pairs to support effective memorization and revision.
                                General Questions: Respond accurately and thoughtfully to a wide range of general knowledge and educational queries, providing explanations and actionable insights when necessary.""",
                            )
# model = genai.GenerativeModel(
#   model_name="gemini-1.5-pro",
#   generation_config=generation_config,
# )

# connect to mongodb
# Ensure the environment variable is being loaded correctly
mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    raise ValueError("MONGO_URI environment variable is not set.")

# Configure Flask-PyMongo
client = pymongo.MongoClient(mongo_uri)
db = client['Summarease']
Users = db['Users']
Sessions = db['Sessions']



# folder configs
UPLOAD_FOLDER = 'static/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
SECRET_KEY = 'your_secret_key'
app.config['SECRET_KEY'] = SECRET_KEY




# format of mongo db
users = [
    {
        "name" : "ujjawal",
        "email" : "u@u.u",
        "password" : "1234",
        "sessions" : [
            {
                "sessionId" :"83891",
                "title" : "Test chat 1"
            },
            {
                "sessionId" :"98467",
                "title" : "Test chat 2"
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
            {"topic":"Ask-ai", "id":1, "message": "what is ur name ?", "response": "i am ai", "files": ['abc.txt']},
            {"topic":"Ask-ai", "id":2, "message": "hello", "response": "hey there !", "files": []}
        ]
    },
    {
        "sessionId" : "98467", 
        "email" : "u@u.u",
        "title" : "hello world 2", 
        "message":[
            {"topic":"Ask-ai", "id":1, "message": "ok", "response": "please give context", "files": []},
            {"topic":"Ask-ai", "id":2, "message": "keep quite...", "response": "ok, i will !", "files": []}
        ]
    }
]

# Serializer instance
# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------------------Production related code

running = False
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({"status" : None, "text": None, "requestCount": None, "running": running})

# fetchedData = None
# requestCount = 0


# def getData():
#     global fetchedData, requestCount
#     response = requests.get("https://summarease-backend.onrender.com/api/test")
#     fetchedData = {"status" : response.status_code, "text": response.text, "requestCount":requestCount, "running": running}
#     return jsonify(fetchedData)

# @app.route('/api/Request', methods=['GET'])
# def KeepRenderInstanceRunning():
#     global requestCount, running
#     if not running:
#         try:
#             while True:
#                 requestCount+=1
#                 running = True
#                 getData()
#                 time.sleep(600)
#             # return jsonify(fetchedData)
#         except Exception as e:
#             running = False
#             print(f"error is {e}")
#             return jsonify({"status" : None, "text": None})
#     else:
#         return fetchedData
    
# =======ROUTES=========================================================================

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

# Signup Endpoint without mongo
# @app.route('/api/signup', methods=['POST'])
# def signup():
#     # print(request.headers)
#     data = request.json
#     for user in users:
#         if user['email'] == data['email']:
#             return jsonify({'message': 'Email already exists'}), 400
#     users.append({
#         'name': data['name'],
#         'email': data['email'],
#         'password': data['password'],
#         'sessions' : []
#     })
#     token = generate_token(data['email'])

#     print("all users : ")
#     for user in users:
#         print(user)
#     return jsonify({'message': 'User registered', 'token': token, 'user': {'name': data['name'], 'email': data['email']}}), 201


# Signup Endpoint with mongo
@app.route('/api/signup', methods=['POST'])
def signup():
    # print(mongo.db)
    data = request.json
    # users_collection = mongo.db.Users

    # Check if email already exists
    if Users.find_one({'email': data['email']}):
        return jsonify({'message': 'Email already exists'}), 400

    # Secure password
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    # Insert the new user into the Users collection
    user_data = {
        'name': data['name'],
        'email': data['email'],
        'password': hashed_password,
        'sessions': []
    }
    Users.insert_one(user_data)

    # Generate a token for the new user
    token = generate_token(data['email'])

    # all_users = users_collection.find()
    # print("All users:")
    # for user in all_users:
    #     print(user)

    return jsonify({'message': 'User registered', 'token': token, 'user': {'name': data['name'], 'email': data['email']}}), 201


# # Login Endpoint without mongo
# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.json
#     print(data)
#     for user in users:
#         print(user)
#         if user['email'] == data['email'] and user['password'] == data['password']:
#             token = generate_token(data['email'])
#             return jsonify({'message': 'Login successful', 'token': token, 'user': {'name': user['name'], 'email': user['email']}}) ,201
#     return jsonify({'message': 'Invalid email or password'}), 400


# Login Endpoint with mongo
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    # users_collection = mongo.db.Users

    # Search for the user in the database
    user = Users.find_one({'email': data['email']})

    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user["password"]):
        # Generate a token for the authenticated user
        token = generate_token(data['email'])
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {'name': user['name'], 'email': user['email']}
        }), 201

    # If no matching user is found
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

# # without mongo
# @app.route('/api/get-sessions', methods=['POST'])
# def get_sessions():
#     token = request.headers.get('Authorization')
#     email = verify_token_and_get_user(token)
#     if email == "Token has expired" or email == "Invalid token":
#         return  jsonify({'message': "Token has expired or invalid token"})
#     if not token or not email:
#         return jsonify({'message': 'Unauthorized'}), 401

#     # Fetch session from email
#     user = next((u for u in users if u['email'] == email), None)
#     if not user:
#         return jsonify({'error': 'User not found'}), 404
#     return jsonify({"sessions": user['sessions']}), 200



# with mongo
@app.route('/api/get-sessions', methods=['POST'])
def get_sessions():
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)

    # Token validation
    if email == "Token has expired" or email == "Invalid token":
        return jsonify({'message': "Token has expired or invalid token"}), 401
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401

    # Fetch user sessions from the database
    # users_collection = mongo.db.Users
    user = Users.find_one({'email': email})
    print(user)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    print(user['sessions'])
    return jsonify({"sessions": user.get('sessions', [])}), 200


# Endpoint to create a new session without mongo
# @app.route('/api/create-session', methods=['POST'])
# def create_session():
#     token = request.headers.get('Authorization')
#     print(token)
#     email = verify_token_and_get_user(token)
#     if email == "Token has expired" or email == "Invalid token":
#         return  jsonify({'message': "Token has expired or invalid token"})
#     if not token or not email:
#         return jsonify({'message': 'Unauthorized'}), 401

#     # Fetch session from email
#     print(email)
#     for user in users:
#         print(user)
#         if (user['email'] == email):
#             # session_id = uuid.uuid4().int >> 64  # Generate a unique session ID
#             session_id = str(uuid.uuid4())
#             user['sessions'].append({"sessionId": session_id, "title": 'new chat'})
#             sessions.append({
#                 "sessionId" : session_id, 
#                 "email" : email,
#                 "title" : "new chat", 
#                 "message":[]
#             })
#             print("\ncreated sessionId " + session_id)
#             return jsonify({"allSessions":user["sessions"],"newSession":{"sessionId": session_id, "title": 'new chat'}}), 201
        
#     return jsonify({'message': 'User not found'}), 404


# with mongo
@app.route('/api/create-session', methods=['POST'])
def create_session():
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)
    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401

    
    # Fetch the user from the database
    # users_collection = mongo.db.Users
    user = Users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Generate a unique session ID
    # session_id = uuid.uuid4().int >> 64  # Generate a unique session ID
    session_id = str(uuid.uuid4())

    # Add the new session to the user's sessions array
    new_session = {"sessionId": session_id, "title": 'new chat'}

    # Update the user's document in the database
    Users.update_one({'email': email}, {'$push': {'sessions': new_session}})

    Sessions.insert_one({
        "sessionId" : session_id, 
        "email" : email,
        "title" : "new chat", 
        "message":[]
    })

    user = Users.find_one({'email': email}) # to get the updated result where i will get the new added session also
    print(f"\ncreated sessionId: {session_id}")
    return jsonify({"allSessions":user["sessions"],"newSession": new_session}), 201


# # Endpoint to get messages for a session without mongo
# @app.route('/c/<session_id>', methods=['POST'])
# def get_messages(session_id):
#     token = request.headers.get('Authorization')
#     email = verify_token_and_get_user(token)
#     if email == "Token has expired" or email == "Invalid token":
#         return  jsonify({'message': "Token has expired or invalid token"})
#     if not token or not email:
#         return jsonify({'message': 'Unauthorized'}), 401
    
#     session = next((s for s in sessions if (s['sessionId'] == session_id and s["email"] == email)), None)

#     if not session:
#         return jsonify({'error': 'Session not found'}), 404
#     return jsonify(session), 200
#     # return jsonify({"messages": session['message']}), 200


# with mongo
@app.route('/c/<session_id>', methods=['POST'])
def get_messages(session_id):
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)
    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401
    
    # Fetch the session from the sessions collection
    # sessions_collection = mongo.db.sessions
    session = Sessions.find_one({'sessionId': session_id, 'email': email})

    if not session:
        return jsonify({'error': 'Session not found'}), 404
    

    # Return the session details
    session["_id"] = str(session["_id"])
    return jsonify(session), 200





# -----------------------------ai related code

def initialize_chat(session_id):
    # Fetch the session from the sessions collection
    # sessions_collection = mongo.db.sessions
    session = Sessions.find_one({"sessionId": session_id})

    if not session:
        print(f"No session found for session_id: {session_id}")
        return None

    # Prepare the chat history from the session's message field
    history = []
    for message in session.get("message", []):
        history.append({"role": "user", "parts": message["message"]})
        history.append({"role": "model", "parts": message["response"]})

    # Initialize the chat
    chat = model.start_chat(history=history)
    return chat

# -----------------------------tools
def  ai(prompt, chat):
    if not chat:
        print("Chat is not initialized.")
        return None
    
    response = chat.send_message(prompt)
    # response = model.generate_content(prompt)
    print("actual ai func end")
    return response.text


def Ask_ai(text, chatHistory):
    prompt = f"Answer the following: {text}"
    print("end ask ai")
    return ai(prompt, chatHistory)

# def Chapter_summarizer(context, prompt):
#     response = model.generate_content(f"Summarize the following text and highlight all the important points also, based on this message - \n {context} : \n{prompt}")
#     return response.text

def Summarize_text(text, chatHistory):
    # Set the system role for summarization
    prompt = f"Summarize the following text: {text}"
    # Call the Google Generative AI API
    print("end summarize")
    return ai(prompt, chatHistory)


def Generate_flashcards(text, chatHistory):
    prompt = f"""Generate at least 5 important JSONs with id, heading, and description having atleast 3 points.
    Example of a single JSON:
    {{
        "id": 1,
        "heading": "Recoil example",
        "description": [
            {{ "id": "1", "text": "point 1" }},
            {{ "id": "2", "text": "point 2" }},
            {{ "id": "3", "text": "point 3" }}
        ]
    }}
    based on the following prompt: {text}"""

    print("end flashcard")
    return ai(prompt, chatHistory)

def Quiz_generator(text, num_questions, chatHistory):
    prompt = f"""Generate at least 5 important JSONs with id, question, options.
    Example of a single JSON:
    {{
        "id": 1,
        "question": "Which planet is known as the Red Planet?",
        "options": [
            {{ "id": "a", "text": "Venus", "isCorrect": false }},
            {{ "id": "b", "text": "Mars", "isCorrect": true }},
            {{ "id": "c", "text": "Jupiter", "isCorrect": false }},
            {{ "id": "d", "text": "Saturn", "isCorrect": false }}
        ]
    }}
    based on the following text: {text}"""

    print("end quiz")
    return ai(prompt, chatHistory)





# @app.route('/new-session', methods=['GET'])
# def new_session():
#     if not verify_token(token):
#         return jsonify({'Error': "Unauthorized access"})
#     session_id = str(uuid.uuid4())  # Generate a unique session ID
#     return jsonify({'session_id': session_id})

def handle_user_prompt(topic, chatHistory, prompt, file_text=None, num_questions=None):
    # If no file, use provided prompt
    if file_text:
        print("file_text")
        extracted_text = file_text
    else:
        extracted_text = prompt

    # Call corresponding function based on the user's prompt
    response_text = None

    if topic == 'Summarize':
        print("summarize")
        response_text = Summarize_text(extracted_text, chatHistory)
    elif topic == 'Flashcard':
        print("flashcard")
        response_text = Generate_flashcards(extracted_text, chatHistory)
    elif topic == 'Quiz':
        print("quiz...")
        response_text = Quiz_generator(extracted_text, num_questions, chatHistory)
    else:
        print("ask-ai")
        response_text = Ask_ai(extracted_text, chatHistory)
    
    return response_text


# # without mongo
# @app.route('/api/get-response', methods=['POST'])
# def get_response():
#     token = request.headers.get('Authorization')
#     email = verify_token_and_get_user(token)

#     if email == "Token has expired" or email == "Invalid token":
#         return  jsonify({'message': "Token has expired or invalid token"})
#     if not token or not email:
#         return jsonify({'message': 'Unauthorized'}), 401
    

#     session_id = request.form.get('session_id')
#     prompt = request.form.get("message")
#     files = request.files.getlist('file')
#     topic = request.form.get('topic')

#     session = next((s for s in sessions if s['sessionId'] == session_id and s['email'] == email), None)

#     response = None
#     try:
#         if not session:
#             raise PermissionError("Unauthorized access. The session ID is not valid.")
        
#         print("ai function started")
#         file = None
#         content = None
#         if len(files) > 0:
#             content = upload_files_and_get_content(files)
#             first_file = list(content.keys())[0] 
#             file = content[first_file]

#         print(file)
#         chatHistory = initialize_chat(session_id)
#         answer = handle_user_prompt(topic, chatHistory, prompt, file)
#         # answer = handle_user_prompt(prompt, prompt, num_questions=10, file=file)
#         # answer = "fine"


#         unique_id = uuid.uuid4().int >> 64
#         if len(files) > 0:
#             response = {'topic':topic,'id':unique_id, 'message':prompt, 'response':answer, 'files':list(content.keys())}
#         else:
#             response = {'topic':topic,'id':unique_id, 'message':prompt, 'response':answer, 'files':[]}

#         session['message'].append(response)
#         print(session)

#         print("ai response ended")
#         return response

#     except Exception as e:
#         print(e)
#         unique_id = uuid.uuid4().int >> 64
#         return jsonify({'topic':topic,'id':unique_id, 'message':prompt, 'response':"some error occured", 'files':[]}), 500
    

# with mongo
@app.route('/api/get-response', methods=['POST'])
def get_response():
    token = request.headers.get('Authorization')
    email = verify_token_and_get_user(token)

    if email == "Token has expired" or email == "Invalid token":
        return  jsonify({'message': "Token has expired or invalid token"})
    if not token or not email:
        return jsonify({'message': 'Unauthorized'}), 401
    

    session_id = request.form.get('session_id')
    prompt = request.form.get("message")
    files = request.files.getlist('file')
    topic = request.form.get('topic')

    # Fetch the session from the sessions collection
    # sessions_collection = mongo.db.sessions
    session = Sessions.find_one({'sessionId': session_id, 'email': email})

    if not session:
        return jsonify({'message': 'Unauthorized access. The session ID is not valid.'}), 403

    response = None

    try:
        print("ai function started")
        file = None
        content = None
        if len(files) > 0:
            content = upload_files_and_get_content(files)
            first_file = list(content.keys())[0] 
            file = content[first_file]

        print(file)
        chatHistory = initialize_chat(session_id)
        answer = handle_user_prompt(topic, chatHistory, prompt, file)
        # answer = handle_user_prompt(prompt, prompt, num_questions=10, file=file)
        # answer = "fine"


        unique_id = str(uuid.uuid4().int >> 64)
        if len(files) > 0:
            response = {'topic':topic,'id':unique_id, 'message':prompt, 'response':answer, 'files':list(content.keys())}
        else:
            response = {'topic':topic,'id':unique_id, 'message':prompt, 'response':answer, 'files':[]}


        # Update the session in the database
        Sessions.update_one({'sessionId': session_id}, {'$push': {'message': response}})
        print(session)

        print("ai response ended")
        return response

    except Exception as e:
        print(e)
        unique_id = str(uuid.uuid4().int >> 64)
        return jsonify({'topic':topic,'id':unique_id, 'message':prompt, 'response':"some error occured", 'files':[]}), 500
    

# @app.route('/api/get-response', methods=['POST'])
# def get_response():
#     token = request.headers.get('Authorization')
#     email = verify_token_and_get_user(token)
#     if email == "Token has expired" or email == "Invalid token":
#         return  jsonify({'message': "Token has expired or invalid token"})
#     if not token or not email:
#         return jsonify({'message': 'Unauthorized'}), 401
    

#     session_id = request.form.get('session_id')
#     message = request.form.get("message")
#     files = request.files.getlist('file')

#     session = next((s for s in sessions if s['sessionId'] == session_id and s['email'] == email), None)

#     response = None
#     try:
#         print(files)
#         if len(files) > 0:
#             content = upload_files_and_get_content(files)
#             first_file = list(content.keys())[0]  
#             print(first_file + " : " + content[first_file]) 

#             answer = Chapter_summarizer(message, content[first_file])
#             # answer = jsonify({'text' :"fine"})
#             unique_id = uuid.uuid4().int >> 64
#             response = {'id':unique_id, 'message':message, 'response':answer.text, 'files':list(content.keys())}
#         else:       
#             answer = Ask_ai(message)
#             # answer = "fine outside"
#             unique_id = uuid.uuid4().int >> 64
#             response = {'id':unique_id, 'message':message, 'response':answer, 'files':[]}
        
#         session['message'].append(response)
#         print(session)
#         return jsonify(response)

#         # response = open("SampleAiResponse.txt",'r')
#         # response = response.read()

#     except Exception as e:
#         print(e)
#         unique_id = uuid.uuid4().int >> 64
#         return jsonify({'id':unique_id, 'message':message, 'response':"some error occured", 'files':[]}), 500





# Define supported file extensions
SUPPORTED_EXTENSIONS = {'txt', 'pdf', 'docx','csv'}

def allowed_file(filename):
    """Check if the uploaded file is of an allowed type."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in SUPPORTED_EXTENSIONS

class UnsupportedFileTypeError(Exception):
    """Custom exception for unsupported file types."""
    def __init__(self, message="Unsupported file type."):
        self.message = message
        super().__init__(self.message)



def upload_files_and_get_content(files):
    print("file function start")
    print(files)
    file_content = {}

    for file in files:
        if file.filename == '':
            continue
        print("here2")

        original_filename = secure_filename(file.filename)
        file_extension = os.path.splitext(original_filename)[1]  # Get the extension, e.g., ".pdf"

        if not allowed_file(original_filename):
            raise UnsupportedFileTypeError(f"Unsupported file type: {file_extension}") 

        # Generate a random encoded filename
        encoded_filename = ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + file_extension

        # Define the file's save path
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], encoded_filename)

        # Save the file to the static folder
        file.save(save_path)


        extracted_text = None
        if encoded_filename.endswith('.pdf'):
            extracted_text = extract_text_from_pdf(save_path)

        elif encoded_filename.endswith('.docx'):
            extracted_text = extract_text_from_docx(save_path)

        elif encoded_filename.endswith('.txt'):
            extracted_text = extract_text_from_txt(save_path)

        elif encoded_filename.endswith('.csv'):
            extracted_text = extract_text_from_csv(save_path)
                    
        file_content[encoded_filename] = extracted_text

    print("saved and ended")
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
    print("in docx function")
    doc = Document(filepath)
    text = ''
    for paragraph in doc.paragraphs:
        text += paragraph.text + '\n'
    return text

def extract_text_from_txt(filepath):
    """Extract text from a .txt file."""
    f = open(filepath, "r")
    return f.read()

def extract_text_from_csv(filepath):
    """Extract content from a .csv file."""
    import csv
    content = []
    with open(filepath, mode ='r') as file:
        csvFile = csv.reader(file)
        for lines in csvFile:
                content.append(lines)
    return content

if __name__ == '__main__':
    # app.run(host='127.0.0.1', port=5000, debug=True)
    app.run(host='192.168.1.6', port=5000, debug=True)
    # app.run(debug=True)

