from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlmodel import SQLModel, create_engine, Session, Field, select
import uuid
import os
from datetime import datetime
from typing import Optional
import jwt
from pydantic import BaseModel
from passlib.hash import pbkdf2_sha256
from dotenv import load_dotenv
import logging
from fastapi.security import OAuth2PasswordBearer

allowed_types= ['.txt', '.md','.pdf','.jpg','.jpeg','.png', '.gif']

app = FastAPI()

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

secret= os.getenv('SECRET').strip()
if not secret:
	logger.error('secret missing in env variables')

class File_from_user(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	unique_name: str = Field(index= True, nullable=False)
	real_name: str = Field(nullable= False)
	extension: str = Field(nullable=False)
	timestamp: str
	
class User(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	username: str = Field(unique=True, index=True, nullable=False)
	password: str = Field(nullable=False)
	user_id: Optional[str] = Field(nullable=False, default=None)


class User_from_req(BaseModel):
	username: str
	plain_pass: str


engine = create_engine('sqlite:///data.db')
SQLModel.metadata.create_all(engine)

def create_session():
	with Session(engine) as session:
		yield session

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

token = OAuth2PasswordBearer(tokenUrl = 'login')
def get_current_user(token: str = Depends(token), session:Session = Depends(create_session)):
	if not token:
		raise HTTPException(status_code=400, detail='token missing from auth header')
	try:
		payload = jwt.decode(token, secret, algorithms='HS256')	
	except Exception as e:
		raise HTTPException(status_code=400, detail='invalid token')
	username = payload['username']
	current_user = session.exec(select(User).where(User.username == username)).first()
	if not current_user:
		raise HTTPException(status_code=404, detail='cannot authenticate, user not found')
	return current_user
	

@app.post('/register')
async def register_user(user:User_from_req, session:Session = Depends(create_session)):
	username = user.username
	plain_pass = user.plain_pass

	if not username:
		raise HTTPException(status_code=400, detail="username missing")
	if len(username) >20:
		raise HTTPException(status_code=400, detail="username too long. keep under 50 char")
	if not plain_pass or len(plain_pass)<8:
		raise HTTPException(status_code=400, detail="password missing or invalid password. Password should be atleast 8 char long.")

	
	user_exists = session.exec(select(User).where(User.username == username)).first()
	if user_exists:
		raise HTTPException(status_code=400, detail="username already exists")

	
	hashed_pass = pbkdf2_sha256.hash(plain_pass)

	new_user = User(username = username, password = hashed_pass, user_id= str(uuid.uuid4()))

	try:
		session.add(new_user)
		session.commit()
		session.refresh(new_user)
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"error while adding user to database: {str(e)}")
		
	return {"message":"user registered successfully"}


@app.post('/login')
async def login_user(user: User_from_req, session:Session = Depends(create_session)):
	username = user.username
	plain_pass = user.plain_pass

	if not username:
		raise HTTPException(status_code=400, detail="username missing")
	if len(username) >20:
		raise HTTPException(status_code=400, detail="username too long. keep under 50 char")
	if not plain_pass or len(plain_pass)<8:
		raise HTTPException(status_code=400, detail="password missing or invalid password. Password should be atleast 8 char long.")

	try:
		user_in_db = session.exec(select(User).where(User.username == username)).first()
		if not user_in_db:
			raise HTTPException(status_code=404, detail='cannot log in, user not found in database')
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"error while fetching user from database: {str(e)}")

	ismatched = pbkdf2_sha256.verify(plain_pass, user_in_db.password)

	if not ismatched:
		raise HTTPException(status_code=403, detail="cannot log in user: username or password wrong")

	payload = {'username':username}
	token = jwt.encode(payload, secret, algorithm='HS256')

	return {'message':'user logged in successfully', 'token':token}



@app.post('/upload')
async def upload_files(file: UploadFile = File(...), session: Session = Depends(create_session)):

	file_extension = os.path.splitext(file.filename)[1]

	if file_extension not in allowed_types:
		raise HTTPException(status_code=400, detail='err: file type not allowed')
	
	unique_name = f'{uuid.uuid4()}{file_extension}'
	file_path = os.path.join(UPLOAD_DIR, unique_name)

	new_file = File_from_user(
		unique_name = unique_name,
		real_name = file.filename,
		extension = file_extension,
		timestamp = datetime.utcnow().isoformat()
	)

	try:
		session.add(new_file)
		session.commit()
		session.refresh(new_file)
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"err: error while uploading file metadata to database: {str(e)}")

	with open(file_path, 'wb') as buffer:
		buffer.write(await file.read())

	return {"filename":unique_name, "message":"please copy/store this unique filename, since you'll need to use this to retrieve your file"}

@app.get('/file/{filename}')
async def download_file(filename: str):
	
	base_dir = os.path.abspath(UPLOAD_DIR)
	file_path =os.path.abspath(os.path.join(UPLOAD_DIR, filename))

	if not file_path.startswith(base_dir):
		raise HTTPException(status_code=400, detail='invalid file path')
	
	if not os.path.exists(file_path):
		raise HTTPException(status_code=404, detail='file not found')
	
	return FileResponse(file_path, media_type=file.content_type, filename=filename)

@app.get('/protected')
def protected(user: User = Depends(get_current_user)):
	return {'user':user.username}
