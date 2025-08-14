from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlmodel import SQLModel, create_engine, Session, Field
import uuid
import os
from datetime import datetime
from typing import Optional

allowed_types= ['.txt', '.md','.pdf','.jpg','.jpeg','.png', '.gif']

app = FastAPI()

class File_from_user(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	unique_name: str = Field(index= True, nullable=False)
	real_name: str = Field(nullable= False)
	extension: str = Field(nullable=False)
	timestamp: str
	

engine = create_engine('sqlite:///data.db')
SQLModel.metadata.create_all(engine)

def create_session():
	with Session(engine) as session:
		yield session

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
		raise HTTPException(status_code=500, detail="err: error while uploading file metadata to database")

	with open(file_path, 'wb') as buffer:
		buffer.write(await file.read())

	return {"filename":unique_name}

@app.get('/file/{filename}')
async def download_file(filename: str):
	
	base_dir = os.path.abspath(UPLOAD_DIR)
	file_path =os.path.abspath(os.path.join(UPLOAD_DIR, filename))

	if not file_path.startswith(base_dir):
		raise HTTPException(status_code=400, detail='invalid file path')
	
	if not os.path.exists(file_path):
		raise HTTPException(status_code=404, detail='file not found')
	
	return FileResponse(file_path, media_type=file.content_type, filename=filename)


