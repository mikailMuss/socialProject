from datetime import datetime, timedelta
from typing import Optional
import psycopg2
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import html

import sqlite3

connection = sqlite3.connect('test.db', check_same_thread=False)

'''
Logging system actions:
0 - registration
1 - login
2 - post creation
3 - post like
4 - post unlike
5 - info service
'''


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "0fe1af4d6d8907d05985c3decf5c45f5eaff6687afa5a6e6afaf019304207302"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




class User(BaseModel):
	username: str
	password: str
	name: Optional[str] = ''
	surname: Optional[str] = ''

# class User(BaseModel):
# 	username: str


# class Post(BaseModel):
# 	author: str
# 	title: str
# 	text: str
# 	like: Optional[int] = 0

class Post(BaseModel):
	title: str
	text: str
	like: Optional[int] = 0

class LikeAnalytics(BaseModel):
	date_from: str
	date_to: str

# class UserInDb(User):
# 	hashed_password: str

app = FastAPI()


#====================================================
# Authorization
async def check_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
		status_code=401,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		# print('payload = ', payload)
		username: str = payload.get("sub")
		if username is None:
			# print('username = ', username)
			raise credentials_exception
	except JWTError as e:
		# print(str(e))
		# print('exception 117')
		raise credentials_exception
	sel_sql = """SELECT * FROM users WHERE username=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (username, ))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()
	if len(result) == 0:
		raise credentials_exception
	# if result[0][2]:
	# 	raise HTTPException(status_code=400, detail="Inactive user")
	return username
#====================================================
# Authentication
def authenticate(username: str, password: str):
	sel_sql = """SELECT * FROM users WHERE username=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (username,))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()
	print(result)
	if len(result) == 0:
		raise False
	if not pwd_context.verify(password, result[0][3]):
		print('passwords are not correct')
		return False
	print('passwords are correct')
	return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    # print('create_access_token')
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
def login_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
	print(form_data.username)
	print(form_data.password)
	user = authenticate(form_data.username, form_data.password)
	if not user:
		raise HTTPException(
            status_code=403,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
	ins_sql = """INSERT INTO logs("user", "action", "action_date") VALUES (?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql, (form_data.username, "1", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	access_token_expires = timedelta(hours=12)
	access_token = create_access_token(
		data={"sub": form_data.username}, expires_delta=access_token_expires
	)    
	return {"access_token": access_token, "token_type": "bearer"}
#====================================================
# User's API
@app.post('/user_registration/')
async def sign_up(user_reg: User):
	name_escaped = html.escape(user_reg.name)
	username_escaped = html.escape(user_reg.username)
	surname_escaped = html.escape(user_reg.surname)
	password_escaped = html.escape(user_reg.password)
	print(name_escaped)
	print(username_escaped)
	print(surname_escaped)
	print(password_escaped)
	# print(user.name)

	sel_sql = """SELECT * FROM users WHERE username=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (username_escaped,))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()
	print(result)
	if len(result) != 0:
		raise HTTPException(status_code=409, detail="Account with this username is already created")
	print('user')
	ins_sql = """INSERT INTO users("name", "surname", "username", "hashed_password") VALUES (?, ?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql, (name_escaped, surname_escaped, username_escaped, str(pwd_context.hash(password_escaped)), ))
	connection.commit()
	cursor.close()

	

	ins_sql2 = """INSERT INTO logs("user", "action", "action_date") VALUES (?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql2, (username_escaped, "0", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	ins_sql3 = """INSERT INTO logs("user", "action", "action_date") VALUES (?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql3, (username_escaped, "1", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	# return {'result': 'hello'}
	access_token_expires = timedelta(hours=12)
	access_token = create_access_token(
		data={"sub": username_escaped}, expires_delta=access_token_expires
	)    
	return {"access_token": access_token, "token_type": "bearer"}

@app.post('/user_info/')
async def user_information(current_username:str = Depends(check_user)):
	output_dict = {}

	sel_sql = """SELECT * FROM logs WHERE user=? AND action=? ORDER BY action_date ASC"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (current_username, "1", ))
	result = cursor.fetchall()
	cursor.close()

	output_dict['last_login_time'] = result[-1][4]

	sel_sql = """SELECT * FROM logs WHERE user=? ORDER BY action_date ASC"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (current_username, ))
	result = cursor.fetchall()
	cursor.close()	

	for i in range(len(result)-1, -1, -1):
		if result[i][2] == 0 or result[i][2] == 1 or result[i][2] == 5:
			continue
		if result[i][2] == 2:
			output_dict['last_service'] = "post creation"
		if result[i][2] == 3:
			output_dict['last_service'] = "post like"
		if result[i][2] == 4:
			output_dict['last_service'] = "post unlike"
		output_dict['last_service_time'] = result[i][4]
		break

	ins_sql = """INSERT INTO logs("user", "action", "action_date") VALUES (?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql, (current_username, "5", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	return {"actions": output_dict}
		


#====================================================
# Post's API
@app.post('/post_creation/')
async def post_creation(post: Post, current_username:str = Depends(check_user)):
	post_dict = post.dict()
	print(post)
	print(current_username)
	ins_sql = """INSERT INTO posts("author", "post_title", "post_content", "post_like", "creation_date") VALUES (?, ?, ?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql, (current_username, post.title, post.text, post.like,  datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	# cursor.close()

	sel_sql = """SELECT * FROM posts WHERE author=? AND post_title=? AND post_content=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (current_username, post.title, post.text, ))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()
	print(result[-1][0])
	print(type(result[-1][0]))


	ins_sql2 = """INSERT INTO logs("user", "action", "action_done_on_post", "action_date") VALUES (?, ?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql2, (current_username, "2", str(result[-1][0]), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	return {'post_id': result[-1][0]}



@app.post('/post_like/')
async def post_liking(post_id: int, current_username:str = Depends(check_user)):

	sel_sql = """SELECT * FROM posts WHERE post_id=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (str(post_id), ))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()

	print(result)

	upd_sql = """UPDATE posts SET post_like=? WHERE post_id=?"""
	cursor = connection.cursor()
	cursor.execute(upd_sql, (str(result[-1][4] + 1), str(post_id), ))
	connection.commit()
	cursor.close()



	ins_sql2 = """INSERT INTO logs("user", "action", "action_done_on_post", "action_date") VALUES (?, ?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql2, (current_username, "3", str(post_id), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	return {'post_id': post_id}



@app.post('/post_unlike/')
async def post_unliking(post_id: int, current_username:str = Depends(check_user)):

	sel_sql = """SELECT * FROM posts WHERE post_id=?"""
	cursor = connection.cursor()
	cursor.execute(sel_sql, (str(post_id), ))
	result = cursor.fetchall()
	# connection.commit()
	cursor.close()

	print(result)
	if result[-1][4] == 0:
		raise HTTPException(status_code=400, detail="There is no likes")

	upd_sql = """UPDATE posts SET post_like=? WHERE post_id=?"""
	cursor = connection.cursor()
	cursor.execute(upd_sql, (str(result[-1][4] - 1), str(post_id), ))
	connection.commit()
	cursor.close()



	ins_sql2 = """INSERT INTO logs("user", "action", "action_done_on_post", "action_date") VALUES (?, ?, ?, ?)"""
	cursor = connection.cursor()
	cursor.execute(ins_sql2, (current_username, "4", str(post_id), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ))
	connection.commit()
	cursor.close()

	return {'post_id': post_id}

#====================================================
# Like analytics
@app.post('/like_analytics/')
async def like_per_days(days: LikeAnalytics):
	date_from_datetime = datetime.strptime(days.date_from, '%Y-%m-%d')
	date_to_datetime = datetime.strptime(days.date_to, '%Y-%m-%d')
	if (date_to_datetime - date_from_datetime).days < 0:
		raise HTTPException(status_code=400, detail="Dates are not correct")
	output_dict = {}
	for i in range((date_to_datetime - date_from_datetime).days + 1):
		date = date_from_datetime + timedelta(days=i)
		sel_sql = """SELECT * FROM logs WHERE action_date LIKE ? AND action=?"""
		cursor = connection.cursor()
		cursor.execute(sel_sql, (date.strftime("%Y-%m-%d%"), "3", ))
		result = cursor.fetchall()
		cursor.close()
		print(date.strftime("%Y-%m-%d"))
		print(result)
		print(date.strftime("%Y-%m-%d"), ' - ', len(result))
		output_dict[date.strftime("%Y-%m-%d")] = len(result)

	return {'days': output_dict}