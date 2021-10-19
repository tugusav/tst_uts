import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = "70d6e62ed2f0016722974769fcfb7907a5609b79ee590114ec170f822ab2348c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

description = '''
Nama: Ida Bagus Raditya Avanindra Mahaputra\n
NIM	: 1821911\n
UTS II3160 Teknologi Sistem Terintegrasi\n
API Restaurant Menu adalah API yang dibuat untuk dapat mengakses, mengubah, dan menghapus 
data menu dari sebuah restoran.\n
User yang dapat digunakan untuk authentication:\n\n
*username*: asdf\n
*password*: asdf
'''

app = FastAPI(
	title="Restaurant Menu API",
	description=description,
)

users_db = {
	"admin":{
		"username": "asdf",
        "full_name": "Admin",
        "email": "admin@example.com",
        "hashed_password": "$2b$12$exoIL8YOqkt1unUhBuGkpeZ7QBeJ6O.4TFRLTcy.sQFJhG2b/kKoW",
        "disabled": False,
	},
    "tugusav": {
        "username": "tugusav",
        "full_name": "Tugus Avanindra",
        "email": "tugusav@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
}

with open("menu.json", "r") as read_file:
	data = json.load(read_file)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
	username: str
	email: Optional[str] = None
	full_name: Optional[str] = None
	disabled: Optional[str] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")


def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
	pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(user_db, username: str, password: str):
    user = get_user(user_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# Token
@app.post("/token", tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/users/me', response_model=User, tags=["User"])
async def get_current_user_data(current_user: User = Depends(get_current_active_user)):
	return current_user


## menu api

@app.get('/', tags=["Index"])
def root():
	description = {
		"Description": "API Restaurant Menu adalah API yang dibuat untuk dapat mengakses, mengubah, dan menghapus data menu dari sebuah restoran. Silakan mengakses /docs untuk melihat API selengkapnya",
		"Credit": "By Ida Bagus Raditya A.M. 18219117. Sistem dan Teknologi Informasi. Institut Teknologi Bandung"
		}
	return description['Description']

@app.get('/creator', tags=["API Credit"])
def who_am_i() -> dict:
	return {
			'Nama': 'Ida Bagus Raditya A.M',
			'NIM': 18219117, 
			'Kelas': "K1"
			}

@app.get('/menu', tags=["Menu"])
async def read_all_menu(token: str = Depends(oauth2_scheme)):
	return data

@app.get('/menu/{item_id}', tags=["Menu"])
async def read_a_menu(item_id: int, token: str = Depends(oauth2_scheme)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			return menu_item
	raise HTTPException(
		status_code=404, detail=f'Item not found'
)

@app.post('/menu', tags=["Menu"])
async def create_new_menu(name:str, token: str = Depends(oauth2_scheme)):
	id = 1
	if(len(data['menu']) > 0):
		id = data['menu'][len(data['menu']) - 1]['id'] + 1 # nyari data paling akhir, dan idnya, lalu tambahkan 1
	new_data = {'id':id, 'name':name}
	data['menu'].append(dict(new_data))
	read_file.close()
	with open("menu.json", "w") as write_file:
		json.dump(data,write_file, indent=4)
	write_file.close()

	return new_data
	raise HTTPException(
		status_code=500, detail=f'Internal server error')

@app.put('/menu/{item_id}', tags=["Menu"])
async def update_menu(item_id: int, name:str, token: str = Depends(oauth2_scheme)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			menu_item['name'] = name
		read_file.close()
		with open("menu.json", "w") as write_file:
			json.dump(data,write_file, indent=4)
		write_file.close()
	return {'message': 'Data updated'}
	raise HTTPException(
		status_code=404, detail=f'Item not found'
)

@app.delete('/menu/{item_id}', tags=["Menu"])
async def delete_menu(item_id: int, token: str = Depends(oauth2_scheme)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			data['menu'].remove(menu_item)
			read_file.close()
			with open("menu.json", "w") as write_file:
				json.dump(data,write_file, indent=4)
			write_file.close()
	return {'message': 'Data deleted'}
	raise HTTPException(
		status_code=404, detail=f'Item not found'
)