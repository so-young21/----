import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import datetime
import bcrypt
import json
# Firebase 서비스 계정 키 파일 경로
key_dict = json.loads(st.secrets["textkey"])
cred = credentials.Certificate(key_dict)

# Firebase 인증 및 앱 초기화
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
    print("firebase 앱이 초기화 되었습니다.")
else:
    print("Firebase 앱이 이미 초기화 되었습니다.")

# Firestore 클라이언트 생성
db = firestore.client()

# 비밀번호 해싱 함수
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# 비밀번호 확인 함수
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# 회원가입 함수
def sign_up_user(email, password, user_data):
    try:
        hashed_password = hash_password(password)
        user_data['password'] = hashed_password
        user_data['created_at'] = datetime.datetime.now()
        db.collection('users').document(email).set(user_data)
        st.success('Successfully created new user')
        return email
    except Exception as e:
        st.error(f'Error creating new user: {e}')
        return None

# 로그인 함수
def sign_in_user(email, password):
    try:
        user_ref = db.collection('users').document(email)
        user = user_ref.get()
        if user.exists:
            user_data = user.to_dict()
            if check_password(password, user_data['password']):
                st.success('Successfully signed in')
                return email
            else:
                st.error('Incorrect password')
        else:
            st.error('User does not exist')
        return None
    except Exception as e:
        st.error(f'Error signing in: {e}')
        return None

# Streamlit 앱 인터페이스
st.title('Firestore Auth Login Page')

choice = st.sidebar.selectbox('Login/Signup', ['Login', 'Signup'])

if choice == 'Signup':
    st.subheader('Create New Account')
    email = st.text_input('Email')
    password = st.text_input('Password', type='password')
    name = st.text_input('Name')
    age = st.number_input('Age', min_value=0)

    if st.button('Signup'):
        user_data = {
            'name': name,
            'age': age,
            'email': email
        }
        sign_up_user(email, password, user_data)

elif choice == 'Login':
    st.subheader('Login to Your Account')
    email = st.text_input('Email')
    password = st.text_input('Password', type='password')

    if st.button('Login'):
        user_id = sign_in_user(email, password)
        if user_id:
            st.success(f'Welcome back, {email}!')

# Streamlit 실행 명령어
# streamlit run your_script_name.py
