import re
import requests
import streamlit as st
from database_delo import SessionLocal, Uporabniki
from passlib.context import CryptContext
import pandas as pd
import logging
import shemas
import time
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         SETUP
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Configure the logging module
logging.basicConfig(
#   filename='example.log',
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


BACKEND_URL = "http://backend:8000"
SECRET_KEY = "b3f6e6b9b7f3d2c7a6f9d4e7c8b5a2f1"

# check if any token was used in last 30 minutes (database session)

# Set the page configuration
st.set_page_config(
    page_title="Dust Strike Force",
    layout="wide",
    page_icon="🧹",
    initial_sidebar_state="expanded",
)


# get opravila from database opravila
def get_opravila():
    url = BACKEND_URL+"/opravila/"
    response = requests.get(url)
    rsp = response.json()
    logging.info(f'Successfully loaded the table from the database.')
    return rsp


# get cistila from database cistila
def get_cistila():
    url = BACKEND_URL+"/cistila/"
    response = requests.get(url)
    rsp = response.json()
    logging.info(f'Successfully loaded the table from the database.')
    return rsp


def decode_jwt_token(token):
    try:
        token = token.strip() 
        if isinstance(token, str):  # Check if token is a string
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return decoded_token
        else:
            st.error("Invalid token type. Please provide a valid JWT token.")
    except jwt.ExpiredSignatureError as e:
        st.error(f"Token has expired. Error: {e}")
    except jwt.JWTError as e:
        st.error(f"Invalid token. Error: {e}")
    except jwt.InvalidTokenError as e:
        st.error(f"Signature verification failed. Error: {e}")
    return None


def get_active_token():
    url = BACKEND_URL + "/session/"
    active_token = requests.get(url).json()
    return (active_token.get("token"), active_token.get("user"))


def clear_session_db():
    requests.post(BACKEND_URL + "/clear_session/")
    return
    
def add_to_session_db(token, user, expiration_time):
    url = BACKEND_URL + "/session/"
    requests.post(url,
                  json={"token": token, "user": user, "expiration_time": expiration_time},
                  headers={'Content-Type': 'application/json'})
    return


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         MAIN
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def add_initial_admin_user():
    admin_email = "admin@gmail.com"
    admin_username = "Admin"
    admin_password = "seminarDelamo!?Letos3"
    # Check if the user already exists
    url = BACKEND_URL + f"/users/{admin_username}"
    response = requests.get(url)
    if response.status_code == 404:
        # If the user doesn't exist, add the initial admin user
        url = BACKEND_URL + "/sign-up"
        response = requests.post(
            url, json={"email": admin_email, "username": admin_username, "password": admin_password, "role": "admin"}
        )
        if response.status_code == 201:
            logging.info("Initial admin user added successfully.")
        else:
            logging.error("Failed to add initial admin user.")
    else:
        logging.info("Admin user already exists.")


def is_token_valid(token):
    try:
        decoded_token = decode_jwt_token(token)
        if decoded_token:
            # Check if the token has not expired
            expiration_time = decoded_token.get("exp", 0)
            current_time = datetime.utcnow()
            return current_time < expiration_time
    except:
        pass
    return False


def main():
    st.sidebar.image("logo.png", width=200)
    st.sidebar.title("Dust Strike Force")
    add_initial_admin_user()
    
    if 'is_logged_in' not in st.session_state:
        # check if active token (from last session)
        token, username = get_active_token()

        if token is not None and username is not None:
            # if active, set the session state
            st.session_state['is_logged_in'] = True
            st.session_state['token'] = token
            st.session_state['current_user'] = username

        else:
            st.session_state['is_logged_in'] = False
            st.session_state['token'] = None
            st.session_state['current_user'] = None

    if 'token' not in st.session_state:
        st.session_state['token'] = None

    # If the user is not logged in, show the login page
    if not st.session_state.is_logged_in:
        st.header("Dusk Strike Force")
        selected_option = st.sidebar.radio(
            "Select Option", ["Login", "Sign Up"], key="login_options"
            )
        if selected_option == "Login":
            login()
        elif selected_option == "Sign Up":
            sign_up()  
                
    else:
        # Get current user role
        decoded_token = decode_jwt_token(st.session_state.token)
        user_role = decoded_token.get("role", "")
        if user_role == "admin":
            selected_option = st.sidebar.radio(
                "Select Option", ["Chores", "Cleaning agents", "Manage Users", "Manage Chores", "Manage Cleaning agents", "Log Out"], key="other_options"
            )
        else:
            selected_option = st.sidebar.radio(
                "Select Option", ["Chores", "Cleaning agents","API documentation" ,"Log Out"], key="other_options"
            )
        st.title(selected_option)
        # Display the appropriate content based on the selected option
        if selected_option == "Chores":
            opravila(st.session_state.token)
        elif selected_option == "Cleaning agents":
            sredstva(st.session_state.token)
        elif selected_option == "API documentation":
            display_api()
        elif selected_option == "Manage Users":
            manage_users()
        elif selected_option == "Manage Chores":
            manage_opravila()
        elif selected_option == "Manage Cleaning agents":
            manage_sredstva()
        elif selected_option == "Log Out":
            log_out()
                
                
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         LOGIN
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def get_user_info(token):
    # Get user information from the backend using the token
    try:
        headers = {"Authorization": f"Bearer {token}"}
        url = BACKEND_URL + "/get-user-info"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        st.error(f"Failed to get user information. Error: {e}")
        return None


def set_current_user(user):
    st.session_state['current_user'] = user


def get_current_user(token):
    # Get the current user information from the token
    user_info = get_user_info(token)
    return user_info.get('username') if user_info else None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    # Verify the plain password against the hashed password
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def authenticate_user_with_token(token):
    # Get user information from the backend using the token
    headers = {"Authorization": f"Bearer {token}"}
    url = BACKEND_URL + "/get-user-info"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None


def authenticate_user(email: str, password: str):
    # Get the database session
    db = SessionLocal()
    try:
        # Query the user from the database
        user = db.query(Uporabniki).filter(Uporabniki.email == email).first()

        # Check if the user exists and the password is correct
        if user and verify_password(password, user.password):
            token_payload = {
                "sub": user.email,
                "role": user.role,  # Include other relevant claims
                "exp": datetime.utcnow() + timedelta(hours=6)  # Set expiration time
            }
            secret_key = SECRET_KEY  # Replace with your actual secret key
            token = jwt.encode(token_payload, secret_key, algorithm="HS256")
            return token
    finally:
        db.close()

    return None


def current_user(email: str, password: str):
    # Get the database session
    db = SessionLocal()
    try:
        # Query the user from the database
        user = db.query(Uporabniki).filter(Uporabniki.email == email).first()
        # Check if the user exists and the password is correct
        if user and verify_password(password, user.password):
            return user.username
    finally:
        db.close()
    return None


def login():
    placeholder = st.empty()
    container = st.empty()
    with placeholder.form("login"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        if submit_button:
            placeholder.empty()
            # Check if the email and password are valid
            token = authenticate_user(email, password)
            token_str = str(token)
            if token:
                decoded_token = decode_jwt_token(token_str)
                uporabnik = get_current_user(token)
                
                st.session_state.token = token_str
                st.session_state.is_logged_in = True

                set_current_user(uporabnik)
                expiration_time = datetime.utcnow() + timedelta(minutes=30)

                clear_session_db()
                add_to_session_db(token=token_str,
                                  user=uporabnik,
                                  expiration_time=expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%f'))
  
                container.success("You have successfully logged in.")
                # Check user role
                user_role = decoded_token.get("role", "")
                if user_role == "admin":
                    st.session_state.user_role = "admin"
                    st.sidebar.empty()
                    st.rerun()
                else:
                    st.sidebar.empty()
                    st.rerun()            
            else:
                container.error("Invalid email or password. Please try again.")
                time.sleep(1)
                st.rerun() 


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         SIGN UP
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def sign_up():
    placeholder = st.empty()
    # Insert a form in the container
    with placeholder.form("register"):
        email = st.text_input("Email")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Register")
        
        if submit:
            # Check username length
            if len(username) < 3:
                st.error("Username must be at least 3 characters long.")
            # Check email format
            elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                st.error("Invalid email format.")
            # Check password length and complexity
            elif len(password) < 14 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password) or not any(c.isalnum() for c in password):
                st.error(
                    "Password must be at least 14 characters long and contain at least one uppercase letter, one digit, and one special character.")
            else:
                # Call FastaAPI to add a new user
                url = BACKEND_URL + "/sign-up"
                response = requests.post(
                    url, json={"email": email, "username": username, "password": password,"role":"normal_user"})
                if response.status_code == 201:
                    st.success("you have successfully registered.")
                    st.session_state.is_logged_in = True
                    token = authenticate_user(email, password)
                    uporabnik = get_current_user(token)
                    set_current_user(uporabnik)
                    st.session_state.token = str(token)
                    
                    clear_session_db()

                    expiration_time = datetime.utcnow() + timedelta(minutes=30)
                    
                    add_to_session_db(token=str(token),
                                      user=uporabnik,
                                      expiration_time=expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%f'))
                    
                    st.sidebar.empty()
                    st.rerun()
                elif response.status_code == 400:
                    st.error("User with that email already exists.")
                else:
                    st.error("Error occurred during user registration. Please try again.")
                
                
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         EVIDENCE
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def get_evidenca():
    url = BACKEND_URL+"/evidenca/"
    response = requests.get(url)
    df_ev = pd.DataFrame(response.json())
    logging.info(f'Successfully loaded the table from the database.')
    return df_ev


def add_evidenca(ev: shemas.Evidenca,token):
    url = BACKEND_URL + "/evidenca"
    data = ev.model_dump()
    data['datum'] = pd.to_datetime(data['datum']).strftime('%Y-%m-%dT%H:%M:%S.%f')
    data['token'] = token
    #st.write(data)
    response = requests.post(url,
                             json=data,
                             headers={'Content-Type': 'application/json'})
    logging.info(f'Successfully added a new row to the table.')
    return response


def display_ev():
    # Display the existing data table
    df = get_evidenca()
    df = df.drop(columns=['id_evidenca'])
    df['datum'] = pd.to_datetime(df['datum'], format='%Y-%m-%dT%H:%M:%S').dt.strftime('%d/%m/%Y')
    df.rename(columns={'user_username': 'User', 'opravilo': 'Task',
                       'done': 'Done', 'datum': 'Date'}, inplace=True)
    # rearange columns
    df = df[['User', 'Task', 'Done', 'Date']]
    #display the latest entry first
    df = df.iloc[::-1]
    return st.dataframe(df)


def opravila(token):
    # get data from database opravila
    NameList = get_opravila()
    st.header("Add new entry")
    current_user = get_current_user(token)

    new_row_data = {
        "User": current_user,
        "Task": st.selectbox("Select task", NameList),
        "Done": st.checkbox("Done"),
        "Date": st.date_input("Date", format="DD/MM/YYYY")
    }
    #st.write("new_row",new_row_data) 
    # submit button and adding to database
    if st.button("Submit"):
        nova_evidenca = shemas.Evidenca(
            user_username=current_user,
            opravilo=new_row_data["Task"],
            done=new_row_data["Done"],
            datum=new_row_data["Date"]
        )
        # Add new entry to database if nova_evidenca is defined
        #st.write("nova",nova_evidenca)
        add_evidenca(nova_evidenca,token)
        display_ev()
        st.rerun()
    display_ev()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         MEANS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def get_sredstva():
    url = BACKEND_URL+"/sredstva/"
    response = requests.get(url)
    df_sr = pd.DataFrame(response.json())
    logging.info(f'Successfully loaded the table from the database.')
    return df_sr


def add_sredstva(sr: shemas.Sredstva,token):
    url = BACKEND_URL + "/sredstva"
    data = sr.model_dump()
    data['date'] = pd.to_datetime(data['date']).strftime('%Y-%m-%dT%H:%M:%S.%f')
    data['token'] = token
    st.write(data)
    response = requests.post(url,
                            json=data,
                            headers={'Content-Type': 'application/json'})
    logging.info(f'Successfully added a new row to the table.')
    return response


def display_sred():
    # Display the existing data table
    df_sr = get_sredstva()
    df_sr = df_sr.drop(columns=['id_sredstva'])
    # datum format
    df_sr['date'] = pd.to_datetime(df_sr['date'], format='%Y-%m-%dT%H:%M:%S').dt.strftime('%d/%m/%Y')
    df_sr.rename(columns={'user_username': 'User', 'cistilo': 'Cleaning product',
                 'stevilo': 'Number', 'denar': 'Cost', 'date': 'Date'}, inplace=True)
    # rearange columns
    df_sr = df_sr[['User', 'Cleaning product',
                   'Number', 'Cost', 'Date']]
    df_sr = df_sr.iloc[::-1]
    return st.dataframe(df_sr)


def sredstva(token):
    # get data from database sredstva for dropdown menu
    NameList = get_cistila()
    st.header("Add new entry")
    # get current user
    current_user = get_current_user(token)

    new_row_data = {
        "User": current_user,
        "Cistila": st.selectbox("Choose the cleaning product", NameList),
        "Stevilo": st.text_input("Number of products"),
        "Denar": st.text_input("Cost of product"),
        "Datum": st.date_input("Date", format="DD/MM/YYYY")
    }
    # Validate 'Number' input
    if new_row_data["Stevilo"] and not new_row_data["Stevilo"].isdigit():
        st.error("Number of products must be an integer.")
        return
    
    # submit button and adding to database
    if st.button("Submit"):
        nova_sredstva = shemas.Sredstva(
            user_username=current_user,
            cistila=new_row_data["Cistila"],
            stevilo=new_row_data["Stevilo"],
            denar=new_row_data["Denar"],
            date=new_row_data["Datum"]
        )
        # Add new entry to database if nova_sredstva is defined
        add_sredstva(nova_sredstva, token)
        st.rerun()
    display_sred()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         ADMIN
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def get_all_users():
    url = BACKEND_URL+"/users/"
    response = requests.get(url)
    df = pd.DataFrame(response.json())
    return df


def delete_user(username, token):
    url = BACKEND_URL + "/users/" + username
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(url, headers=headers)
    if response.status_code == 200:
        st.success(f"User {username} deleted successfully.")
    else:
        st.error(f"Failed to delete user {username}.")


def manage_users():
    # Get all users from the databas
    df = get_all_users()
    df = df[df['role'] != 'admin']
    df = df.drop(columns=['id', 'password'])
    if not df.empty:
        # Display users in a DataFrame with checkboxes
        selected_users = st.multiselect(
            "Select users to delete:", df['username'])
        if st.button("Delete Selected Users"):
            for username in selected_users:
                delete_user(username,st.session_state.token)
                st.rerun()
        # Display the user DataFrame
        st.dataframe(df)
    else:
        st.info("No users found.")


def sredstva_admin():
    df_sr = get_sredstva()
    df_sr['date'] = pd.to_datetime(df_sr['date'], format='%Y-%m-%dT%H:%M:%S').dt.strftime('%d/%m/%Y')
    df_sr.rename(columns={'user_username': 'User', 'id_sredstva':'id','cistilo': 'Cleaning product',
                    'stevilo': 'Number', 'denar': 'Cost', 'date': 'Date'}, inplace=True)
    df_sr = df_sr[['id','User', 'Cleaning product',
                    'Number', 'Cost', 'Date']]
    df_sr = df_sr.iloc[::-1]
    return df_sr


def opravila_admin():
    df_ev = get_evidenca()
    #drop id_evidenca
    df_ev['datum'] = pd.to_datetime(df_ev['datum'], format='%Y-%m-%dT%H:%M:%S').dt.strftime('%d/%m/%Y')
    df_ev.rename(columns={'user_username': 'User','id_evidenca':'id' ,'opravilo': 'Task',
                    'done': 'Done', 'datum': 'Date'}, inplace=True)
    df_ev = df_ev[['id','User', 'Task', 'Done', 'Date']]
    df_ev = df_ev.iloc[::-1]
    return df_ev


def delete_selected_rows_sredstva(selected_rows):
    if isinstance(selected_rows, pd.DataFrame):
        if not selected_rows.empty:
            for index, row in selected_rows.iterrows():
                username, id_value = row['User'], row['id']

                # Make API call to delete the record
                delete_api_url = BACKEND_URL + f"/sredstva/{username}/{id_value}"  # Adjust the URL as needed
                response = requests.delete(delete_api_url)

                # Check the response status code
                if response.status_code == 200:
                    st.success(f"Successfully deleted record for {username} with ID {id_value}")
                else:
                    st.error(f"Failed to delete record for {username} with ID {id_value}")
        else:
            st.warning("No rows selected for deletion.")
    elif isinstance(selected_rows, list):
        for item in selected_rows:
            username, id_value = item.get('User'), item.get('id')

            # Make API call to delete the record
            if username is not None and id_value is not None:
                delete_api_url = BACKEND_URL + f"/sredstva/{username}/{id_value}"  # Adjust the URL as needed
                response = requests.delete(delete_api_url)

                # Check the response status code
                if response.status_code == 200:
                    st.success(f"Successfully deleted record for {username} with ID {id_value}")
                else:
                    st.error(f"Failed to delete record for {username} with ID {id_value}")
            else:
                st.warning("Invalid data format in the list.")
    else:
        st.warning("Selected rows are not in the correct format.")

    
def manage_sredstva():
    df_sr = sredstva_admin()
    display_sred()
    
    # Select rows to delete
    selected_indices = st.multiselect("Select rows to delete:", df_sr.index)
    df_to_delete = df_sr.loc[selected_indices]
    
    if st.button("Delete Selected Rows"):
        delete_selected_rows_sredstva(df_to_delete)
        st.rerun()
 

def delete_selected_rows_opravila(selected_rows):
    for index, row in selected_rows.iterrows():
        username, id_value = row['User'], row['id']

        # Make API call to delete the record
        delete_api_url = BACKEND_URL+f"/evidenca/{username}/{id_value}"
        response = requests.delete(delete_api_url)

        # Check the response status code
        if response.status_code == 200:
            st.success(f"Successfully deleted record for {username} with ID {id_value}")
        else:
            st.error(f"Failed to delete record for {username} with ID {id_value}")            
    
    
def manage_opravila():
    # Get the data from the backend
    df_ev = opravila_admin()
    display_ev()

    # Select rows to delete
    selected_indices = st.multiselect("Select rows to delete:", df_ev.index)
    selected_rows = df_ev.loc[selected_indices]

    if st.button("Delete Selected Rows"):
        # Delete the selected rows
        delete_selected_rows_opravila(selected_rows)
        st.rerun()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         API DOCUMENTATION
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def display_api():
    st.subheader("API documentation")
    st.divider()
    st.markdown("**Endpoint:** `/sign_up`")
    st.markdown("**Method:** POST")
    st.write("Adds a new user to the database. Checks if the user already exists and if the provided email is in use.")
    st.code('''
        {
        "username": "string",
        "password": "string",
        "email": "string",
        "role": "string"
        }''', language='json')
    st.divider()
    st.markdown("**Endpoint** `/login`")
    st.markdown("**Method:** POST")
    st.write("Calls a function to authenticate user, creates a token for the given user.")
    st.divider()
    st.markdown("**Endpoint:** `/users/`")
    st.markdown("**Method:** GET")
    st.write("Simple api call that gets all users from database.")
    st.markdown("**Response:**")
    st.code('''
            [
            {
            "username": "user1",
            "email": "emailUser1@gmail.com",
            "id": 2,
            "password": "$2b$223T3F9fgmSPIvaRce232062Oic8JQ0POCpxa03.V5dRemwRm9paEPv6",
            "role": "normal_user"
            }
            ]''', language='json')
    st.divider()
    st.markdown("**Endpoint:** `/users/{username}`")
    st.markdown("**Method:** GET")
    st.write("Get a user from the database.")
    st.markdown("**Response:**")
    st.code('''
            {
            "username": "user2",
            "email": "emailUser2@gmail.com",
            "id": 3,
            "password": "$2b$223T3F9fgmSPIvaRce232062Oic8JQ0POCpxa03.V5dRemwRm9paEPv6",
            "role": "normal_user"
            }
            ''',language='json') 
    st.divider()
    st.markdown("**Endpoint:** `/users/{username}/`")
    st.markdown("**Method:** DELETE")
    st.write("Deletes a user from the database.")
    st.divider()
    st.markdown("**Endpoint:** `/get-user-info`")
    st.markdown("**Method:** GET")
    st.write("Get current user information from the database using the token.")
    st.markdown("**Response:**")
    st.code('''
            {
            "username": "user2",
            "email": "emailUser2@gmail.com",
            "id": 3,
            "password": "$2b$223T3F9fgmSPIvaRce232062Oic8JQ0POCpxa03.V5dRemwRm9paEPv6",
            "role": "normal_user"
            }
            ''',language='json') 
    st.divider()
    st.markdown("**Endpoint:** `/opravila/`")
    st.markdown("**Method:** GET")
    st.write("Get all tasks from the database.")
    st.markdown("**Response:**")
    st.code('''
            [
            "Kitchen",
            "Floor",
            "WC",
            "Bathroom",
            "Balcony",
            "Dining room",
            "Trash"
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/evidenca/`")
    st.markdown("**Method:** GET")
    st.write("Get all cleaning chores from the database.")
    st.markdown("**Response:**")
    st.code('''
            [
            {
                "datum": "2024-03-12T00:00:00",
                "id_evidenca": 1,
                "done": true,
                "user_username": "user1",
                "opravilo": "Floor"
            }
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/evidenca/{username}`")
    st.markdown("**Method:** GET")
    st.write("Get all inputs from a specific user on cleaning chores from the database.")
    st.markdown("**Response:**")
    st.code('''
            [
            {
                "datum": "2024-03-12T00:00:00",
                "id_evidenca": 1,
                "done": true,
                "user_username": "user1",
                "opravilo": "Floor"
            }
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/evidenca`")
    st.markdown("**Method:** POST")
    st.write("Adds a new entry for a user to the database.")
    st.code('''
            {
            "user_username": "string",
            "opravilo": "string",
            "done": true,
            "datum": "2024-03-13T15:12:11.181Z"
            }
        ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/evidenca/{username}/{id_evidenca}`")
    st.markdown("**Method:** DELETE")
    st.write("Deletes a specific entry for a user from the database.")
    st.divider()
    st.markdown("**Endpoint:** `/cistila/`")
    st.markdown("**Method:** GET")
    st.write("Get all cleaning agents from the database.")
    st.code('''
            [
            "Floor detergent",
            "Dish detergen",
            "Toilet duck",
            "Stelex",
            "Arf",
            "BIO garbage bags",
            "Garbage bags",
            "Toilet paper",
            "Paper towels"
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/sredstva`")
    st.markdown("**Method:** POST")
    st.write("Adds a new entry for a user to the database.")
    st.code('''
            {
            "user_username": "string",
            "cistila": "string",
            "stevilo": 0,
            "denar": 0,
            "date": "2024-03-13T15:56:12.149Z"
            }
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/sredstva/{username}`")
    st.markdown("**Method:** GET")
    st.write("Get all inputs from a specific user on cleaning agents from the database.")
    st.code('''
            [
            {
                "stevilo": 2,
                "id_sredstva": 2,
                "user_username": "user1",
                "date": "2024-03-12T00:00:00",
                "cistilo": "Dish detergent",
                "denar": 5.4
            }
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/sredstva/{username}/{id_sredstva}`")
    st.markdown("**Method:** DELETE")
    st.write("Deletes a specific entry inside clening agents table for a user from the database.")
    st.divider()
    st.markdown("**Endpoint:** `/sredstva/`")
    st.markdown("**Method:** GET")
    st.write("Get all inputs from the cleaning agents table from the database.")
    st.code('''
            [
            {
                "stevilo": 2,
                "id_sredstva": 2,
                "user_username": "user1",
                "date": "2024-03-12T00:00:00",
                "cistilo": "Dish detergent",
                "denar": 5.4
            }
            ]
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/session/`")
    st.markdown("**Method:** GET")
    st.write("Get last active session/token from the database.")
    st.markdown("**Response:**")
    st.code('''
            {
            "token": string,
            "user": user1
            }
            ''',language='json')
    st.divider()
    st.markdown("**Endpoint:** `/clear_session/`")
    st.markdown("**Method:** POST")
    st.write("Clears the session database.")
    st.divider()
    st.markdown("**Endpoint:** `/session/`")
    st.markdown("**Method:** POST")
    st.write("Adds a new session/token to the database.")
    st.code('''
            {
            "token": "string",
            "expiration_time": "2024-03-13T16:06:02.333Z",
            "user": "string"
            }
            ''',language='json')
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         LOG OUT
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def log_out():
    # Clear the session state to simulate logging out
    st.session_state.clear()
    # clear session database
    clear_session_db()
    # Rerun the app to update the sidebar options
    st.rerun()

if __name__ == "__main__":
    main()
