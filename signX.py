import streamlit as st
import pandas as pd
import hashlib

# Dummy sign language data for training
SIGN_LANGUAGE_DATA = {
    "ASL": {
        "Hello": "https://www.youtube.com/watch?v=jWCk3WqtVi4",
        "Good Morning": "https://youtube.com/shorts/6HPumD9Qvpg?si=JAel9TKFQLB9JAtz",
    },
    "BSL": {
        "Hello": "hello_bsl.mp4",
        "Good Morning": "good_morning_bsl.mp4",
    }
}

# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

# Login system
def login():
    st.title("Sign Language Learning App")
    
    users_data = pd.read_csv("users.csv")  # This will store user login data

    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    hashed_password = hash_password(password)

    if st.button("Login"):
        if username in users_data['username'].values:
            stored_password = users_data[users_data['username'] == username]['password'].values[0]
            if stored_password == hashed_password:
                st.success(f"Welcome back, {username}!")
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
            else:
                st.error("Invalid password")
        else:
            st.error("Username not found")

def sign_up():
    st.subheader("Sign Up")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Sign Up"):
        if password == confirm_password:
            hashed_password = hash_password(password)
            users_data = pd.read_csv("users.csv")
            new_user = pd.DataFrame([[username, hashed_password]], columns=["username", "password"])
            users_data = pd.concat([users_data, new_user], ignore_index=True)
            users_data.to_csv("users.csv", index=False)
            st.success("Account created successfully! Please log in.")
        else:
            st.error("Passwords do not match")

# Language Selection
def select_language():
    st.subheader("Choose Your Sign Language")
    language_choice = st.selectbox("Select Language", ["ASL", "BSL"])
    return language_choice

# Training Module
def training(language):
    st.subheader("Sign Language Training")
    for phrase, video in SIGN_LANGUAGE_DATA[language].items():
        st.write(f"Phrase: {phrase}")
        st.video(video)
        if st.button(f"Mark {phrase} as learned"):
            track_progress(st.session_state['username'], language, phrase)

# Performance Tracking
def track_progress(username, language, phrase):
    progress_data = pd.read_csv("progress.csv")
    new_entry = pd.DataFrame([[username, language, phrase]], columns=["username", "language", "phrase"])
    progress_data = pd.concat([progress_data, new_entry], ignore_index=True)
    progress_data.to_csv("progress.csv", index=False)
    st.success(f"{phrase} marked as learned!")

# Display User Progress
def show_progress(username):
    st.subheader("Your Learning Progress")
    progress_data = pd.read_csv("progress.csv")
    user_progress = progress_data[progress_data['username'] == username]
    st.table(user_progress)

# Evaluation Module
def evaluation(language):
    st.subheader("Sign Language Evaluation")
    st.write("Watch the sign and identify it.")
    
    random_phrase = "Hello"  # Random example, you can make it more dynamic
    st.video(SIGN_LANGUAGE_DATA[language][random_phrase])
    
    answer = st.text_input("What is the phrase?")
    
    if st.button("Submit"):
        if answer.lower() == random_phrase.lower():
            st.success("Correct!")
            track_progress(st.session_state['username'], language, random_phrase)
        else:
            st.error("Try again!")

# Main App Flow
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if not st.session_state['logged_in']:
    st.sidebar.title("Sign Language App")
    login_option = st.sidebar.selectbox("Login or Sign Up", ["Login", "Sign Up"])

    if login_option == "Login":
        login()
    else:
        sign_up()
else:
    st.sidebar.title(f"Welcome, {st.session_state['username']}")
    action = st.sidebar.selectbox("Action", ["Select Language", "Training", "Evaluation", "View Progress", "Logout"])

    if action == "Select Language":
        language = select_language()
        st.session_state['language'] = language

    if 'language' in st.session_state:
        language = st.session_state['language']

        if action == "Training":
            training(language)

        elif action == "Evaluation":
            evaluation(language)

        elif action == "View Progress":
            show_progress(st.session_state['username'])

        elif action == "Logout":
            st.session_state['logged_in'] = False
            st.session_state['username'] = None
            st.success("Logged out successfully!")
