from flask import Flask, render_template, request, redirect, session, url_for
from utils import encrypt_message, decrypt_message, history, feedbacks, users
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return redirect(url_for('chat')) if 'user' in session else redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        users[request.form['username']] = request.form['password']
        session['user'] = request.form['username']
        return redirect(url_for('chat'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if users.get(request.form['username']) == request.form['password']:
            session['user'] = request.form['username']
            return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user' not in session: return redirect(url_for('login'))
    response = None
    if request.method == 'POST':
        msg = request.form['message']
        urgency = request.form['urgency']
        priority = request.form['priority']
        enc = encrypt_message(msg)
        dec = decrypt_message(enc)
        history.append({'user': session['user'], 'message': dec, 'urgency': urgency, 'priority': priority})
        response = encrypt_message("Received ✅")
    return render_template('chat.html', response=response)

@app.route('/history')
def show_history():
    if 'user' not in session: return redirect(url_for('login'))
    user_history = [h for h in history if h['user'] == session['user']]
    return render_template('history.html', history=user_history)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        feedbacks.append({'user': session['user'], 'feedback': request.form['feedback']})
        return render_template('feedback.html', thanks=True)
    return render_template('feedback.html')

if __name__ == '__main__':
    app.run(debug=True)
