from flask import Flask, request, render_template, redirect, url_for
import datetime
import os
import time

app = Flask(__name__)

# Use the same log file path as the monitor script
# Ensure this path is correct for your environment
# Read from environment variable or use default
LOG_FILE_PATH = os.environ.get('FAILED_LOGIN_LOG_PATH', r'C:\Users\vaugh\Documents\Coding\failed_login_monitor\attempts.log')

@app.route('/')
def login_form():
    """Displays the login form."""
    # Check if templates directory exists, create if not
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # Check if login.html exists, create a basic one if not
    login_html_path = os.path.join('templates', 'login.html')
    if not os.path.exists(login_html_path):
        with open(login_html_path, 'w') as f:
            f.write('''<!doctype html>
<title>Test Login</title>
<h1>Test Login Page</h1>
<form method=post action="/login">
  <label for="username">Username:</label>
  <input type=text id="username" name=username required><br><br>
  <label for="password">Password:</label>
  <input type=password id="password" name=password required><br><br>
  <input type=submit value=Login>
</form>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul class=flashes>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
''')
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    """Handles the login attempt and logs a failed attempt."""
    username = request.form.get('username', 'unknown_user')
    # Simulate failed login for any input
    ip_address = request.remote_addr # Get the client's IP address
    timestamp = datetime.datetime.now().strftime('%b %d %H:%M:%S') # Example format, adjust if needed
    hostname = 'test-system' # Placeholder hostname

    # Construct the log message based on the monitor's expected format
    # Format: Failed password for <user> from <ip> port <port>
    # We need to ensure this matches LOG_FORMAT_REGEX in monitor.py
    log_message = f"{timestamp} {hostname} sshd[12345]: Failed password for {username} from {ip_address} port 54321\n"

    try:
        with open(LOG_FILE_PATH, 'a') as log_file:
            log_file.write(log_message)
        print(f"Logged failed attempt for user '{username}' from IP {ip_address}")
        # Optionally flash a message to the user
        # flash('Simulated failed login attempt logged.')
    except Exception as e:
        print(f"Error writing to log file {LOG_FILE_PATH}: {e}")
        # Optionally flash an error message
        # flash('Error logging attempt.')

    # Redirect back to the login form or show a confirmation
    # return redirect(url_for('login_form'))
    return f"Simulated failed login attempt for user '{username}' from IP {ip_address} logged to {LOG_FILE_PATH}. <a href='/'>Try again</a>"

if __name__ == '__main__':
    # Ensure the log file exists, create if not
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'w') as f:
            print(f"Created log file: {LOG_FILE_PATH}")
            f.write("Log file created.\n") # Add an initial line if needed

    # Read secret key from environment variable or use a default
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_secret_key') # Needed for flashing messages
    app.run(port=5000) # Runs on http://127.0.0.1:5000/, removed debug=True