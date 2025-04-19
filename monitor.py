import re
import argparse
from collections import defaultdict, deque
import time
import smtplib
from email.mime.text import MIMEText

# Configuration (consider moving to a config file or environment variables)
LOG_FILE_PATH = r'C:\Users\vaugh\Documents\Coding\failed_login_monitor\attempts.log' # Example for SSH logs, adjust as needed
LOG_FORMAT_REGEX = r'Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+' # Example regex, adjust for your log format
TIME_WINDOW_SECONDS = 300 # 5 minutes
MAX_FAILED_ATTEMPTS = 5
ALERT_EMAIL_TO = 'Your_Email'
ALERT_EMAIL_FROM = 'Your_SMTP_'
SMTP_SERVER = 'localhost'
SMTP_PORT = 25 # or 587 for TLS, 465 for SSL
SMTP_USER = None # Set if authentication is required
SMTP_PASSWORD = None # Set if authentication is required

failed_attempts = defaultdict(lambda: deque())
blocked_ips = set()

def send_alert(ip_address, attempts):
    """Sends an email alert about a potential brute-force attack."""
    subject = f"Potential Brute-Force Attack Detected from {ip_address}"
    body = f"Alert: Detected {len(attempts)} failed login attempts from IP address {ip_address} within the last {TIME_WINDOW_SECONDS} seconds.\n\n"
    body += "Attempt Timestamps:\n"
    for ts in attempts:
        body += f"- {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}\n"
    body += f"\nIP address {ip_address} may be blocked or further action might be required."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = ALERT_EMAIL_FROM
    msg['To'] = ALERT_EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # Uncomment the following lines if using TLS
            # server.starttls()
            # if SMTP_USER and SMTP_PASSWORD:
            #     server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())
        print(f"Alert email sent successfully to {ALERT_EMAIL_TO} regarding IP {ip_address}.")
    except Exception as e:
        print(f"Error sending alert email: {e}")

def parse_log_line(line):
    """Parses a log line to extract relevant information."""
    match = re.search(LOG_FORMAT_REGEX, line)
    if match:
        return match.groupdict()
    return None

def monitor_log_file(log_file):
    """Monitors the log file for failed login attempts."""
    print(f"Monitoring log file: {log_file}")
    print(f"Alerting on more than {MAX_FAILED_ATTEMPTS} failures within {TIME_WINDOW_SECONDS} seconds.")
    try:
        with open(log_file, 'r') as f:
            # Go to the end of the file initially
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1) # Wait for new lines
                    continue

                log_entry = parse_log_line(line.strip())
                if log_entry:
                    ip = log_entry['ip']
                    current_time = time.time()

                    if ip in blocked_ips:
                        continue # Skip already alerted IPs for this run (can be refined)

                    # Add current attempt timestamp
                    failed_attempts[ip].append(current_time)

                    # Remove timestamps older than the time window
                    while failed_attempts[ip] and failed_attempts[ip][0] < current_time - TIME_WINDOW_SECONDS:
                        failed_attempts[ip].popleft()

                    # Check if threshold is exceeded
                    if len(failed_attempts[ip]) >= MAX_FAILED_ATTEMPTS:
                        print(f"ALERT: Potential brute-force attack from {ip}. Attempts: {len(failed_attempts[ip])}")
                        send_alert(ip, list(failed_attempts[ip]))
                        blocked_ips.add(ip) # Add to alerted list for this session
                        # Optional: Implement actual blocking (e.g., firewall rule)
                        # print(f"Action: Consider blocking IP {ip}")
                        # Clear attempts for this IP after alerting to avoid re-alerting immediately
                        failed_attempts[ip].clear()

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor log files for failed login attempts.")
    parser.add_argument("-l", "--logfile", default=LOG_FILE_PATH, help=f"Path to the log file to monitor (default: {LOG_FILE_PATH})")
    parser.add_argument("-t", "--threshold", type=int, default=MAX_FAILED_ATTEMPTS, help=f"Number of failed attempts to trigger an alert (default: {MAX_FAILED_ATTEMPTS})")
    parser.add_argument("-w", "--window", type=int, default=TIME_WINDOW_SECONDS, help=f"Time window in seconds to count failed attempts (default: {TIME_WINDOW_SECONDS})")
    # Add arguments for email config if needed

    args = parser.parse_args()

    # Update config from args if provided
    LOG_FILE_PATH = args.logfile
    MAX_FAILED_ATTEMPTS = args.threshold
    TIME_WINDOW_SECONDS = args.window

    monitor_log_file(LOG_FILE_PATH)