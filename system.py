import requests
import json
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Wazuh API credentials and endpoint (change to your Wazuh server)
WAZUH_API_URL = "https://your-wazuh-server:55000"
WAZUH_API_USER = "wazuh"
WAZUH_API_PASSWORD = "password"

# Email configuration (update with your SMTP server details)
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587
SENDER_EMAIL = 'admin@example.com'
SENDER_PASSWORD = 'password'
ADMIN_EMAIL = 'admin@example.com'

# Block IP function using iptables (Linux)
def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        print(f"Blocked IP: {ip_address}")
    except Exception as e:
        print(f"Error blocking IP {ip_address}: {e}")

# Function to send an email notification to the administrator
def notify_admin(ip_address):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = f"Security Alert: Blocked IP {ip_address}"

        body = f"IP {ip_address} was blocked due to suspicious activity on the server."
        msg.attach(MIMEText(body, 'plain'))

        # Connect to the email server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, text)
        server.quit()

        print(f"Notification sent to admin for IP: {ip_address}")
    except Exception as e:
        print(f"Failed to send email notification: {e}")

# Function to check Wazuh alerts
def check_wazuh_alerts():
    url = f"{WAZUH_API_URL}/alerts"
    headers = {
        "Content-Type": "application/json"
    }
    
    # Get Wazuh alerts
    try:
        response = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD), headers=headers, verify=False)
        if response.status_code == 200:
            alerts = json.loads(response.text)['data']['alerts']
            for alert in alerts:
                if alert['rule']['id'] == 5715:  # Example rule ID for unauthorized access
                    ip_address = alert['data']['srcip']
                    print(f"Detected unauthorized access from IP: {ip_address}")

                    # Block IP and notify admin
                    block_ip(ip_address)
                    notify_admin(ip_address)
        else:
            print(f"Failed to fetch Wazuh alerts: {response.status_code}")
    except Exception as e:
        print(f"Error fetching alerts from Wazuh API: {e}")

# Simulating the function to check alerts periodically
if __name__ == "__main__":
    while True:
        check_wazuh_alerts()
        # Pause between checks (e.g., 5 minutes)
        time.sleep(300)
