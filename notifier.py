import smtplib
from email.message import EmailMessage

# For testing, you can call this manually or integrate with a background task
def send_security_alert(user_email):
    # USE YOUR APP PASSWORD HERE
    EMAIL_ADDRESS = "your-email@gmail.com"
    EMAIL_PASSWORD = "your-app-password" 

    msg = EmailMessage()
    msg['Subject'] = '🛡️ Vault+ Security Checkup'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = user_email
    msg.set_content(f"Hi {user_email},\n\nOur system noticed you haven't updated your passwords in a while. "
                    "For maximum security, we recommend rotating your credentials to prevent credential leaks.")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except:
        return False