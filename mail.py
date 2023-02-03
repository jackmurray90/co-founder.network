from smtplib import SMTP_SSL
from ssl import create_default_context
from config import SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread

def send_email(frm, recipients, subject, content, reply_to=None):
  def thread():
    with SMTP_SSL(SMTP_HOST, SMTP_PORT, context=create_default_context()) as server:
      server.login(SMTP_USERNAME, SMTP_PASSWORD)
      message = MIMEMultipart("alternative")
      message['Subject'] = subject
      message['From'] = frm
      message['To'] = recipients
      if reply_to:
        message['Reply-To'] = reply_to
      message.attach(MIMEText(content, 'html'))
      server.sendmail(frm, recipients, message.as_string())
  Thread(target=thread).start()

def send_raw_email(frm, recipients, message):
  def thread():
    with SMTP_SSL(SMTP_HOST, SMTP_PORT, context=create_default_context()) as server:
      server.login(SMTP_USERNAME, SMTP_PASSWORD)
      server.sendmail(frm, recipients, message)
  Thread(target=thread).start()
