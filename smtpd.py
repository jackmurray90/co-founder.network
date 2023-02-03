from aiosmtpd.controller import Controller
from asyncio import get_event_loop
from email import message_from_bytes, policy
from mail import send_raw_email
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from config import DATABASE
from db import User, Connection
import re
import ssl

engine = create_engine(DATABASE)

class Handler:
  async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
    if not address.endswith('@co-founder.network'):
      return '550 not relaying to that domain'
    envelope.rcpt_tos.append(address)
    return '250 OK'

  async def handle_DATA(self, server, session, envelope):
    try:
      message = message_from_bytes(envelope.content, policy=policy.default)
    except:
      return
    with Session(engine) as session:
      def get_user(address):
        match = re.match('.*<(.*)>', address)
        if match:
          address = match.group(1)
        address = address.strip()
        return session.query(User).where(User.email == address).first()
      for recipient in envelope.rcpt_tos:
        if 'jack@co-founder.network' in recipient:
          try:
            message.replace_header('Reply-To', envelope.mail_from)
          except:
            message.add_header('Reply-To', envelope.mail_from)
          try:
            message.replace_header('From', 'no-reply@co-founder.network')
          except:
            message.add_header('From', 'no-reply@co-founder.network')
          try:
            message.replace_header('To', 'jack@murray.software')
          except:
            message.add_header('To', 'jack@murray.software')
          send_raw_email('no-reply@co-founder.network', 'jack@murray.software', message)
        if 'connections@co-founder.network' in recipient:
          sender = get_user(message['From'] or '')
          if sender:
            for recipient in (message['To'] or '').split(','):
              recipient = get_user(recipient)
              if recipient:
                try:
                  session.add(Connection(a=sender.id, b=recipient.id))
                  session.commit()
                except:
                  pass
    return '250 Message accepted for delivery'

if __name__ == '__main__':
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain(
    '/etc/letsencrypt/live/co-founder.network/fullchain.pem',
    '/etc/letsencrypt/live/co-founder.network/privkey.pem'
  )
  controller = Controller(Handler(), hostname='0.0.0.0', port=25, tls_context=context)
  ssl_controller = Controller(Handler(), hostname='0.0.0.0', port=465, ssl_context=context)
  controller.start()
  ssl_controller.start()
  get_event_loop().run_forever()
