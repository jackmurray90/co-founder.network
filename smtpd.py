from aiosmtpd.controller import Controller
from asyncio import get_event_loop
from email import message_from_bytes, policy
from mail import forward_email 
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
      for recipient in envelope.rcpt_tos:
        if 'jack@co-founder.network' in recipient:
          forward_email('no-reply@co-founder.network', 'jack@murray.software', message)
        match = re.search('connections\+([a-zA-Z0-9]+)@co-founder.network', message['To'] or '')
        if match:
          connection = session.query(Connection).where(Connection.code == match.group(1)).first()
          if connection:
            try:
              session.add(Connection(a=connection.b, b=connection.a))
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
  controller = Controller(Handler(), hostname='0.0.0.0', port=25, tls_context=context, server_hostname='co-founder.network')
  ssl_controller = Controller(Handler(), hostname='0.0.0.0', port=465, ssl_context=context, server_hostname='co-founder.network')
  controller.start()
  ssl_controller.start()
  get_event_loop().run_forever()
