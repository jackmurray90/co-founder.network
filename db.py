from sqlalchemy import Integer, Numeric, Column, String, Text, Boolean, ForeignKey, Date
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
  __tablename__ = 'users'
  id = Column(Integer, primary_key=True)
  username = Column(String, unique=True)
  name = Column(String, default='')
  city = Column(String, default='')
  cv = Column(String, default='')
  about = Column(Text, default='')
  open = Column(Boolean, default=False)
  show_email = Column(Boolean, default=False)
  show_profile = Column(Boolean, default=False)
  api_key = Column(String)
  email = Column(String)
  email_verified = Column(Boolean, default=False)
  admin = Column(Boolean, default=False)
  views = relationship('View')

class Job(Base):
  __tablename__ = 'jobs'
  id = Column(Integer, primary_key=True)
  user_id = Column(Integer, ForeignKey('users.id'))
  name = Column(String, default='')
  url = Column(String, default='')
  position = Column(String, default='')
  location = Column(String, default='')
  share = Column(Numeric(6, 3))
  vesting_frequency = Column(Integer)
  vesting_peroid = Column(Integer)
  description = Column(Text, default='')
  expiration = Column(Date)
  paid = Column(Boolean, default=False)

class LoginCode(Base):
  __tablename__ = 'login_codes'
  code = Column(String, primary_key=True)
  user_id = Column(Integer, ForeignKey('users.id'))
  expiry = Column(Integer)
  user = relationship('User')

class Referrer(Base):
  __tablename__ = 'referrers'
  hostname = Column(String, primary_key=True)
  count = Column(Integer)

class View(Base):
  __tablename__ = 'views'
  id = Column(Integer, primary_key=True)
  user_id = Column(Integer, ForeignKey('users.id'))
  job_id = Column(Integer, ForeignKey('jobs.id'))
  remote_address = Column(String)
  timestamp = Column(Integer)
