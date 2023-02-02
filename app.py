from flask import Flask, request, redirect, abort, render_template, make_response
from csrf import csrf
from util import random_128_bit_string
from sqlalchemy import create_engine
from decimal import Decimal
from datetime import date, timedelta
from config import DATABASE
from db import User, LoginCode, Referrer, View, Job
from time import time
from mistune import create_markdown
from mail import send_email
from os.path import isfile
from os import system, unlink
import re

# print(start_date + timedelta(days=days_in_month))

app = Flask(__name__)
get, post = csrf(app, create_engine(DATABASE))
markdown = create_markdown()

def make_url(url):
  url = url.strip()
  if not url: return url
  if url.startswith("http://") or url.startswith("https://"):
    return url
  return f'http://{url}'

@app.template_filter()
def render_markdown(m):
  return markdown(m)

@get('/')
def landing_page(render_template, session, user, tr):
  log_referrer(session)
  return render_template('landing_page.html', profiles=session.query(User).order_by(User.bump_timestamp.desc()))

@get('/pages/privacy-policy')
def privacy(render_template, session, user, tr):
  log_referrer(session)
  return render_template('privacy_policy.html')

@get('/pages/terms-and-conditions')
def terms(render_template, session, user, tr):
  log_referrer(session)
  return render_template('terms.html')

@get('/sitemap.xml')
def sitemap(render_template, session, user, tr):
  response = render_template('sitemap.xml', users=session.query(User).all())
  response.headers['Content-Type'] = 'text/xml'
  return response

@get('/pages/cordova')
def cordova(render_template, session, user, tr):
  response = make_response(redirect('/'))
  response.set_cookie('cordova', 'true')
  return response

@get('/pages/cordova/<code>')
def cordova(render_template, session, user, tr, code):
  if re.search('[^0-9a-zA-Z]', code): abort(400)
  return f'<!doctype html><script>window.location.href="cofoundernetwork:{code}";</script>'

@get('/pages/referrers')
def referrers(render_template, session, user, tr):
  if not user or not user.admin: return redirect('/')
  return render_template('referrers.html', referrers=session.query(Referrer).order_by(Referrer.count.desc()).all())

@get('/pages/sign-up')
def sign_up(render_template, session, user, tr):
  if user: return redirect('/')
  return render_template('login.html', sign_up=True)

@post('/pages/sign-up')
def sign_up(redirect, session, user, tr):
  if user: return redirect('/')
  if not 'terms' in request.form: return redirect('/pages/sign-up', tr['must_agree'])
  try:
    [user] = session.query(User).where(User.email == request.form['email'].strip().lower())
    if user.email_verified:
      return redirect('/pages/sign-up', tr['account_already_exists'])
  except:
    user = User(email=request.form['email'].strip().lower(), api_key=random_128_bit_string(), email_notifications_key=random_128_bit_string(), bump_timestamp=int(time()))
    session.add(user)
    session.commit()
  login_code = LoginCode(user_id=user.id, code=random_128_bit_string(), expiry=int(time()+60*60*2))
  session.add(login_code)
  session.commit()
  template = 'emails/verification.html' if not 'cordova' in request.cookies else 'emails/cordova_verification.html'
  send_email(user.email, tr['verification_email_subject'], render_template(template, tr=tr, code=login_code.code))
  return redirect('/pages/sign-up', tr['verify_your_email'] % user.email)

@get('/pages/login/<code>')
def login(render_template, session, user, tr, code):
  try:
    [login_code] = session.query(LoginCode).where(LoginCode.code == code)
  except:
    abort(404)
  if login_code.expiry < time():
    return render_template('login.html', message=tr['login_code_expired'])
  [user] = session.query(User).where(User.id == login_code.user_id)
  user.email_verified = True
  session.delete(login_code)
  session.commit()
  if user.username:
    response = make_response(redirect(f'/{user.username}'))
  else:
    response = make_response(redirect(f'/{user.id}'))
  response.set_cookie('api_key', user.api_key)
  return response

@get('/pages/login')
def login(render_template, session, user, tr):
  if user: return redirect('/')
  return render_template('login.html')

@post('/pages/login')
def login(redirect, session, user, tr):
  if user: return redirect('/')
  try:
    [user] = session.query(User).where(User.email == request.form['email'].strip().lower())
  except:
    return redirect('/pages/login', tr['email_not_found'])
  login_code = LoginCode(user_id=user.id, code=random_128_bit_string(), expiry=int(time()+60*60*2))
  session.add(login_code)
  session.commit()
  if user.email_verified:
    template = 'emails/login.html' if not 'cordova' in request.cookies else 'emails/cordova_login.html'
    send_email(user.email, tr['login_email_subject'], render_template(template, tr=tr, code=login_code.code))
    return redirect('/pages/login', tr['login_email_sent'])
  else:
    template = 'emails/verification.html' if not 'cordova' in request.cookies else 'emails/cordova_verification.html'
    send_email(user.email, tr['verification_email_subject'], render_template(template, tr=tr, code=login_code.code))
    return redirect('/pages/sign-up', tr['verify_your_email'] % request.form['email'])

@post('/pages/logout')
def logout(redirect, session, user, tr):
  if not user: return redirect('/')
  response = redirect('/')
  response.set_cookie('api_key', '', expires=0)
  return response

@post('/pages/set-username')
def set_username(redirect, session, user, tr):
  if not user: return redirect('/')
  if re.search('[^a-z0-9-]', request.form['username']) or not re.search('[a-z]', request.form['username']):
    abort(400)
  if len(request.form['username']) > 30:
    abort(400)
  try:
    if request.form['username'] == 'pages':
      raise Exception
    user.username = request.form['username'] or None
    session.commit()
    return redirect('/pages/settings', tr['successful_claim'] + request.form['username'])
  except:
    return redirect('/pages/settings', request.form['username'] + tr['is_taken'])

@post('/pages/set-profile-picture')
def set_profile_picture(redirect, session, user, tr):
  if not user: return abort(403)
  temp = random_128_bit_string()
  request.files['image'].save(f'static/profile_pictures/{temp}')
  system(f"convert static/profile_pictures/{temp} -resize 128x128 static/profile_pictures/{user.id}.png")
  unlink(f'static/profile_pictures/{temp}')
  return {'result': 'success'}

@get('/pages/settings')
def settings(render_template, session, user, tr):
  if not user: return redirect('/')
  return render_template('settings.html', profile_picture_exists=isfile(f'static/profile_pictures/{user.id}.png'))

@post('/pages/settings')
def settings(redirect, session, user, tr):
  if not user: return redirect('/')
  if len(request.form['name']) > 80: abort(400)
  if len(request.form['city']) > 80: abort(400)
  if len(request.form['cv']) > 80: abort(400)
  if len(request.form['about']) > 1000: abort(400)
  user.name = request.form['name']
  user.city = request.form['city']
  user.cv = request.form['cv']
  user.about = request.form['about']
  user.show_email = 'show_email' in request.form
  user.show_profile = 'show_profile' in request.form
  user.open = 'open' in request.form
  user.receive_emails = 'receive_emails' in request.form
  session.commit()
  if user.username:
    return redirect(f'/{user.username}')
  return redirect(f'/{user.id}')

@get('/pages/delete')
def delete(render_template, session, user, tr):
  if not user: return redirect('/')
  return render_template('delete.html')

@post('/pages/delete')
def delete(redirect, session, user, tr):
  if not user: return redirect('/')
  session.delete(user)
  session.commit()
  return redirect('/')

@get('/<int:id>')
def view(render_template, session, user, tr, id):
  log_referrer(session)
  try:
    [profile] = session.query(User).where(User.id == id)
  except:
    abort(404)
  return view_profile(render_template, session, user, profile)

@get('/<username>')
def view(render_template, session, user, tr, username):
  log_referrer(session)
  try:
    [profile] = session.query(User).where(User.username == username)
  except:
    abort(404)
  return view_profile(render_template, session, user, profile)

def view_profile(render_template, session, user, profile):
  if not profile.show_profile and (not user or user.id != profile.id):
    abort(404)
  view = session.query(View).filter((View.user_id == profile.id) & (View.remote_address == request.remote_addr)).first()
  if view is None:
    view = View(user_id=profile.id, remote_address=request.remote_addr, timestamp=0)
  if view.timestamp + 60*60*24 < time():
    session.add(View(user_id=profile.id, remote_address=request.remote_addr, timestamp=int(time())))
    session.commit()
  return render_template('profile.html', profile=profile, profile_picture_exists=isfile(f'static/profile_pictures/{profile.id}.png'))

def log_referrer(session):
  try:
    referrer_hostname = re.match('https?://([^/]*)', request.referrer).group(1)
  except:
    referrer_hostname = 'unknown'
  try:
    [ref] = session.query(Referrer).where(Referrer.hostname == referrer_hostname)
    ref.count += 1
    session.commit()
  except:
    session.add(Referrer(hostname=referrer_hostname, count=1))
    session.commit()
