from flask import Flask, request, redirect, abort, render_template, make_response
from csrf import csrf
from util import random_128_bit_string
from sqlalchemy import create_engine
from decimal import Decimal
from datetime import date, timedelta
from config import DATABASE, STRIPE_API_KEY
from db import User, LoginCode, Referrer, View, Job, Connection, Application, JobPayment
from time import time, sleep
from mistune import create_markdown
from mail import send_email
from os.path import isfile
from os import system, unlink
import stripe
import re

app = Flask(__name__)
get, post = csrf(app, create_engine(DATABASE))
markdown = create_markdown()
stripe.api_key = STRIPE_API_KEY

def make_url(url):
  url = url.strip()
  if not url: return url
  if url.startswith("http://") or url.startswith("https://"):
    return url
  return f'http://{url}'

def valid_email(email):
  return re.match("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])", email)

def init_profile_for_render(session, user, profile):
  if isfile(f'static/profile_pictures/{profile.id}.png'):
    profile.profile_picture_exists = True
  if user and session.query(Connection).where((Connection.a == user.id) & (Connection.b == profile.id)).first():
    if session.query(Connection).where((Connection.a == profile.id) & (Connection.b == user.id)).first():
      profile.connected = True
    else:
      profile.connection_request_sent = True

def init_job_for_render(session, user, job):
  if isfile(f'static/job_logos/{job.id}.png'):
    job.logo_exists = True
  if user and session.query(Application).where((Application.user_id == user.id) & (Application.job_id == job.id)).first():
    job.applied = True

@app.template_filter()
def render_markdown(m):
  return markdown(m)

@get('/')
def landing_page(render_template, session, user, tr):
  log_referrer(session)
  profiles = session.query(User).where((User.name != '') & (User.show_profile == True)).order_by(User.bump_timestamp.desc()).limit(100)
  for profile in profiles:
    init_profile_for_render(session, user, profile)
  return render_template('members.html', profiles=profiles)

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
  response = render_template('sitemap.xml', users=session.query(User).where(User.show_profile == True), jobs=session.query(Job).where((Job.active == True) & (Job.paid == True) & (Job.expiration >= date.today())))
  response.headers['Content-Type'] = 'text/xml'
  return response

@get('/pages/cordova')
def cordova(render_template, session, user, tr):
  response = make_response(redirect('/'))
  response.set_cookie('cordova', 'true', samesite='Lax', secure=True)
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
  if not valid_email(request.form['email'].strip().lower()): return redirect('/pages/sign-up', tr['invalid_email'])
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
  send_email("no-reply@co-founder.network", user.email, tr['verification_email_subject'], render_template(template, tr=tr, code=login_code.code))
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
  response = make_response(redirect('/pages/settings'))
  response.set_cookie('api_key', user.api_key, samesite='Lax', secure=True)
  return response

@get('/pages/login')
def login(render_template, session, user, tr):
  if user: return redirect('/')
  return render_template('login.html')

@post('/pages/login')
def login(redirect, session, user, tr):
  if user: return redirect('/')
  if not valid_email(request.form['email'].strip().lower()): return redirect('/pages/login', tr['invalid_email'])
  try:
    [user] = session.query(User).where(User.email == request.form['email'].strip().lower())
  except:
    return redirect('/pages/login', tr['email_not_found'])
  login_code = LoginCode(user_id=user.id, code=random_128_bit_string(), expiry=int(time()+60*60*2))
  session.add(login_code)
  session.commit()
  if user.email_verified:
    template = 'emails/login.html' if not 'cordova' in request.cookies else 'emails/cordova_login.html'
    send_email("no-reply@co-founder.network", user.email, tr['login_email_subject'], render_template(template, tr=tr, code=login_code.code))
    return redirect('/pages/login', tr['login_email_sent'])
  else:
    template = 'emails/verification.html' if not 'cordova' in request.cookies else 'emails/cordova_verification.html'
    send_email("no-reply@co-founder.network", user.email, tr['verification_email_subject'], render_template(template, tr=tr, code=login_code.code))
    return redirect('/pages/sign-up', tr['verify_your_email'] % request.form['email'])

@post('/pages/logout')
def logout(redirect, session, user, tr):
  if not user: return redirect('/')
  response = redirect('/')
  response.set_cookie('api_key', '', expires=int(time())+5, samesite='Lax', secure=True)
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

@post('/pages/set-logo/<id>')
def set_profile_picture(redirect, session, user, tr, id):
  if not user: abort(403)
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.user_id == user.id: abort(403)
  temp = random_128_bit_string()
  request.files['image'].save(f'static/job_logos/{temp}')
  system(f"convert static/job_logos/{temp} -resize 128x128 static/job_logos/{id}.png")
  unlink(f'static/job_logos/{temp}')
  return {'result': 'success'}

@get('/pages/settings')
def settings(render_template, session, user, tr):
  if not user: return redirect('/')
  if isfile(f'static/profile_pictures/{user.id}.png'):
    user.profile_picture_exists = True
  if user.bump_timestamp < int(time()) - 60*60*24*7:
    user.made_first_bump = False
  return render_template('settings.html')

@post('/pages/settings')
def settings(redirect, session, user, tr):
  if not user: return redirect('/')
  if len(request.form['name']) > 80: abort(400)
  if '\n' in request.form['name']: abort(400)
  if len(request.form['city']) > 80: abort(400)
  if len(request.form['cv']) > 80: abort(400)
  if len(request.form['about']) > 1000: abort(400)
  user.name = request.form['name']
  user.city = request.form['city']
  user.cv = make_url(request.form['cv'])
  user.about = request.form['about']
  user.show_email = 'show_email' in request.form
  user.show_profile = 'show_profile' in request.form
  user.open = 'open' in request.form
  user.receive_connection_emails = 'receive_connection_emails' in request.form
  user.receive_application_emails = 'receive_application_emails' in request.form
  session.commit()
  if user.username:
    return redirect(f'/{user.username}', tr['settings_saved'])
  return redirect(f'/{user.id}', tr['settings_saved'])

@post('/pages/bump-profile')
def settings(redirect, session, user, tr):
  if not user: return redirect('/')
  if user.made_first_bump and user.bump_timestamp >= int(time()) - 60*60*24*7:
    abort(403)
  user.bump_timestamp = int(time())
  user.made_first_bump = True
  session.commit()
  return redirect('/pages/settings', tr['your_profile_bumped'])

@get('/pages/jobs')
def jobs(render_template, session, user, tr):
  log_referrer(session)
  jobs = session.query(Job).where((Job.name != '') & (Job.active == True) & (Job.expiration >= date.today())).order_by(Job.id.desc())
  for job in jobs:
    init_job_for_render(session, user, job)
  return render_template('jobs.html', jobs=jobs)

@get('/pages/my-jobs')
def jobs(render_template, session, user, tr):
  if not user: return redirect('/')
  jobs = session.query(Job).where(Job.user_id == user.id)
  for job in jobs:
    init_job_for_render(session, user, job)
  return render_template('my_jobs.html', jobs=jobs)

@get('/pages/jobs/<id>')
def job(render_template, session, user, tr, id):
  log_referrer(session)
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.active and (not user or user.id != job.user_id): abort(404)
  view = session.query(View).filter((View.job_id == job.id) & (View.remote_address == request.remote_addr)).first()
  if view is None: view = View(job_id=job.id, remote_address=request.remote_addr, timestamp=0)
  if view.timestamp + 60*60*24 < time():
    session.add(View(job_id=job.id, remote_address=request.remote_addr, timestamp=int(time())))
    session.commit()
  init_job_for_render(session, user, job)
  return render_template('job.html', job=job)

@get('/pages/generate-job-payment/<id>')
def generate_job_payment(render_template, session, user, tr, id):
  if not user: return redirect('/')
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if job.user_id != user.id: abort(403)
  job_payment = JobPayment(job_id=job.id)
  session.add(job_payment)
  session.commit()
  response = stripe.checkout.Session.create(
    success_url=f"https://co-founder.network/pages/job-payment/{job_payment.id}",
    line_items=[{"price": "price_1MXyQCLVmaYiDBolchsCKxoO","quantity": 1}],
    mode="payment",
    customer_email=user.email
  )
  job_payment.stripe_session_id = response['id']
  session.commit()
  return redirect(response['url'])

@get('/pages/job-payment/<id>')
def job_payment(render_template, session, user, tr, id):
  if not user: return redirect('/')
  job_payment = session.query(JobPayment).where(JobPayment.id == id).first()
  if not job_payment: abort(404)
  job = session.query(Job).where(Job.id == job_payment.job_id).first()
  if job.user_id != user.id: abort(403)
  if job_payment.processed:
    return render_template('job_paid.html', error=False)
  response = stripe.checkout.Session.retrieve(job_payment.stripe_session_id)
  if response['payment_status'] != 'paid':
    return render_template('job_paid.html', error=True)
  job_payment.processed  = True
  if job.paid:
    job.expiration = job.expiration + timedelta(days=30)
  else:
    job.expiration = date.today() + timedelta(days=30)
    job.paid = True
  session.commit()
  return render_template('job_paid.html', error=False)

@get('/pages/new-job')
def new_job(render_template, session, user, tr):
  if not user: return redirect('/')
  job = Job(user_id=user.id)
  session.add(job)
  session.commit()
  return redirect(f'/pages/edit-job/{job.id}')

@get('/pages/edit-job/<id>')
def edit_job(render_template, session, user, tr, id):
  if not user: return redirect('/')
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.user_id == user.id: abort(403)
  init_job_for_render(session, user, job)
  return render_template('edit_job.html', job=job)

@post('/pages/edit-job/<id>')
def edit_job(redirect, session, user, tr, id):
  if not user: return redirect('/')
  if len(request.form['name']) > 80: abort(400)
  if len(request.form['url']) > 80: abort(400)
  if len(request.form['location']) > 80: abort(400)
  if len(request.form['position']) > 80: abort(400)
  if len(request.form['description']) > 1500: abort(400)
  try:
    share = Decimal(request.form['share']) if request.form['share'] else None
    vesting_period = int(request.form['vesting_period']) if request.form['vesting_period'] else None
    vesting_frequency = int(request.form['vesting_frequency']) if request.form['vesting_frequency'] else None
  except:
    abort(400)
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.user_id == user.id: abort(403)
  job.name = request.form['name']
  job.url = make_url(request.form['url'])
  job.location = request.form['location']
  job.position = request.form['position']
  job.description = request.form['description']
  job.share = share
  job.vesting_period = vesting_period
  job.vesting_frequency = vesting_frequency
  job.active = 'active' in request.form
  session.commit()
  return redirect(f'/pages/edit-job/{job.id}', tr['job_listing_saved'])

@get('/pages/delete-job/<id>')
def delete_job(render_template, session, user, tr, id):
  if not user: return redirect('/')
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.user_id == user.id: abort(403)
  return render_template('delete_job.html', job=job)

@post('/pages/delete-job/<id>')
def delete_job(redirect, session, user, tr, id):
  if not user: return redirect('/')
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.user_id == user.id: abort(403)
  # TODO: do this with a lock
  while True:
    try:
      job = session.query(Job).where(Job.id == id).first()
      for view in job.views:
        session.delete(view)
      for application in job.applications:
        session.delete(application)
      session.delete(job)
      session.commit()
      break
    except:
      sleep(1)
  return redirect('/pages/jobs', tr['job_deleted'])

@post('/pages/connection-request/<id>')
def connection_request(redirect, session, user, tr, id):
  if not user: abort(403)
  if len(request.form['message']) > 1000: abort(400)
  profile = session.query(User).where(User.id == id).first()
  if not profile: abort(404)
  if not profile.open: abort(403)
  connection = session.query(Connection).where((Connection.a == user.id) & (Connection.b == profile.id)).first()
  if connection: abort(403)
  code = random_128_bit_string()
  session.add(Connection(a=user.id, b=profile.id, code=code))
  session.commit()
  if profile.receive_connection_emails:
    sender = f"connections+{code}@co-founder.network"
    send_email(sender, profile.email, tr['connection_email_subject']%(user.name or user.email), render_template('emails/connection.html', tr=tr, user=user, message=request.form['message']), ','.join([sender, user.email]))
  return {'success': True}

@post('/pages/job-application/<id>')
def job_application(redirect, session, user, tr, id):
  if not user: abort(403)
  if len(request.form['message']) > 1000: abort(400)
  job = session.query(Job).where(Job.id == id).first()
  if not job: abort(404)
  if not job.active: abort(404)
  application = session.query(Application).where((Application.user_id == user.id) & (Application.job_id == job.id)).first()
  if application: abort(403)
  code = random_128_bit_string()
  session.add(Application(user_id=user.id, job_id=job.id, code=code))
  session.commit()
  if job.user.receive_application_emails:
    sender = f'applications+{code}@co-founder.network'
    send_email(sender, job.user.email, tr['application_email_subject']%(user.name or user.email), render_template('emails/application.html', tr=tr, user=user, message=request.form['message']), ','.join([sender, user.email]))
  return {'success': True}

@get('/pages/delete/<id>')
def delete(render_template, session, user, tr, id):
  if not user: return redirect('/')
  if not (user.admin or user.id == id): abort(403)
  profile = session.query(User).where(User.id == id).first()
  if not profile: abort(404)
  return render_template('delete.html', profile=profile)

@post('/pages/delete/<id>')
def delete(redirect, session, user, tr, id):
  if not user: return redirect('/')
  if not (user.admin or user.id == id): abort(403)
  profile = session.query(User).where(User.id == id).first()
  if not profile: abort(404)
  # TODO: do this with a lock
  while True:
    try:
      [profile] = session.query(User).where(User.id == profile.id)
      for view in profile.views:
        session.delete(view)
      for login_code in profile.login_codes:
        session.delete(login_code)
      for job in profile.jobs:
        for job_payment in job.payments:
          session.delete(job_payment)
        for application in job.applications:
          session.delete(application)
        session.delete(job)
      for connection in session.query(Connection).where((Connection.a == profile.id) | (Connection.b == profile.id)):
        session.delete(connection)
      for application in profile.applications:
        session.delete(application)
      session.delete(profile)
      session.commit()
      break
    except:
      sleep(1)
  return redirect('/', tr['your_account_was_deleted'])

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
  init_profile_for_render(session, user, profile)
  return render_template('profile.html', profile=profile)

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
