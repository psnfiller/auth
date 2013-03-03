#!/usr/bin/python2.6
import time
import hmac
import hashlib
import base64

import web
from web import form

urls = (
  '/auth/', 'login',
  '/auth/logout', 'logout',
)

render = web.template.render('templates/')

login_box = form.Form(
    form.Textbox('username'),
    form.Password('password'),
    form.Hidden('token'),
)

logout_box = form.Form(
    form.Hidden('token'),
    form.Button('button'),
)


KEY='65656565fgfdhghg65'
def LoggedIn():
  state, data = GetSecureCookie('LoggedIn')
  return  state

def GenerateCookieSig(*parts):
  output = hmac.new(KEY, digestmod=hashlib.sha1)
  for part in parts:
    output.update(str(part))
  return output.hexdigest()



def SetSecureCookie(name, value, expires, **kwargs):
  timestamp = str(int(time.time()))

  value = base64.b64encode(value)
  sig = GenerateCookieSig(name, value, timestamp, expires)
  value = '|'.join((name, value, timestamp, str(expires), sig))
  web.setcookie(name, value, expires=expires, **kwargs)

def GetSecureCookie(name):
  data = web.cookies().get(name)
  if data is None:
    return False, 'no cookie'
  d = data.split('|')
  if len(d) != 5:
    return False, 'malformed cookie'
  name, value, timestamp, expires, sig = d
  if sig != GenerateCookieSig(name, value, timestamp, expires):
    return False, 'invalid sig'
  if int(timestamp) + int(expires) < time.time():
    return False, 'cookie expired'
  return True, base64.b64decode(value)


def GetLoginToken():
  ip = web.ctx.ip
  timestamp = str(int(time.time())) 
  sig = GenerateCookieSig(ip, timestamp)
  value = '|'.join((ip, timestamp, sig))
  return value

class login:
  
  def GET(self):
    if LoggedIn():
      _, username = GetSecureCookie('LoggedIn')
      return render.logged_in(username)
    else:

      return render.login(True, GetLoginToken())

  def POST(self):
    f = login_box()
    if not f.validates():
      return render.login(form, GetLoginToken())

    value = f['token'].value
    username = f['username'].value
    if username == None or value == None:
      return render.login(form, GetLoginToken())
    value = value.split('|')
    if len(value) != 3:
      return render.login(form, GetLoginToken())
    ip, timestamp, sig = value
    if ip != web.ctx.ip:
      return render.login(form, GetLoginToken())
    timestamp = int(timestamp)
    if timestamp + 2 * 60 < time.time():
      return render.login(form, GetLoginToken())
    if sig != GenerateCookieSig(ip, timestamp):
      return render.login(form, GetLoginToken())
    
    SetSecureCookie('LoggedIn', username, 60 * 60)

    return render.logged_in(username)

class logout:
  def GET(self):
    f = logout_box()
    f['token'].value = GetLoginToken()
    return render.logout_page(f)
  
  def POST(self):
    web.setcookie('LoggedIn', '', -1)
    return render.logout()

app = web.application(urls, globals())
web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)
if __name__ == "__main__":
    app.run()
