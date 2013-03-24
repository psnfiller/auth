#!/usr/bin/python2.6
#
# This code as a few crsf holes.

import os
import time
import hmac
import hashlib
import base64

import web
from web import form

urls = (
  '/', 'go',
  '/insecure_auth/', 'login',
  '/insecure_auth/logout', 'logout',
)

render = web.template.render('templates/insecure/')

login_box = form.Form(
    form.Textbox('username'),
    form.Password('password'),
)

logout_box = form.Form(
    form.Button('button'),
)


KEY='45454543djfdjfsdkjfsdjkfsd'
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
  web.setcookie(name, value, expires=expires, secure=True, httponly=True, **kwargs)

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

class login:
  
  def GET(self):
    if LoggedIn():
      _, username = GetSecureCookie('LoggedIn')
      return render.logged_in(username)
    else:

      return render.login(True)

  def POST(self):
    f = login_box()
    if not f.validates():
      return render.login(form)
    
    username = f['username'].value
    if username == None: 
      return render.login(form)
    SetSecureCookie('LoggedIn', username, 60 * 60)
    return render.logged_in(username)

class logout:
  def GET(self):
    f = logout_box()
    return render.logout_page(f)
  
  def POST(self):
    web.setcookie('LoggedIn', '', -1)
    return render.logout()

class go:
  def GET(self):
    return render.redirect()

app = web.application(urls, globals())
if __name__ == "__main__":
  if not os.environ.get('test'):
    web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)
  app.run()
