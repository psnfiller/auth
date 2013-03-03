import time
import hmac
import hashlib
import base64

import web
from web import form

urls = (
  '/', 'login',
  '/logout', 'logout',
)

render = web.template.render('templates/')

login_box = form.Form(
    form.Textbox('username'),
    form.Password('password'),
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
  
  
class login:
  def GET(self):
    if LoggedIn():
      _, username = GetSecureCookie('LoggedIn')
      return render.logged_in(username)
    else:
      f = login_box()
      return render.login(f)
   
  def POST(self): 
    f = login_box()
    if not f.validates(): 
      return render.login(form)
    # write cookie
    # write to db

    username = f['username'].value
    SetSecureCookie('LoggedIn', username, 60 * 60)
     
    return render.logged_in(username)

class logout:
  def GET(self):
    web.setcookie('LoggedIn', '', -1)
    return render.logout()

if __name__ == "__main__": 
    app = web.application(urls, globals())
    app.run()    
