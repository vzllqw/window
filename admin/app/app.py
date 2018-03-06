from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, IPAddress
# from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from haproxyadmin import haproxy    
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address,get_ipaddr
USERNAME='INPUTUSER'
PASSWORD='INPUTPASSWD'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'kdsdfsdgpanPan!'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////mnt/c/Users/antho/Documents/login-example/database.db'
bootstrap = Bootstrap(app)
csrf = CSRFProtect(app)

# db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



# class User(UserMixin, db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # username = db.Column(db.String(15), unique=True)
    # email = db.Column(db.String(50), unique=True)
    # password = db.Column(db.String(80))
    
# @login_manager.user_loader
# def load_user(user_id):
    # return User.query.get(int(user_id))
limiter = Limiter(
    app,
    key_func=get_ipaddr,
    default_limits=["200 per day", "50 per hour"]
)

import re
 
def ipFormatChk(ip_str):
   pattern = r"\b^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)((?:/(?:32|31|30|29|28|27|26|25|24|23|22|21|20))?)$\b"
   if re.match(pattern, ip_str):
      return True
   else:
      return False
      
    
class User():
  username=USERNAME
  def is_active():
    return True
  def get_id():
    return 0
  def is_authenticated():
    return True 
    
@login_manager.user_loader
def load_user(user_id):
  return User;
    
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
def getOut():
    try:
      logout_user()
    except:
      pass
    return redirect(url_for('login'))

@app.route('/')
def index():
    # return render_template('index.html')
    return redirect(url_for('login'))

@limiter.limit("50/hour;20/minute;500/day",error_message=lambda : 'DENY ACCESS')
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # user = User.query.filter_by(username=form.username.data).first()
        # if user:
            # if check_password_hash(user.password, form.password.data):
        if USERNAME == form.username.data and PASSWORD == form.password.data:
          login_user(User, remember=form.remember.data)
          return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
    # form = RegisterForm()

    # if form.validate_on_submit():
        # hashed_password = generate_password_hash(form.password.data, method='sha256')
        # new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        # db.session.add(new_user)
        # db.session.commit()

        # return '<h1>New user has been created!</h1>'
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    # return render_template('signup.html', form=form)


def get_x_ip():
  if request.headers.getlist("X-Forwarded-For"):
   ip = request.headers.getlist("X-Forwarded-For")[0]
  else:
    ip=request.remote_addr
  return ip

@app.route('/dashboard')
@login_required
def dashboard():
  ip=get_x_ip()
  hap=haproxy.HAProxy(socket_dir='/var/run/',socket_file='haproxy.sock')
  acls=[ x.split()[1] for x in hap.show_acl(0) ]
  #hap.add_acl(0,'111.47.27.238/32')   ##ref: http://haproxyadmin.readthedocs.io/en/latest/user/haproxy.html?highlight=acl
  return render_template('dashboard.html', name=current_user.username, user_ip=ip, acls=acls)
  
@app.route('/delete',methods=['POST'])
@login_required
def del_ip():
  if 'ipaddress' in request.form and request.form['ipaddress']:
    ip=request.form['ipaddress'].strip()
    if ipFormatChk(ip):
      hap=haproxy.HAProxy(socket_dir='/var/run/',socket_file='haproxy.sock')
      for x in hap.show_acl(0):
        if x.split()[1] == ip :
          hap.del_acl(0,ip)
          return redirect(url_for('dashboard'))
  return redirect(url_for('dashboard'))

@app.route('/add',methods=['POST'])
@login_required
def add_ip():
  if not 'ipaddress' in request.form or not request.form['ipaddress']:
    ip=get_x_ip()
  else:
    ip=request.form['ipaddress']
  ip=ip.strip()
  if ipFormatChk(ip):
    hap=haproxy.HAProxy(socket_dir='/var/run/',socket_file='haproxy.sock')
    acls=[ x.split()[1] for x in hap.show_acl(0) ]
    if not ip in acls:
      hap.add_acl(0,ip)
  return redirect(url_for('dashboard'))
  
  
@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('dashboard'))


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return getOut()

@app.errorhandler(404)
def page_not_found(e):
  return getOut()

@app.errorhandler(500)
def page_not_found(e):
  return getOut()




if __name__ == '__main__':    
    app.run(debug=False,host="0.0.0.0",port=8888)

