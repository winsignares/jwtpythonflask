import datetime
from flask import Flask, request, jsonify, session,\
     render_template, make_response
from functools import wraps

from flask.helpers import make_response
import jwt
from flask.templating import render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = "pruebaToken"
token = ""

def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'mensaje':'Necesitas el Token'}), 403
        try:
            data= jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'mensaje':'Invalido el Token'}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route('/public')
def public():
    return 'Anyone can view this'



@app.route('/login',methods=['POST'])
def login():
    if request.form['username'] and request.form['password']=='password':
        session['logged_in'] = True
        token = jwt.encode({
            'user': request.form['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
        },
        app.config['SECRET_KEY'])
        #return jsonify({'token': jwt.decode(token,app.config['SECRET_KEY'], algorithms="HS256")})
        if token :
            session['token'] = token
            request.args.get('token',token)
            return jsonify({'token': token})
        else:
            return "jsonify({'token': token})"
    else:
        return make_response('imposible verificar',403,{'www-Authenticate': 'Basic realm: "login..."'})

@app.route('/auth')
#@check_for_token
def authorised():
    if  session.get('token'):
        return "Autorizado"
    else:
        return 'Esta pagina solo es visible teniendo un token'

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Currently logged in'

@app.route('/salir')
def salir():
    if session.get('logged_in'):
        session.clear()
        return index()

if __name__ == '__main__':
    port = 3000
    host = "localhost"
    app.run(host=host, port=port,debug=True)
  