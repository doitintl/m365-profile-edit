from flask import Flask, redirect, url_for, session, request, render_template
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import requests
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_PERMANENT"] = False
Session(app)

tenant_name = 'doitintl.onmicrosoft.com'

oauth = OAuth(app)
msgraph = oauth.register(
    'msgraph',
    client_id=os.environ['CLIENT_ID'],
    client_secret=os.environ['CLIENT_SECRET'],
    access_token_url='https://login.microsoftonline.com/'+ tenant_name +'/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/'+ tenant_name +'/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    server_metadata_url='https://login.microsoftonline.com/'+ tenant_name +'/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'User.Read User.ReadWrite Directory.AccessAsUser.All'},
)

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return msgraph.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    session['access_token'] = msgraph.authorize_access_token()    
    return redirect(url_for('profile'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        phone = request.form.get('phone')
        city = request.form.get('city')

        data = {
            'mobilePhone': phone,
            'city': city
        }
        headers = {
            'Authorization': f"Bearer {session['access_token']}",
            'Content-Type': 'application/json'
        }

        resp = msgraph.patch(f'me', json=data, headers=headers, token=session['access_token'])
        if resp.status_code == 204:
            return redirect(url_for('profile'))
        else:
            return resp.status_code
    user_data = msgraph.get('me?$select=displayName,mail,city,mobilePhone', token=session['access_token']).json()

    return render_template('profile.html', user_data=user_data)

if __name__ == '__main__':
    app.run(debug=True, port="50000")
