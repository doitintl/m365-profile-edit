from flask import Flask, redirect, url_for, session, request, render_template
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import os
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_PERMANENT"] = False
Session(app)
tenant_name = os.environ['TENANT_NAME']

def get_app_access_token(client_id, client_secret, tenant_name):
    token_url = f'https://login.microsoftonline.com/{tenant_name}/oauth2/v2.0/token'

    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }

    token_r = requests.post(token_url, data=token_data)
    token_r.raise_for_status()
    token_response = token_r.json()

    return token_response['access_token']

oauth = OAuth(app)
msgraph = oauth.register(
    'msgraph',
    client_id=os.environ['CLIENT_ID'],
    client_secret=os.environ['CLIENT_SECRET'],
    access_token_url='https://login.microsoftonline.com/' + tenant_name + '/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/' + tenant_name + '/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    server_metadata_url='https://login.microsoftonline.com/' + tenant_name + '/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'User.Read Directory.AccessAsUser.All'},
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
    user_data = msgraph.get('me').json()
    session['user_id'] = user_data['id']
    return redirect(url_for('profile'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        country = request.form.get('country')
        state = request.form.get('state')
        city = request.form.get('city')
        postalCode = request.form.get('postalCode')
        streetAddress = request.form.get('streetAddress')
        companyName = request.form.get('companyName')
        department = request.form.get('department')
        jobTitle = request.form.get('jobTitle')
        officeLocation = request.form.get('officeLocation')
        mobilePhone = request.form.get('mobilePhone')

        # Check if the user is trying to update their own profile
        if session['user_id'] != request.form.get('user_id'):
            return "Unauthorized: You can only update your own profile.", 403

        # Update the profile using the app-only access token
        access_token = get_app_access_token(os.environ['CLIENT_ID'], os.environ['CLIENT_SECRET'], os.environ['TENANT_NAME'])

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        data = {
            'country': country,
            'state': state,
            'city': city,
            'postalCode': postalCode,
            'streetAddress': streetAddress,
            'companyName': companyName,
            'department': department,
            'jobTitle': jobTitle,
            'officeLocation': officeLocation,
            'mobilePhone': mobilePhone
        }
        response = requests.patch(f'https://graph.microsoft.com/v1.0/users/{session["user_id"]}', headers=headers, json=data)
        response.raise_for_status()
        if response.status_code == 204:
            return redirect(url_for('profile'))
        else:
            return response.text
    user_data = msgraph.get('me?$select=id,displayName,mail,country,state,city,postalCode,streetAddress,companyName,department,jobTitle,officeLocation,mobilePhone', token=session['access_token']).json()

    return render_template('profile.html', user_data=user_data)

if __name__ == '__main__':
    app.run(debug=True, port="50000")
