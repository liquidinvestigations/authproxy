#!/usr/bin/env python3

import os
import logging
import requests
from paste.proxy import Proxy
from werkzeug.middleware.proxy_fix import ProxyFix
import flask

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

app = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

CONFIG_VARS = [
    'DEBUG',
    'LIQUID_CLIENT_ID',
    'LIQUID_CLIENT_SECRET',
    'SECRET_KEY',
    'UPSTREAM_APP_URL',
    'LIQUID_PUBLIC_URL',
    'LIQUID_INTERNAL_URL',
]

config = app.config
for name in CONFIG_VARS:
    config[name] = os.environ[name]

config['USER_HEADER_TEMPLATE'] = os.environ.get('USER_HEADER_TEMPLATE')

upstream = Proxy(config['UPSTREAM_APP_URL'])


def get_profile():
    access_token = flask.session.get('access_token')
    if not access_token:
        log.warn('auth fail - no access token')
        flask.session.pop('access_token', None)
        return None

    profile_url = config['LIQUID_INTERNAL_URL'] + '/accounts/profile'
    profile_resp = requests.get(profile_url, headers={
        'Authorization': 'Bearer {}'.format(flask.session['access_token']),
    })

    if profile_resp.status_code != 200:
        log.warn('auth fail - profile response: %r', profile_resp)
        flask.session.pop('access_token', None)
        return None

    profile = profile_resp.json()
    if not profile:
        log.warn('auth fail - empty profile: %r', profile)
        flask.session.pop('access_token', None)
        return None

    return profile


@app.before_request
def dispatch():
    if not flask.request.path.startswith('/__auth/'):
        profile = get_profile()
        if not profile:
            return flask.redirect('/__auth/')

        USER_HEADER_TEMPLATE = config.get('USER_HEADER_TEMPLATE')
        if USER_HEADER_TEMPLATE:
            uservalue = USER_HEADER_TEMPLATE.format(profile['login'])
            flask.request.environ['HTTP_X_FORWARDED_USER'] = uservalue
            flask.request.environ['HTTP_X_FORWARDED_USER_FULL_NAME'] = profile['name'].encode('utf8')
            flask.request.environ['HTTP_X_FORWARDED_USER_EMAIL'] = profile['email']
            flask.request.environ['HTTP_X_FORWARDED_USER_ADMIN'] = str(profile['is_admin']).lower()

        return upstream


@app.route('/__auth/')
def login():
    authorize_url = (
        '{}/o/authorize/?response_type=code&client_id={}'
        .format(config['LIQUID_PUBLIC_URL'], config['LIQUID_CLIENT_ID'])
    )
    log.info("oauth - redirecting to authorize url = %r", authorize_url)
    return flask.redirect(authorize_url)


@app.route('/__auth/callback')
def callback():
    redirect_uri = flask.request.base_url
    log.info("oauth - getting token, redirect_uri = %r", redirect_uri)
    token_resp = requests.post(
        config['LIQUID_INTERNAL_URL'] + '/o/token/',
        data={
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
            'code': flask.request.args['code'],
        },
        auth=(config['LIQUID_CLIENT_ID'], config['LIQUID_CLIENT_SECRET']),
    )
    if token_resp.status_code != 200:
        raise RuntimeError("Could not get token: {!r}".format(token_resp))

    token_data = token_resp.json()
    token_type = token_data['token_type']
    if token_type != 'Bearer':
        raise RuntimeError(
            "Expected token_type='Bearer', got {!r}"
            .format(token_type)
        )

    flask.session['access_token'] = token_data['access_token']
    return flask.redirect('/')


@app.route('/__auth/token')
def get_token():
    profile = get_profile()
    if not profile:
        flask.abort(401)
    return flask.jsonify({
        'username': profile['login'],
        'access_token': flask.session['access_token'],
    })


LOGGED_OUT = """\
<!doctype html>
<p>You have been logged out.</p>
<p><a href="/">home</a></p>
"""


@app.route('/__auth/logout')
def logout():
    access_token = flask.session.get('access_token', None)
    if access_token:
        logout_url = config['LIQUID_INTERNAL_URL'] + '/accounts/logout/'
        headers = {'Authorization': f'Bearer {access_token}'}
        logout_resp = requests.get(logout_url, headers=headers)
    return LOGGED_OUT


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    reload_code = False

    if reload_code:
        app.run(host='0.0.0.0')

    else:
        import waitress
        waitress.serve(app, host='0.0.0.0', port=5000)
