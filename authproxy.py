#!/usr/bin/env python3

import logging
import os
import random

from paste.proxy import Proxy
from werkzeug.middleware.proxy_fix import ProxyFix
import flask
import requests

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

app = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

CONFIG_VARS = [
    'DEBUG',
    'LIQUID_CLIENT_ID',
    'LIQUID_CLIENT_SECRET',
    'SECRET_KEY',
    'LIQUID_PUBLIC_URL',
    'CONSUL_URL',
    'LIQUID_CORE_SERVICE',
    'UPSTREAM_SERVICE',
]

config = app.config
for name in CONFIG_VARS:
    config[name] = os.environ[name]

config['USER_HEADER_TEMPLATE'] = os.environ.get('USER_HEADER_TEMPLATE')
config['THREADS'] = os.environ.get('THREADS', '4')

config['SESSION_COOKIE_NAME'] = \
    os.environ.get('SESSION_COOKIE_NAME', 'authproxy.session')


class ProxyUTF8(Proxy):
    def __call__(self, environ, start_response):
        path_info = environ['PATH_INFO']
        decoded_path_info = bytes(path_info, 'latin-1')
        environ['PATH_INFO'] = str(decoded_path_info, 'utf-8')
        return super(ProxyUTF8, self).__call__(environ, start_response)


class ServiceMissing(RuntimeError):
    pass


def consul(url):
    return requests.get(f"{config['CONSUL_URL']}{url}").json()


def consul_service(name):
    health = {
        node['ServiceID']: node['Status']
        for node in consul(f"/v1//health/checks/{name}")
    }

    passing = []
    for node in consul(f"/v1/catalog/service/{name}"):
        if health[node['ServiceID']] == 'passing':
            passing.append(f"{node['ServiceAddress']}:{node['ServicePort']}")

    if passing:
        return random.choice(passing)

    raise ServiceMissing(name)


def get_upstream():
    name = config['UPSTREAM_SERVICE']

    try:
        address = consul_service(name)

    except ServiceMissing:
        log.warn("No upstream service {name!r} found in consul!")
        return "Authproxy 502: Application is not ready.", 502

    return ProxyUTF8(f"http://{address}")


def get_oauth_server():
    return f"http://{consul_service(config['LIQUID_CORE_SERVICE'])}"


def get_profile():
    access_token = flask.session.get('access_token')
    if not access_token:
        log.warning('auth fail - no access token')
        flask.session.pop('access_token', None)
        return None

    profile_url = get_oauth_server() + '/accounts/profile'
    profile_resp = requests.get(profile_url, headers={
        'Authorization': 'Bearer {}'.format(flask.session['access_token']),
    })

    if profile_resp.status_code != 200:
        log.warning('auth fail - profile response: %r', profile_resp)
        flask.session.pop('access_token', None)
        return None

    profile = profile_resp.json()
    if not profile:
        log.warning('auth fail - empty profile: %r', profile)
        flask.session.pop('access_token', None)
        return None

    return profile


@app.before_request
def dispatch():
    if not flask.request.path.startswith('/__auth/'):
        profile = get_profile()
        if not profile:
            flask.session['next'] = flask.request.url
            return flask.redirect('/__auth/')

        USER_HEADER_TEMPLATE = config.get('USER_HEADER_TEMPLATE')
        if USER_HEADER_TEMPLATE:
            uservalue = USER_HEADER_TEMPLATE.format(profile['login'])
            flask.request.environ['HTTP_X_FORWARDED_USER'] = uservalue
            flask.request.environ['HTTP_X_FORWARDED_USER_FULL_NAME'] = profile['name'].encode('utf8')
            flask.request.environ['HTTP_X_FORWARDED_USER_EMAIL'] = profile['email']
            flask.request.environ['HTTP_X_FORWARDED_USER_ADMIN'] = str(profile['is_admin']).lower()

        return get_upstream()


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
        get_oauth_server() + '/o/token/',
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
    return flask.redirect(flask.session.get('next', '/'))


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
        logout_url = get_oauth_server() + '/accounts/logout/'
        headers = {'Authorization': f'Bearer {access_token}'}
        logout_resp = requests.get(logout_url, headers=headers)
    return LOGGED_OUT


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    reload_code = False

    log.info(f"Authproxy for {config['UPSTREAM_SERVICE']} starting")
    if reload_code:
        app.run(host='0.0.0.0')

    else:
        import waitress
        waitress.serve(app, host='0.0.0.0', port=5000, threads=int(config['THREADS']))
