import http
import threading
import urllib

from http.server import BaseHTTPRequestHandler

import pytest
import responses

from authproxy import app

CONFIG_VARS = {
    'DEBUG': 'DEBUG',
    'LIQUID_CLIENT_ID': 'LIQUID_CLIENT_ID',
    'LIQUID_CLIENT_SECRET': 'LIQUID_CLIENT_SECRET',
    'SECRET_KEY': 'SECRET_KEY',
    'LIQUID_PUBLIC_URL': 'http://liquid_public_url',
    'CONSUL_URL': 'http://consul_url',
    'LIQUID_CORE_SERVICE': 'liquid_core_service',
    'UPSTREAM_SERVICE': 'upstream_service',
}


class handler_class(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('charset', 'utf-8')
        self.end_headers()
        self.wfile.write(urllib.parse.unquote(self.path).encode('utf-8'))
        return


@pytest.fixture
def http_server():
    handler = handler_class
    httpd = http.server.HTTPServer(('', 8000), handler)
    http_thread = threading.Thread(target=httpd.serve_forever)
    http_thread.start()
    yield
    httpd.shutdown()
    http_thread.join()


@responses.activate
def test_special_characters(http_server):
    app.config.update(CONFIG_VARS)

    mock_requests()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['access_token'] = 'access_token'

        rv = client.get('/Überraschung')
        assert rv.data == bytes('/Überraschung', 'utf-8')


def mock_requests():
    liquid_core = app.config['LIQUID_CORE_SERVICE']
    upstream = app.config['UPSTREAM_SERVICE']

    liquid_core_id = 1
    upstream_id = 2

    profile_domain = 'get_profile'
    profile_port = 80
    profile_host = f'{profile_domain}:{profile_port}'

    mock_health_check_request(liquid_core, [{'ServiceID': liquid_core_id, 'Status': 'passing'}])

    mock_health_check_request(upstream, [{'ServiceID': upstream_id, 'Status': 'passing'}])

    mock_catalog_service_request(liquid_core, [{
        'ServiceID': liquid_core_id,
        'ServiceAddress': profile_domain,
        'ServicePort': profile_port,
    }])

    mock_catalog_service_request(upstream, [{
        'ServiceID': upstream_id,
        'ServiceAddress': 'localhost',
        'ServicePort': 8000,
    }])

    mock_accounts_request(profile_host, {
        'login': 'test',
        'name': 'test',
        'email': 'test@test.com',
        'is_admin': False,
    })


def mock_health_check_request(service_name, payload):
    url = f'{app.config["CONSUL_URL"]}/v1/health/checks/{service_name}'
    responses.add(responses.GET, url, json=payload)


def mock_catalog_service_request(service_name, payload):
    url = f'{app.config["CONSUL_URL"]}/v1/catalog/service/{service_name}'
    responses.add(responses.GET, url, json=payload)


def mock_accounts_request(host, payload):
    url = f'http://{host}/accounts/profile'
    responses.add(responses.GET, url, json=payload)
