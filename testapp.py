#!/usr/bin/env python3

import flask

app = flask.Flask(__name__)


@app.route('/')
def home():
    return f"Hello, {flask.request.headers['X-Forwarded-User']}"


if __name__ == '__main__':
    import waitress
    waitress.serve(app, host='0.0.0.0', port=5000)
