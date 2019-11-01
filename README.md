# authproxy

This very simple microservice authenticates users with [the authentication server](https://github.com/liquidinvestigations/core) before proxying their requests.

It also sets some extra headers, cookies and fields required by some upstream services, like [if a user is an Admin or not](https://github.com/liquidinvestigations/authproxy/blob/b48ee7949f1c4e439194b7c17355be60570a6ddb/authproxy.py#L122).
