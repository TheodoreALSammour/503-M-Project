"""Every endpoint is documented in OpenAPI and the docs are served."""
import os
import re

import yaml


def _spec():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "openapi.yaml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _flask_to_openapi(rule):
    rule = re.sub(r"<(?:int:|path:)?(\w+)>", r"{\1}", rule)
    return rule


def test_every_route_documented(app):
    paths = _spec()["paths"]
    missing = []
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/<any("):
            names = re.search(r"any\(([^)]*)\)", rule.rule).group(1).replace(" ", "").split(",")
            candidates = ["/" + n for n in names]
        elif rule.endpoint == "static":
            candidates = ["/static/{path}"]
        else:
            candidates = [_flask_to_openapi(rule.rule)]
        for path in candidates:
            methods = {m.lower() for m in rule.methods} - {"head", "options"}
            documented = set(paths.get(path, {}))
            if not methods <= documented:
                missing.append((path, methods - documented))
    assert missing == []


def test_docs_served(client):
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.yaml").status_code == 200
    assert client.get("/api/docs/assets/swagger-ui-bundle.js").status_code == 200
    assert client.get("/api/docs/assets/..%2f..%2fapp%2fconfig.py").status_code == 404


def test_pages_served(client):
    for p in ["/", "/login", "/register", "/cart", "/orders", "/seller", "/account", "/static/js/common.js"]:
        assert client.get(p).status_code == 200, p
