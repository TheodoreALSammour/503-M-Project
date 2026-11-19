"""Web pages (Buyer & Seller frontend) and the Swagger UI.

Pages are static HTML shells; all data is loaded from the JSON API, which
enforces authorization. Hiding a button in the UI is NOT access control.
"""
import os

import swagger_ui_bundle
from flask import Blueprint, abort, current_app, send_from_directory

from ..policy import authorize

bp = Blueprint("pages", __name__)

PAGES = {
    "": "index.html",
    "login": "login.html",
    "register": "register.html",
    "cart": "cart.html",
    "orders": "orders.html",
    "seller": "seller.html",
    "account": "account.html",
}
SWAGGER_ASSETS = {"swagger-ui.css", "swagger-ui-bundle.js", "swagger-ui-standalone-preset.js",
                  "favicon-32x32.png", "favicon-16x16.png"}


def _pages_dir():
    return os.path.join(current_app.static_folder, "pages")


@bp.get("/", defaults={"page": ""})
@bp.get("/<any(login, register, cart, orders, seller, account):page>")
@authorize("page.view")
def page(page):
    return send_from_directory(_pages_dir(), PAGES[page], max_age=0)


@bp.get("/api/docs")
@authorize("docs.view")
def swagger_ui():
    return send_from_directory(_pages_dir(), "docs.html", max_age=0)


@bp.get("/api/docs/assets/<name>")
@authorize("docs.view")
def swagger_asset(name):
    if name not in SWAGGER_ASSETS:  # allow-list: no path traversal possible
        abort(404)
    return send_from_directory(swagger_ui_bundle.swagger_ui_path, name)


@bp.get("/api/openapi.yaml")
@authorize("docs.view")
def openapi_spec():
    return send_from_directory(os.path.dirname(os.path.dirname(__file__)), "openapi.yaml",
                               mimetype="application/yaml", max_age=0)
