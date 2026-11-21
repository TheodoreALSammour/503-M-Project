"""Public catalog: anyone (including visitors) can browse/search Published products."""
from flask import Blueprint, abort, jsonify, request

from ..extensions import db
from ..models import AccountStatus, Product, ProductStatus, User
from ..policy import authorize, is_allowed
from ..validation import ValidationError
from . import paginate

bp = Blueprint("catalog", __name__, url_prefix="/api")


def _escape_like(term):
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@bp.get("/products")
@authorize("catalog.browse")
def list_products():
    q = request.args.get("q", "").strip()
    if len(q) > 100:
        raise ValidationError("Search term too long.", field="q")
    # Products of suspended sellers are hidden (they cannot be bought either).
    query = Product.query.filter(Product.status == ProductStatus.PUBLISHED,
                                 Product.seller.has(User.status == AccountStatus.ACTIVE))
    if q:
        # Parameterised LIKE via the ORM (no SQL injection); wildcards escaped.
        pattern = f"%{_escape_like(q)}%"
        query = query.filter(db.or_(Product.name.ilike(pattern, escape="\\"),
                                    Product.description.ilike(pattern, escape="\\")))
    query = query.order_by(Product.id.desc())
    rows, meta = paginate(query)
    return jsonify(products=[p.to_public() for p in rows], **meta)


@bp.get("/products/<int:product_id>")
@authorize("catalog.view")
def get_product(product_id):
    p = db.session.get(Product, product_id)
    if p is None:
        abort(404)
    if p.status != ProductStatus.PUBLISHED:
        # Drafts are only visible to their seller (P1). Others get 404 so the
        # existence of a draft is not revealed.
        if not is_allowed("product.view_own", p):
            abort(404)
        return jsonify(product=p.to_public(include_private=True))
    if p.seller is None or p.seller.status != AccountStatus.ACTIVE:
        abort(404)  # seller suspended: hidden like a non-existent product
    return jsonify(product=p.to_public())
