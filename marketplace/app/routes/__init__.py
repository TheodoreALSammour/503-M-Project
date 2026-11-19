from flask import g, request

from ..validation import query_int


def current_user():
    return g.user


def paginate(query, *, default_per_page=20, max_per_page=100):
    page = query_int("page", 1, min_value=1, max_value=100000)
    per_page = query_int("per_page", default_per_page, min_value=1, max_value=max_per_page)
    total = query.order_by(None).count()
    rows = query.limit(per_page).offset((page - 1) * per_page).all()
    return rows, {"page": page, "per_page": per_page, "total": total}


def arg_choice(name, choices):
    value = request.args.get(name)
    if value in (None, ""):
        return None
    if value not in choices:
        from ..validation import ValidationError
        raise ValidationError(f"Query parameter '{name}' must be one of: {', '.join(sorted(choices))}.",
                              field=name)
    return value
