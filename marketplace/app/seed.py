"""Seed script - creates the demo dataset (idempotent: runs only on an empty DB).

Accounts, passwords and coupon codes are listed in the README. They are demo
credentials for a local test system; the default admin MUST change its email
and password at first login before doing anything else.
"""
from datetime import timedelta

from .auth import hash_password
from .extensions import db
from .models import (Coupon, CouponType, Product, ProductStatus, Role, SellerProfile, SellerStatus, User,
                     utcnow)

ADMIN = ("System Admin", "admin@marketplace.local", "+961 1 000000", "ChangeMe#Default2026")
FINANCE = [
    ("Fiona Finance", "finance1@marketplace.local", "+961 1 111111", "Finance#One2026"),
    ("Farid Finance", "finance2@marketplace.local", "+961 1 222222", "Finance#Two2026"),
]
BUYERS = [
    ("Alice Buyer", "alice@example.com", "+961 3 100100", "Market#Buyer2026"),
    ("Bob Buyer", "bob@example.com", "+961 3 200200", "Market#Buyer2027"),
]
SELLERS = [
    # (name, email, phone, password, store, verification)
    ("Sam Verified", "sam@example.com", "+961 3 300300", "Market#Seller2026", "Sam's Gadgets", SellerStatus.VERIFIED),
    ("Vera Verified", "vera@example.com", "+961 3 400400", "Market#Seller2027", "Vera's Books", SellerStatus.VERIFIED),
    ("Uma Unverified", "uma@example.com", "+961 3 500500", "Market#Seller2028", "Uma's Crafts", SellerStatus.UNVERIFIED),
]
SUSPENDED = ("Sid Suspended", "suspended@example.com", "+961 3 600600", "Market#Buyer2029")


def _user(name, email, phone, password, roles, **kw):
    u = User(full_name=name, email=email, phone=phone, password_hash=hash_password(password), **kw)
    for r in roles:
        u.add_role(r)
    db.session.add(u)
    return u


def seed():
    if User.query.first() is not None:
        print("seed: database already contains data - skipping")
        return

    _user(*ADMIN, roles=[Role.ADMIN], must_change_credentials=True)
    for f in FINANCE:
        _user(*f, roles=[Role.FINANCE])
    for b in BUYERS:
        _user(*b, roles=[Role.BUYER])
    _user(*SUSPENDED, roles=[Role.BUYER], status="suspended")

    sellers = {}
    for name, email, phone, pw, store, status in SELLERS:
        u = _user(name, email, phone, pw, roles=[Role.BUYER, Role.SELLER])
        u.seller_profile = SellerProfile(store_name=store, verification_status=status,
                                         verified_at=utcnow() if status == SellerStatus.VERIFIED else None)
        sellers[email] = u
    db.session.flush()

    P, D = ProductStatus.PUBLISHED, ProductStatus.DRAFT
    products = [
        ("sam@example.com", "Wireless Mouse", "Ergonomic 2.4 GHz wireless mouse.", 2499, 50, P),
        ("sam@example.com", "Mechanical Keyboard", "Hot-swappable switches, RGB.", 8999, 20, P),
        ("sam@example.com", "USB-C Cable", "1 m braided USB-C cable.", 999, 200, P),
        ("sam@example.com", "Last-One Lamp", "Only one in stock - use it to test race conditions.", 4500, 1, P),
        ("sam@example.com", "Prototype Drone", "Draft product - not visible to buyers.", 29900, 5, D),
        ("vera@example.com", "Security Engineering (book)", "Classic textbook.", 5999, 10, P),
        ("vera@example.com", "Cryptography Notebook", "Dotted A5 notebook.", 1250, 30, P),
        ("vera@example.com", "Twenty Cent Sticker", "Use with ROUND125 to see half-up rounding.", 20, 100, P),
        ("uma@example.com", "Handmade Vase", "Unverified seller - can only keep drafts.", 3500, 3, D),
    ]
    for email, name, desc, price, stock, status in products:
        db.session.add(Product(seller_id=sellers[email].id, name=name, description=desc,
                               price_cents=price, stock=stock, status=status))

    now = utcnow()
    year = timedelta(days=365)
    coupons = [
        ("WELCOME10", CouponType.PERCENTAGE, 1000, None, now - timedelta(days=1), now + year, 1000),
        ("SAVE5", CouponType.FIXED, None, 500, now - timedelta(days=1), now + year, 1000),
        ("BIGFIXED100", CouponType.FIXED, None, 10000, now - timedelta(days=1), now + year, 1000),
        ("ROUND125", CouponType.PERCENTAGE, 1250, None, now - timedelta(days=1), now + year, 1000),
        ("SINGLEUSE50", CouponType.PERCENTAGE, 5000, None, now - timedelta(days=1), now + year, 1),
        ("EXPIRED20", CouponType.PERCENTAGE, 2000, None, now - timedelta(days=60), now - timedelta(days=30), 1000),
        ("FUTURE15", CouponType.PERCENTAGE, 1500, None, now + timedelta(days=30), now + year, 1000),
    ]
    for code, kind, bp, amount, start, end, max_uses in coupons:
        db.session.add(Coupon(code=code, kind=kind, percent_bp=bp, amount_cents=amount,
                              valid_from=start, valid_until=end, max_uses=max_uses, used_count=0))
    db.session.commit()
    print("seed: demo data created (see README for accounts and coupon codes)")
