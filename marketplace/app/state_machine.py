"""Order state machine - the ONLY place where order status changes.

    checkout --(gateway approves)--> paid
    checkout --(gateway declines)--> failed      (stock and coupon unchanged)
    paid     --(seller + tracking)--> shipped
    shipped  --(buyer confirms)----> delivered

``checkout`` is the transient state of a checkout request in progress; it is
never persisted (there is no pending state). Transitions are applied with a
conditional ``UPDATE ... WHERE status = <from>`` so a step can never be
repeated or skipped, even by two concurrent requests.
"""
from sqlalchemy import update

from .audit import audit
from .extensions import db
from .models import Order, utcnow


class OrderStatus:
    CHECKOUT = "checkout"
    PAID = "paid"
    FAILED = "failed"
    SHIPPED = "shipped"
    DELIVERED = "delivered"


class Trigger:
    GATEWAY = "gateway"
    SELLER = "seller"
    BUYER = "buyer"


TRANSITIONS = {
    (OrderStatus.CHECKOUT, OrderStatus.PAID): Trigger.GATEWAY,
    (OrderStatus.CHECKOUT, OrderStatus.FAILED): Trigger.GATEWAY,
    (OrderStatus.PAID, OrderStatus.SHIPPED): Trigger.SELLER,
    (OrderStatus.SHIPPED, OrderStatus.DELIVERED): Trigger.BUYER,
}


class InvalidTransition(Exception):
    pass


def is_allowed(from_status, to_status, trigger):
    return TRANSITIONS.get((from_status, to_status)) == trigger


def source_state_for(to_status, trigger):
    for (frm, to), trg in TRANSITIONS.items():
        if to == to_status and trg == trigger:
            return frm
    return None


def record_checkout_outcome(order, to_status):
    """Called for the creation of an order from the transient checkout state."""
    if not is_allowed(OrderStatus.CHECKOUT, to_status, Trigger.GATEWAY):
        raise InvalidTransition(f"checkout -> {to_status} not allowed")
    order.status = to_status
    audit("order.state_change", order_id=order.id, from_status=OrderStatus.CHECKOUT,
          to_status=to_status, trigger=Trigger.GATEWAY)


def transition(order, to_status, trigger, **changes):
    """Atomically move ``order`` to ``to_status``. Raises InvalidTransition if
    the state machine does not allow it from the order's *current* DB state."""
    from_status = order.status
    if not is_allowed(from_status, to_status, trigger):
        audit("order.transition_rejected", order_id=order.id, from_status=from_status,
              to_status=to_status, trigger=trigger)
        raise InvalidTransition(f"{from_status} -> {to_status} is not allowed")
    values = {"status": to_status, "updated_at": utcnow(), **changes}
    result = db.session.execute(
        update(Order).where(Order.id == order.id, Order.status == from_status).values(**values)
    )
    if result.rowcount != 1:
        db.session.rollback()
        audit("order.transition_rejected", order_id=order.id, from_status=from_status,
              to_status=to_status, trigger=trigger, reason="concurrent_change")
        raise InvalidTransition("order state changed concurrently")
    db.session.commit()
    db.session.refresh(order)
    audit("order.state_change", order_id=order.id, from_status=from_status, to_status=to_status,
          trigger=trigger, **{k: v for k, v in changes.items() if k == "tracking_number"})
    return order
