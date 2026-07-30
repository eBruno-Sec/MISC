from __future__ import annotations

from uuid import uuid4

from packages.events import (
    DeliveryStatus,
    EventSubscription,
    InMemoryOutbox,
    OutboxRelay,
    create_outbox_entry,
)


def test_create_outbox_entry():
    tid = uuid4()
    entry = create_outbox_entry("action.proposed", tid, "action", uuid4(), {"technique": "bola"})
    assert entry.event_type == "action.proposed"
    assert entry.tenant_id == tid
    assert entry.status == DeliveryStatus.PENDING
    assert entry.payload["technique"] == "bola"


def test_inmemory_outbox_write_and_get_pending():
    outbox = InMemoryOutbox()
    entry = create_outbox_entry("test.event", uuid4(), "test", uuid4())
    outbox.write(entry)
    pending = outbox.get_pending()
    assert len(pending) == 1
    assert pending[0].entry_id == entry.entry_id


def test_inmemory_outbox_mark_dispatched():
    outbox = InMemoryOutbox()
    entry = create_outbox_entry("test.event", uuid4(), "test", uuid4())
    outbox.write(entry)
    outbox.mark_dispatched(entry.entry_id)
    pending = outbox.get_pending()
    assert len(pending) == 0
    all_entries = outbox.all_entries()
    assert all_entries[0].status == DeliveryStatus.DISPATCHED
    assert all_entries[0].dispatched_at is not None


def test_inmemory_outbox_mark_failed():
    outbox = InMemoryOutbox()
    entry = create_outbox_entry("test.event", uuid4(), "test", uuid4())
    outbox.write(entry)
    outbox.mark_failed(entry.entry_id, "connection refused")
    failed = outbox.get_pending()
    assert len(failed) == 1
    assert failed[0].status == DeliveryStatus.FAILED
    assert failed[0].last_error == "connection refused"


def test_inmemory_outbox_dead_letter():
    outbox = InMemoryOutbox()
    tid = uuid4()
    entry = create_outbox_entry("test.event", tid, "test", uuid4())
    outbox.write(entry)
    outbox.mark_dead_letter(entry.entry_id)
    pending = outbox.get_pending()
    assert len(pending) == 0
    dead = outbox.get_dead_letters(tid)
    assert len(dead) == 1
    assert dead[0].status == DeliveryStatus.DEAD_LETTER


def test_dead_letters_filtered_by_tenant():
    outbox = InMemoryOutbox()
    tid1 = uuid4()
    tid2 = uuid4()
    e1 = create_outbox_entry("a", tid1, "t", uuid4())
    e2 = create_outbox_entry("b", tid2, "t", uuid4())
    outbox.write(e1)
    outbox.write(e2)
    outbox.mark_dead_letter(e1.entry_id)
    outbox.mark_dead_letter(e2.entry_id)
    assert len(outbox.get_dead_letters(tid1)) == 1
    assert len(outbox.get_dead_letters(tid2)) == 1
    assert len(outbox.get_dead_letters()) == 2


def test_pending_batch_size():
    outbox = InMemoryOutbox()
    for _ in range(10):
        outbox.write(create_outbox_entry("x", uuid4(), "t", uuid4()))
    assert len(outbox.get_pending(batch_size=3)) == 3


def test_event_subscription():
    subs = EventSubscription()
    received: list[str] = []
    subs.subscribe("action.proposed", lambda e: received.append(e.event_type))
    handlers = subs.get_handlers("action.proposed")
    assert len(handlers) == 1
    assert subs.get_handlers("other.event") == []


def test_event_subscription_global():
    subs = EventSubscription()
    received: list[str] = []
    subs.subscribe_all(lambda e: received.append("global"))
    assert len(subs.get_handlers("any.event")) == 1


def test_relay_dispatches_events():
    outbox = InMemoryOutbox()
    subs = EventSubscription()
    received: list[str] = []
    subs.subscribe("action.proposed", lambda e: received.append(e.event_type))

    entry = create_outbox_entry("action.proposed", uuid4(), "action", uuid4())
    outbox.write(entry)

    relay = OutboxRelay(outbox, subs)
    dispatched = relay.poll_and_dispatch()
    assert dispatched == 1
    assert received == ["action.proposed"]
    assert relay.processed_count == 1
    assert outbox.get_pending() == []


def test_relay_dispatches_without_handlers():
    outbox = InMemoryOutbox()
    subs = EventSubscription()
    entry = create_outbox_entry("no.handler", uuid4(), "test", uuid4())
    outbox.write(entry)

    relay = OutboxRelay(outbox, subs)
    dispatched = relay.poll_and_dispatch()
    assert dispatched == 1


def test_relay_handler_failure_marks_failed():
    outbox = InMemoryOutbox()
    subs = EventSubscription()
    subs.subscribe("fail.event", lambda e: (_ for _ in ()).throw(RuntimeError("boom")))

    entry = create_outbox_entry("fail.event", uuid4(), "test", uuid4())
    outbox.write(entry)

    relay = OutboxRelay(outbox, subs)
    dispatched = relay.poll_and_dispatch()
    assert dispatched == 0
    remaining = outbox.get_pending()
    assert len(remaining) == 1
    assert remaining[0].status == DeliveryStatus.FAILED


def test_relay_dead_letters_after_max_attempts():
    outbox = InMemoryOutbox()
    subs = EventSubscription()
    subs.subscribe("fail.event", lambda e: (_ for _ in ()).throw(RuntimeError("boom")))

    entry = create_outbox_entry("fail.event", uuid4(), "test", uuid4())
    entry.max_attempts = 1
    outbox.write(entry)

    relay = OutboxRelay(outbox, subs)
    relay.poll_and_dispatch()
    dead = outbox.get_dead_letters()
    assert len(dead) == 1


def test_relay_multiple_events():
    outbox = InMemoryOutbox()
    subs = EventSubscription()
    count = {"n": 0}
    subs.subscribe_all(lambda e: count.__setitem__("n", count["n"] + 1))

    for i in range(5):
        outbox.write(create_outbox_entry(f"event.{i}", uuid4(), "t", uuid4()))

    relay = OutboxRelay(outbox, subs)
    dispatched = relay.poll_and_dispatch()
    assert dispatched == 5
    assert count["n"] == 5
