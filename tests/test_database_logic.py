import pytest
from cryptography.fernet import Fernet

import database_logic as db


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    database = tmp_path / "test_vault.db"
    monkeypatch.setenv("AEGIS_DB_PATH", str(database))
    db.setup_security()
    return database


def insert_test_user(email):
    stored_hash = b"test-hash-not-used-for-authentication"
    if db.bcrypt is not None:
        stored_hash = db.bcrypt.hashpw(b"A-strong-login-secret", db.bcrypt.gensalt())
    with db.get_db() as conn:
        conn.execute(
            "INSERT INTO users (email, hashed_pw, ether_credits, status) VALUES (?, ?, 5, 'active')",
            (email, stored_hash),
        )


def test_registration_login_and_status(temp_db):
    if db.bcrypt is None:
        pytest.skip("bcrypt is not installed in this execution environment")
    assert db.create_user("user@example.test", "A-strong-login-secret") is True
    assert db.create_user("user@example.test", "A-strong-login-secret") is False
    assert db.authenticate_user("user@example.test", "A-strong-login-secret") == "active"
    assert db.authenticate_user("user@example.test", "wrong-password") is None
    assert db.update_user_status("user@example.test", "lockdown") is True
    assert db.check_status("user@example.test") == "lockdown"


def test_status_and_repeated_registration_state(temp_db):
    insert_test_user("user@example.test")
    assert db.update_user_status("user@example.test", "lockdown") is True
    assert db.check_status("user@example.test") == "lockdown"
    assert db.update_user_status("user@example.test", "not-a-status") is False


def test_vault_round_trip_and_wrong_key(temp_db):
    insert_test_user("owner@example.test")
    db.save_account("owner@example.test", "mail service", "owner", "vault-secret-value", "master-key")
    records = db.fetch_accounts("owner@example.test", "master-key")
    assert len(records) == 1
    assert records[0]["Password"] == "vault-secret-value"
    assert records[0]["Site"] == "mail service"
    assert records[0]["User"] == "owner"
    with db.get_db() as conn:
        raw = conn.execute(
            "SELECT site, username, password, encryption_version FROM accounts WHERE owner_email=?",
            ("owner@example.test",),
        ).fetchone()
    assert raw[0] != "mail service"
    assert raw[1] != "owner"
    assert raw[2] != "vault-secret-value"
    assert raw[3] == 2
    assert db.fetch_accounts("owner@example.test", "wrong-key") is None


def test_legacy_owner_email_salt_remains_readable(temp_db):
    owner = "legacy@example.test"
    insert_test_user(owner)
    encrypted = Fernet(db.get_fernet_key("old-master-key", owner.encode())).encrypt(b"old-vault-secret").decode()
    with db.get_db() as conn:
        conn.execute(
            "INSERT INTO accounts (owner_email, site, username, password, salt) VALUES (?, ?, ?, ?, NULL)",
            (owner, "legacy service", "legacy user", encrypted),
        )
    rows = db.fetch_accounts(owner, "old-master-key")
    assert rows and rows[0]["Password"] == "old-vault-secret"
    assert rows[0]["Site"] == "legacy service"
    assert rows[0]["User"] == "legacy user"
    with db.get_db() as conn:
        upgraded = conn.execute(
            "SELECT site, username, password, encryption_version FROM accounts WHERE owner_email=?",
            (owner,),
        ).fetchone()
    assert upgraded[0] != "legacy service"
    assert upgraded[1] != "legacy user"
    assert upgraded[2] != "old-vault-secret"
    assert upgraded[3] == 2


def test_account_edit_and_delete_are_owner_scoped(temp_db):
    insert_test_user("owner@example.test")
    insert_test_user("attacker@example.test")
    db.save_account("owner@example.test", "service", "owner", "secret", "master")
    row_id = db.fetch_accounts("owner@example.test", "master")[0]["id"]
    assert db.update_account(row_id, "changed", "new-secret", "master", "attacker@example.test") is False
    assert db.delete_account(row_id, "attacker@example.test") is False
    assert db.fetch_accounts("owner@example.test", "master")[0]["Password"] == "secret"
    assert db.update_account(
        row_id, "changed", "new-secret", "master", "owner@example.test", new_site="updated service"
    ) is True
    edited = db.fetch_accounts("owner@example.test", "master")[0]
    assert edited["Site"] == "updated service"
    assert edited["User"] == "changed"
    assert edited["Password"] == "new-secret"
    assert db.delete_account(row_id, "owner@example.test") is True
    assert db.fetch_accounts("owner@example.test", "master") == []


def test_transaction_approval_is_atomic_and_idempotent(temp_db):
    owner = "payer@example.test"
    insert_test_user(owner)
    starting_credits = db.get_user_credits(owner)
    transaction_id = db.log_transaction(owner, 50, "VERIFIED", None)
    assert len(db.get_pending_transactions()) == 1
    assert db.approve_transaction(transaction_id) is True
    assert db.approve_transaction(transaction_id) is False
    assert db.get_user_credits(owner) == starting_credits + 5
    assert db.get_pending_transactions() == []


def test_payment_advisory_is_saved_but_transaction_stays_pending(temp_db):
    owner = "payer@example.test"
    insert_test_user(owner)
    transaction_id = db.log_transaction(
        owner, 50, "VERIFIED", "audit_screenshots/example.jpg",
        {
            "verdict": "VERIFIED",
            "confidence": 0.97,
            "amount_detected": "INR 50.00",
            "recipient_match": True,
            "findings": ["Amount matches", "Recipient matches"],
        },
    )
    row = db.get_pending_transactions()[0]
    assert row[0] == transaction_id
    assert row[4] == "PENDING"
    assert row[8] == "VERIFIED"
    assert row[9] == pytest.approx(0.97)
    assert "Amount matches" in row[10]
    assert row[11] == "INR 50.00"
    assert row[12] == 1
    assert db.get_user_credits(owner) == 5


def test_banned_user_cannot_submit_or_receive_payment_approval(temp_db):
    owner = "banned-payer@example.test"
    insert_test_user(owner)
    tx_id = db.log_transaction(owner, 50, "PENDING", None)
    assert db.update_user_status(owner, "banned") is True
    with pytest.raises(PermissionError):
        db.log_transaction(owner, 50, "PENDING", None)
    assert db.approve_transaction(tx_id) is False
    assert db.get_user_credits(owner) == 0


def test_rejection_does_not_grant_credits(temp_db):
    owner = "payer@example.test"
    insert_test_user(owner)
    starting_credits = db.get_user_credits(owner)
    transaction_id = db.log_transaction(owner, 100, "PENDING", None)
    assert db.reject_transaction(transaction_id) is True
    assert db.reject_transaction(transaction_id) is False
    assert db.get_user_credits(owner) == starting_credits


def test_invalid_credit_and_transaction_amounts_are_rejected(temp_db):
    insert_test_user("user@example.test")
    assert db.grant_gems("user@example.test", -5) is False
    assert db.grant_gems("user@example.test", 10001) is False
    with pytest.raises(ValueError):
        db.log_transaction("user@example.test", -10)


def test_ban_retains_identity_and_records_but_blocks_user_actions(temp_db):
    owner = "owner@example.test"
    insert_test_user(owner)
    db.save_account(owner, "service", "user", "secret", "master")
    transaction_id = db.log_transaction(owner, 50, "PENDING", None)
    assert db.update_user_status(owner, "banned") is True
    assert db.check_status(owner) == "banned"
    assert db.fetch_accounts(owner, "master") is None
    assert db.get_user_credits(owner) == 0
    assert db.use_credit(owner) is False
    assert db.update_account(1, "changed", "new-secret", "master", owner, new_site="new service") is False
    assert db.delete_account(1, owner) is False
    assert db.approve_transaction(transaction_id) is False
    with db.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE email=?", (owner,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM accounts WHERE owner_email=?", (owner,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM transactions WHERE user_email=?", (owner,)).fetchone()[0] == 1
    with pytest.raises(PermissionError):
        db.save_account(owner, "another", "user", "secret", "master")
    with pytest.raises(PermissionError):
        db.log_transaction(owner, 50, "PENDING", None)


def test_oracle_credit_refund_restores_one_credit(temp_db):
    owner = "refund@example.test"
    insert_test_user(owner)
    before = db.get_user_credits(owner)
    assert db.use_credit(owner) is True
    assert db.get_user_credits(owner) == before - 1
    assert db.refund_credit(owner) is True
    assert db.get_user_credits(owner) == before


def test_cleanup_removes_aged_orphan_screenshots(temp_db, tmp_path):
    import os
    import time

    upload_dir = tmp_path / "audit_screenshots"
    upload_dir.mkdir()
    orphan = upload_dir / "orphaned-upload.jpg"
    orphan.write_bytes(b"synthetic-test-image")
    old_time = time.time() - (31 * 24 * 60 * 60)
    os.utime(orphan, (old_time, old_time))

    deleted = db.cleanup_expired_screenshots(upload_dir, retention_days=30)
    assert deleted == 1
    assert not orphan.exists()