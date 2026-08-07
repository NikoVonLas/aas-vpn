import json
import os
import sqlite3
import time

SOURCE = os.getenv("WG_DB", "/wg-easy/wg-easy.db")
TARGET = os.getenv("WG_AUTH_SNAPSHOT", "/data/wg-auth.json")


def snapshot():
    con = sqlite3.connect(f"file:{SOURCE}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    user = con.execute("SELECT id,username,password,totp_key,totp_verified,enabled FROM users_table WHERE role=1 ORDER BY id LIMIT 1").fetchone()
    general = con.execute("SELECT session_password,session_timeout FROM general_table WHERE id=1").fetchone()
    con.close()
    if not user or not general:
        return
    data = {
        "user_id": user["id"], "username": user["username"], "password_hash": user["password"],
        "totp_key": user["totp_key"], "totp_verified": user["totp_verified"], "enabled": user["enabled"],
        "session_password": general["session_password"], "session_timeout": general["session_timeout"],
        "synced_at": int(time.time()),
    }
    temporary = TARGET + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(data, stream, separators=(",", ":"))
    os.chown(temporary, 65532, 65532)
    os.chmod(temporary, 0o600)
    os.replace(temporary, TARGET)


while True:
    try:
        snapshot()
    except (OSError, sqlite3.Error) as error:
        print(f"auth sync waiting: {error}", flush=True)
    time.sleep(30)
