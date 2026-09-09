import importlib
import json
import sqlite3
from conftest import KEY


def test_snapshot_reconciles_only_portal_clients(portal, tmp_path, monkeypatch):
    app, client = portal
    source = tmp_path / 'wg-easy.db'
    with sqlite3.connect(source) as con:
        con.executescript('''
        CREATE TABLE users_table(id,username,password,totp_key,totp_verified,enabled,role);
        INSERT INTO users_table VALUES(1,'admin',NULL,NULL,0,1,1);
        CREATE TABLE general_table(id,session_password,session_timeout);
        INSERT INTO general_table VALUES(1,'session-secret',3600);
        CREATE TABLE clients_table(id,ipv4_address,private_key);
        CREATE TABLE interfaces_table(ipv4_cidr,mtu,private_key);
        INSERT INTO interfaces_table VALUES('10.8.0.1/24',1280,'never-export-interface-key');
        ''')
        con.executemany('INSERT INTO clients_table VALUES(?,?,?)', [(41,'10.8.0.9',KEY), (99,'10.8.0.10',KEY)])
    import sync
    monkeypatch.setattr(sync,'SOURCE',str(source))
    monkeypatch.setattr(sync,'TARGET',str(tmp_path/'auth.json'))
    monkeypatch.setattr(sync,'PORTAL_DB',app.DB)
    sync.snapshot()
    assert KEY not in (tmp_path/'auth.json').read_text()
    assert 'never-export-interface-key' not in (tmp_path/'wg-network.json').read_text()
    assert json.loads((tmp_path/'wg-network.json').read_text())['mtus'] == {'10.8.0.0/24': 1280}
    with app.db() as con:
        assert con.execute('SELECT vpn_ip FROM devices WHERE id=1').fetchone()[0] == '10.8.0.9'
        assert con.execute('SELECT vpn_ip FROM devices WHERE id=2').fetchone()[0] is None
        assert con.execute('SELECT count(*) FROM devices').fetchone()[0] == 2
    app.sync_auth_cache()
    assert app.auth_cache()['password_hash'] is None
