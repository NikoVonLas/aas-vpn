"""Explicit, atomic consolidation of a phone identity into an administrator.

Run against the stopped, backed-up portal. Without --apply the transaction is
rolled back, including policy changes. Never prints credentials or configurations.
"""
import argparse
import json
import sqlite3
from pathlib import Path

import identity


def merge_candidates(con, phone):
    admins = con.execute("SELECT DISTINCT a.* FROM accounts a JOIN grants g ON g.account_id=a.id WHERE g.role_id='administrator' AND g.scope='global'").fetchall()
    source = con.execute('SELECT * FROM accounts WHERE phone=?', (phone,)).fetchone()
    if len(admins) != 1 or not source:
        raise ValueError('Нужны ровно один администратор и существующий аккаунт с указанным телефоном')
    target = admins[0]
    if not source['enabled'] or not target['enabled']:
        raise ValueError('Оба аккаунта должны быть активны')
    if source['id'] == target['id']:
        return source, target
    for field in ('phone', 'email'):
        if source[field] and target[field] and source[field] != target[field]:
            raise ValueError('Различаются реквизиты аккаунтов: ' + field)
    if source['admin_id']:
        credential = con.execute('SELECT password_hash,totp_verified FROM admins WHERE id=?', (source['admin_id'],)).fetchone()
        if credential and (credential['password_hash'] or credential['totp_verified']):
            raise ValueError('У телефонного аккаунта есть отдельный пароль или TOTP: требуется явный выбор реквизитов')
    return source, target


def merge_routing(con, source, target):
    rows = {row['account_id']: row for row in con.execute('SELECT * FROM portal.users WHERE account_id IN (?,?)', (source, target))}
    if len(rows) != 2:
        raise ValueError('Не найдены обе записи кабинета')
    old, new = rows[source], rows[target]
    if old['ru_exit_id'] and new['ru_exit_id'] and old['ru_exit_id'] != new['ru_exit_id']:
        raise ValueError('У аккаунтов назначены разные альтернативные выходы')
    rules = con.execute("SELECT target,kind,value FROM portal.scoped_routing_rules WHERE scope='account' AND owner_id IN (?,?)", (source, target)).fetchall()
    destinations = {}
    for row in rules:
        key = row['kind'], row['value']
        if key in destinations and destinations[key] != row['target']:
            raise ValueError('Маршруты аккаунтов противоречат друг другу')
        destinations[key] = row['target']
    con.execute('UPDATE portal.devices SET account_id=?,phone=? WHERE account_id=?', (target, new['phone'], source))
    con.execute("INSERT OR IGNORE INTO portal.scoped_routing_rules SELECT scope,?,target,kind,value FROM portal.scoped_routing_rules WHERE scope='account' AND owner_id=?", (target, source))
    con.execute("DELETE FROM portal.scoped_routing_rules WHERE scope='account' AND owner_id=?", (source,))
    con.execute('UPDATE portal.users SET ru_exit_id=?,device_limit=?,can_change_ru_exit=? WHERE account_id=?',
                (new['ru_exit_id'] or old['ru_exit_id'], max(old['device_limit'], new['device_limit'], con.execute('SELECT count(*) FROM portal.devices WHERE account_id=?', (target,)).fetchone()[0]),
                 max(old['can_change_ru_exit'], new['can_change_ru_exit']), target))
    con.execute('DELETE FROM portal.users WHERE account_id=?', (source,))
    con.execute("UPDATE portal.settings SET value=CAST(value AS INTEGER)+1 WHERE key='routing_revision'")


def merge_identity(con, source, target):
    old, new = source['id'], target['id']
    con.execute('UPDATE accounts SET phone=NULL,email=NULL WHERE id=?', (old,))
    con.execute('UPDATE accounts SET phone=?,email=?,voluntary_2fa=1 WHERE id=?', (target['phone'] or source['phone'], target['email'] or source['email'], new))
    con.execute('UPDATE passkeys SET account_id=? WHERE account_id=?', (new, old))
    con.execute('INSERT OR IGNORE INTO backup_codes SELECT ?,digest FROM backup_codes WHERE account_id=?', (new, old))
    con.execute('DELETE FROM backup_codes WHERE account_id=?', (old,))
    con.execute('INSERT OR IGNORE INTO grant_targets SELECT grant_id,? FROM grant_targets WHERE account_id=?', (new, old))
    con.execute('DELETE FROM grant_targets WHERE account_id=?', (old,))
    con.execute('DELETE FROM grants WHERE account_id=?', (old,))
    for table in ('identity_sessions', 'challenges', 'recovery_codes'):
        con.execute(f'DELETE FROM {table} WHERE account_id IN (?,?)', (old, new))
    con.execute('DELETE FROM accounts WHERE id=?', (old,))
    if source['admin_id']:
        con.execute('DELETE FROM admins WHERE id=?', (source['admin_id'],))
    identity.audit(con, new, 'accounts.merge', old)


def configure_server(con, phone):
    """Explicit installation policy, independent of the password-based defaults."""
    source, target = merge_candidates(con, phone)
    devices_before = [tuple(row) for row in con.execute('SELECT id,client_id,vpn_ip,ru_exit_id,assigned_by FROM portal.devices ORDER BY id')]
    if source['id'] != target['id']:
        merge_routing(con, source['id'], target['id'])
        merge_identity(con, source, target)
    con.execute("UPDATE roles SET primary_methods='[\"phone\"]' WHERE id='user'")
    con.execute("UPDATE roles SET primary_methods='[\"password\",\"phone\"]',require_2fa=1 WHERE id='administrator'")
    con.execute("DELETE FROM grants WHERE account_id=? AND role_id='user'", (target['id'],))
    identity.migrate_builtin_roles(con)
    identity.ensure_owner(con)
    identity.ensure_login_paths(con)
    devices_after = [tuple(row) for row in con.execute('SELECT id,client_id,vpn_ip,ru_exit_id,assigned_by FROM portal.devices ORDER BY id')]
    if devices_before != devices_after:
        raise ValueError('Изменились параметры VPN-устройств')
    return {'merged': source['id'] != target['id'], 'devices_preserved': len(devices_after), 'administrator_2fa': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--auth-db', type=Path, required=True)
    parser.add_argument('--portal-db', type=Path, required=True)
    parser.add_argument('--phone', required=True)
    parser.add_argument('--apply', action='store_true', help='Commit after an agreed stopped-stack backup')
    args = parser.parse_args()
    # mode=rw prevents creating an empty database after a path typo.
    with sqlite3.connect(args.auth_db.resolve().as_uri() + '?mode=rw', uri=True) as con:
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('ATTACH DATABASE ? AS portal', (args.portal_db.resolve().as_uri() + '?mode=rw',))
        if any(con.execute(f'PRAGMA {schema}.journal_mode').fetchone()[0] != 'delete' for schema in ('main', 'portal')):
            raise ValueError('Для атомарного объединения обе базы должны использовать DELETE journal mode')
        con.execute('BEGIN IMMEDIATE')
        result = configure_server(con, args.phone)
        if args.apply:
            con.commit()
        else:
            con.rollback()
        print(json.dumps({**result, 'applied': args.apply}, ensure_ascii=False))


if __name__ == '__main__':
    main()
