"""Persistent routing model and strict, secret-safe WireGuard import."""
import base64
import ipaddress
import json
import os
import re
from pathlib import Path

DEFAULT_RULES = {
    'ru': '.ru .рф .yandex.net .yastatic.net .app-analytics-services.com .2gis.com .pcb-solutions.com',
    'direct': '.tiktok.com .tiktokv.com .tiktokcdn.com .byteoversea.com .ibytedtos.com .ibyteimg.com .muscdn.com .musical.ly',
}


def migrate(con, base=None):
    for table, column, definition in [
        ('users', 'can_change_ru_exit', 'INTEGER NOT NULL DEFAULT 0'),
        ('devices', 'ru_exit_id', 'INTEGER REFERENCES ru_exits(id)'),
        ('devices', 'assigned_by', "TEXT CHECK(assigned_by IN ('user','admin'))"),
        ('devices', 'vpn_ip', 'TEXT'),
    ]:
        if column not in {r[1] for r in con.execute(f'PRAGMA table_info({table})')}:
            con.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
    con.executescript('''
      CREATE TABLE IF NOT EXISTS ru_exits(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        config_file TEXT, legacy INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS routing_rules(
        id INTEGER PRIMARY KEY, target TEXT NOT NULL CHECK(target IN ('ru','direct')),
        kind TEXT NOT NULL CHECK(kind IN ('domain','suffix','ip')), value TEXT NOT NULL,
        UNIQUE(target,kind,value));
    ''')
    if not con.execute("SELECT 1 FROM settings WHERE key='routing_revision'").fetchone():
        cur = con.execute("INSERT INTO ru_exits(name,legacy) VALUES('wg-ru',1)")
        con.execute("INSERT INTO settings VALUES('ru_default',?)", (str(cur.lastrowid),))
        con.execute("INSERT INTO settings VALUES('routing_revision','1')")
        seeds = imported_rules(base) if base else default_rules()
        con.executemany('INSERT OR IGNORE INTO routing_rules(target,kind,value) VALUES(?,?,?)', seeds)
    # wg-easy 15.4 allows NULL passwords (OAuth-only accounts).
    columns = list(con.execute('PRAGMA table_info(auth_cache)'))
    if any(r[1] == 'password_hash' and r[3] for r in columns):
        con.execute('ALTER TABLE auth_cache RENAME TO old_auth_cache')
        con.execute('''CREATE TABLE auth_cache(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          user_id INTEGER NOT NULL, username TEXT NOT NULL, password_hash TEXT, totp_key TEXT,
          totp_verified INTEGER NOT NULL, enabled INTEGER NOT NULL, session_password TEXT NOT NULL,
          session_timeout INTEGER NOT NULL, synced_at INTEGER NOT NULL)''')
        con.execute('INSERT INTO auth_cache SELECT * FROM old_auth_cache')
        con.execute('DROP TABLE old_auth_cache')


def imported_rules(base):
    seeds = []
    for rule in base.get('route', {}).get('rules', []):
        target = {'ru-direct': 'ru', 'eu-direct': 'direct'}.get(rule.get('outbound'))
        if target:
            seeds.extend(imported_rule_fields(rule, target))
    return seeds


def imported_rule_fields(rule, target):
    for field in ['domain', 'domain_suffix', 'ip_cidr']:
        values = rule.get(field, [])
        for value in ([values] if isinstance(values, str) else values):
            text = '.' + value.lstrip('.') if field == 'domain_suffix' else value
            kind, normalized = normalize_rule(text)
            yield target, kind, normalized


def default_rules():
    for target, values in DEFAULT_RULES.items():
        for value in values.split():
            kind, normalized = normalize_rule(value)
            yield target, kind, normalized


def changed(con):
    con.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='routing_revision'")


def normalize_rule(value):
    value = value.strip().lower().rstrip('.')
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError('IPv6 отключён')
        return 'ip', str(network)
    except ValueError:
        if '/' in value or ':' in value or re.fullmatch(r'[\d.]+', value):
            raise ValueError('Укажите корректный IPv4 или CIDR') from None
    kind = 'suffix' if value.startswith('.') else 'domain'
    value = value[1:] if kind == 'suffix' else value
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('Некорректное доменное имя') from None
    if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError('Некорректное доменное имя')
    return kind, value


def rule_order(rule):
    kind, value = rule['kind'], rule['value']
    if kind == 'ip':
        return (1, -ipaddress.ip_network(value).prefixlen, 0, rule['target'] != 'direct')
    return (0, -len(value.split('.')), kind != 'domain', rule['target'] != 'direct')


def parse_wireguard(text):
    """Never include input (in particular private keys) in exception messages."""
    try:
        return _parse_wireguard(text)
    except (ValueError, KeyError, TypeError):
        raise ValueError('Некорректный WireGuard-конфиг: проверьте поля, ключи и IPv4; hooks не поддерживаются') from None


INTERFACE_FIELDS = {'PrivateKey', 'Address', 'ListenPort', 'MTU', 'DNS', 'Table', 'FwMark'}
PEER_FIELDS = {'PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive'}


def wireguard_field(line, current, permitted):
    name, value = [part.strip() for part in line.split('=', 1)]
    if current is None or name not in permitted:
        raise ValueError()
    if name in current:
        if name not in {'Address', 'DNS', 'AllowedIPs'}:
            raise ValueError()
        value = current[name] + ',' + value
    current[name] = value


def wireguard_sections(text):
    if len(text.encode()) > 65536:
        raise ValueError()
    interface, peers, current = {}, [], None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line == '[Interface]':
            require_section(current is None)
            current = interface
        elif line == '[Peer]':
            require_section(current is not None)
            current = {}
            peers.append(current)
        else:
            fields = INTERFACE_FIELDS if current is interface else PEER_FIELDS
            wireguard_field(line, current, fields)
    return interface, peers


def require_section(valid):
    if not valid:
        raise ValueError()


def wireguard_key(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError()
    return value


def bounded_number(value, low, high):
    result = int(value)
    if not low <= result <= high:
        raise ValueError()
    return result


def wireguard_peer(peer, listen_port):
    allowed = [ipaddress.ip_network(x.strip(), strict=False) for x in peer['AllowedIPs'].split(',')]
    allowed = [str(x) for x in allowed if x.version == 4]
    if not allowed:
        raise ValueError()
    item = {'public_key': wireguard_key(peer['PublicKey']), 'allowed_ips': allowed}
    if 'PresharedKey' in peer:
        item['pre_shared_key'] = wireguard_key(peer['PresharedKey'])
    if 'Endpoint' in peer:
        host, port = peer['Endpoint'].rsplit(':', 1)
        normalize_rule(host)
        if host.startswith('.') or '/' in host:
            raise ValueError()
        item.update(address=host.encode('idna').decode('ascii'), port=bounded_number(port, 1, 65535))
    elif not listen_port:
        raise ValueError()
    if 'PersistentKeepalive' in peer:
        item['persistent_keepalive_interval'] = bounded_number(peer['PersistentKeepalive'], 0, 65535)
    return item


def _parse_wireguard(text):
    interface, peers = wireguard_sections(text)
    addresses = [str(ipaddress.ip_interface(x.strip())) for x in interface['Address'].split(',')]
    addresses = [x for x in addresses if ipaddress.ip_interface(x).version == 4]
    if not addresses or not peers or len(peers) > 16:
        raise ValueError()
    if interface.get('Table', 'off') not in {'off', 'auto'}:
        raise ValueError()
    result = {'type': 'wireguard', 'system': False, 'address': addresses,
              'private_key': wireguard_key(interface['PrivateKey']), 'peers': []}
    if 'ListenPort' in interface:
        result['listen_port'] = bounded_number(interface['ListenPort'], 1, 65535)
    if 'FwMark' in interface:
        mark = int(interface['FwMark'], 0) if interface['FwMark'].startswith('0x') else int(interface['FwMark'])
        result['routing_mark'] = bounded_number(mark, 0, 0xffffffff)
    if 'MTU' in interface:
        result['mtu'] = bounded_number(interface['MTU'], 576, 9000)
    result['peers'] = [wireguard_peer(peer, result.get('listen_port')) for peer in peers]
    # A RU exit must be able to carry arbitrary IPv4 destinations.
    if '0.0.0.0/0' not in [x for p in result['peers'] for x in p['allowed_ips']]:
        raise ValueError()
    return result


def atomic_json(path, data, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, ensure_ascii=False)
        stream.flush(); os.fsync(stream.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def effective_exit(assigned, default, health):
    chosen = assigned or default
    if health.get(str(chosen), False):
        return chosen
    return default if health.get(str(default), False) else None


def device_choices(devices, default, health):
    choices = {}
    for device in devices:
        if device['vpn_ip']:
            ip = str(ipaddress.IPv4Address(device['vpn_ip'])) + '/32'
            chosen = effective_exit(device['ru_exit_id'], default, health)
            choices.setdefault(chosen, []).append(ip)
    return choices


def add_exit_endpoints(config, base, exits, generated, config_dir):
    for node in exits:
        tag = f"ru-{node['id']}"
        if node['legacy']:
            legacy = next((x for x in base['outbounds'] if x['tag'] == 'ru-direct'), {})
            config['outbounds'].append({'type': 'direct', 'tag': tag, 'bind_interface': legacy.get('bind_interface', 'wg-ru')})
        else:
            path = Path(config_dir) / Path(node['config_file']).name
            endpoint = json.loads(path.read_text())
            endpoint['tag'] = tag
            config['endpoints'].append(endpoint)
        config['inbounds'].append({'type': 'socks', 'tag': f"probe-{node['id']}", 'listen': '127.0.0.1', 'listen_port': 19000 + node['id']})
        generated.append({'inbound': f"probe-{node['id']}", 'action': 'route', 'outbound': tag})


def compile_config(base, exits, devices, rules, default, health, bridge, config_dir):
    """First matching domain rule wins, then longest IP prefix, then VPS."""
    config = json.loads(json.dumps(base))
    config['endpoints'] = []
    config['outbounds'] = [x for x in config['outbounds'] if x['tag'] != 'ru-direct']
    config['inbounds'] = [x for x in config['inbounds'] if not x['tag'].startswith('probe-')]
    for inbound in config['inbounds']:
        if inbound['tag'] == 'vpn-clients':
            inbound['include_interface'] = [bridge]
    generated = [r for r in base['route']['rules'] if r.get('action') in {'sniff', 'hijack-dns'}]
    add_exit_endpoints(config, base, exits, generated, config_dir)
    choices = device_choices(devices, default, health)
    fallback = effective_exit(None, default, health)
    for rule in sorted(rules, key=rule_order):
        field = {'domain': 'domain', 'suffix': 'domain_suffix', 'ip': 'ip_cidr'}[rule['kind']]
        match = {'inbound': 'vpn-clients', field: [rule['value']]}
        if rule['target'] == 'direct':
            generated.append({**match, 'action': 'route', 'outbound': 'eu-direct'})
        else:
            for chosen, ips in choices.items():
                generated.append({**match, 'source_ip_cidr': ips, **exit_action(chosen)})
            generated.append({**match, **exit_action(fallback)})
    config['route']['rules'] = generated
    config['route']['final'] = 'eu-direct'
    return config


def exit_action(chosen):
    return {'action': 'route', 'outbound': f'ru-{chosen}'} if chosen else {'action': 'reject'}
