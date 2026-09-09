import { readFileSync, writeFileSync } from 'node:fs';

// The service inherits only CAP_NET_ADMIN and CAP_NET_RAW via capsh. Avoid wg-quick's UID-only
// sudo check: the service runs as node and the kernel checks capabilities.
for (const name of ['wg-quick', 'awg-quick']) {
  const path = `/usr/bin/${name}`;
  const source = readFileSync(path, 'utf8');
  const check = /^\t\[\[ \$UID == 0 \]\] \|\| exec (?:sudo|"\$\{SUDO:-sudo\}") .*$/m;
  if (!check.test(source)) throw new Error('Unexpected wg-quick privilege check');
  writeFileSync(path, source.replace(check, '\t: # Network commands use ambient capabilities.'));
}
