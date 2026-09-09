// Use the same authenticated cookie implementation as wg-easy's h3 session.
// Secrets travel only over stdin; never include library errors in output.
import { webcrypto } from 'node:crypto';
import { defaults, seal, unseal } from 'iron-webcrypto';

try {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 16384) throw new Error('Session input too large');
  }
  const { operation, value, secret, ttl = 0 } = JSON.parse(input);
  const options = { ...defaults, ttl };
  let result;
  if (operation === 'seal') {
    result = await seal(webcrypto, value, secret, options);
  } else if (operation === 'unseal') {
    result = await unseal(webcrypto, value, secret, options);
  } else {
    throw new Error('Unknown operation');
  }
  process.stdout.write(JSON.stringify(result));
} catch {
  process.exitCode = 1;
}
