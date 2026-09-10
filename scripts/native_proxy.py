"""Replace only the known legacy proxy block; retain all server-owned settings."""
from pathlib import Path


def update(path):
    lines = path.read_text().splitlines(keepends=True)
    output = []
    replacing = False
    for line in lines:
        if line.strip() == 'reverse_proxy awg2:51821 {':
            replacing = True
            output.append('    redir https://{$PORTAL_DOMAIN}/admin 308\n')
        elif replacing:
            if line.strip() == '}':
                replacing = False
            elif line.strip() != 'header_down Set-Cookie "Path=/" "Path=/; Domain={$COOKIE_DOMAIN}"':
                raise ValueError('Custom legacy proxy directives require review')
        else:
            output.append(line)
    if replacing or any('awg2:51821' in line for line in output):
        raise ValueError('Unsupported legacy proxy block')
    path.write_text(''.join(output))


if __name__ == '__main__':
    update(Path(__file__).resolve().parents[1] / 'config' / 'Caddyfile')
