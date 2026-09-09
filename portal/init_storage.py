"""One-shot volume ownership migration; no network access or long-running root."""
import os
from pathlib import Path


def owned_tree(directory, owner):
    root = Path(directory)
    os.chown(root, owner, 65532)
    for path in root.rglob('*'):
        if not path.is_symlink():
            os.chown(path, owner, 65532)


def initialize():
    for directory, mode in [('/ru-configs', 0o700), ('/data', 0o770), ('/auth', 0o700),
                            ('/router-state', 0o700), ('/routing-status', 0o750)]:
        owned_tree(directory, 65532)
        os.chmod(directory, mode)
    for directory, mode in [('/awg-data', 0o700), ('/awg-control', 0o750), ('/awg-network', 0o750)]:
        owned_tree(directory, 1000)
        os.chmod(directory, mode)


if __name__ == '__main__':
    initialize()
