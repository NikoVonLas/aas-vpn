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
    for directory, mode in [('/ru-configs', 0o700), ('/data', 0o770),
                            ('/router-state', 0o700), ('/routing-status', 0o750)]:
        owned_tree(directory, 65532)
        os.chmod(directory, mode)
    # Existing keys and SQLite files retain their contents and private modes.
    root = Path('/wg-easy')
    owned_tree(root, 1000)
    os.chmod(root, 0o750)
    for name in ['wg-easy.db', 'wg-easy.db-wal', 'wg-easy.db-shm']:
        path = root / name
        if path.exists() and not path.is_symlink():
            os.chmod(path, 0o640)


if __name__ == '__main__':
    initialize()
