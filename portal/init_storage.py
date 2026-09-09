"""One-shot volume ownership migration; no network access or long-running root."""
import os
from pathlib import Path


def initialize():
    for directory, mode in [('/ru-configs', 0o700), ('/data', 0o770),
                            ('/router-state', 0o700), ('/routing-status', 0o750)]:
        os.chown(directory, 65532, 65532)
        os.chmod(directory, mode)
    # Existing keys and SQLite files retain their contents and private modes.
    root = Path('/wg-easy')
    os.chown(root, 1000, 65532)
    os.chmod(root, 0o700)
    for path in root.rglob('*'):
        if not path.is_symlink():
            os.chown(path, 1000, 65532)


if __name__ == '__main__':
    initialize()
