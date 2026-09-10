"""Run inside the stopped-for-writes legacy portal before its final backup."""
import asyncio
import json
import os
from pathlib import Path
import tempfile

import app


async def export():
    async with app.wg_session() as client:
        response = await client.get('/api/client')
        response.raise_for_status()
        result = {}
        for peer in response.json():
            config = await client.get(f"/api/client/{peer['id']}/configuration")
            config.raise_for_status()
            result[str(peer['id'])] = config.text
    return result


def save(result):
    directory = Path('/data')
    with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as stream:
        try:
            json.dump(result, stream)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(stream.name, directory / 'native-reference.json')
        finally:
            Path(stream.name).unlink(missing_ok=True)
    print(f'Client configurations exported privately: {len(result)}')


if __name__ == '__main__':
    save(asyncio.run(export()))
