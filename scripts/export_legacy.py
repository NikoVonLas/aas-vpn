"""Run inside the stopped-for-writes legacy portal before its final backup."""
import asyncio
import json
import os

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
    descriptor = os.open('/tmp/native-reference.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(result, stream)
    print(f'Client configurations exported privately: {len(result)}')


if __name__ == '__main__':
    asyncio.run(export())
