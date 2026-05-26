import asyncio

from redis.asyncio import Redis

# auth-service produces events but does not consume any streams
CONSUMERS: list = []


async def start_all_consumers(redis: Redis) -> None:
    for consumer in CONSUMERS:
        asyncio.create_task(consumer.run(redis))
