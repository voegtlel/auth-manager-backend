import asyncio
import math
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, format_datetime

from starlette.requests import Request

from user_manager.common.config import config
from user_manager.common.models import IpLoginThrottle
from user_manager.common.mongo import async_ip_login_throttle_collection

_max_throttle_count = int(
    math.log2(config.oauth2.login_throttler.max_delay / config.oauth2.login_throttler.base_delay) + 1
)


async def async_throttle(request: Request):
    if not config.oauth2.login_throttler.enable:
        return 0
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': request.client.host})
    if throttle_data is None:
        return 0
    throttle = IpLoginThrottle.validate(throttle_data)
    delay = (throttle.next_retry - datetime.utcnow()).total_seconds()
    if delay > 0:
        print(f"Throttle check from {request.client.host}: {delay}sec at {throttle.next_retry}")
        await asyncio.sleep(delay)


async def async_throttle_failure(request: Request) -> str:
    if not config.oauth2.login_throttler.enable:
        return formatdate(usegmt=True)
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': request.client.host})
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    if throttle_data is None:
        delay = config.oauth2.login_throttler.base_delay
        throttle = IpLoginThrottle(
            ip=request.client.host,
            retries=1,
            last_retry=now,
            next_retry=now + timedelta(seconds=delay),
            forget_time=now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff),
        )
        await async_ip_login_throttle_collection.insert_one(throttle.dict(exclude_none=True, by_alias=True))
    else:
        throttle = IpLoginThrottle.validate(throttle_data)
        throttle.retries = min(throttle.retries + 1, _max_throttle_count)
        throttle.last_retry = now
        delay = min(
            config.oauth2.login_throttler.base_delay * (2 ** throttle.retries), config.oauth2.login_throttler.max_delay
        )
        throttle.next_retry = now + timedelta(seconds=delay)
        throttle.forget_time = now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff)
        await async_ip_login_throttle_collection.replace_one(
            {'_id': throttle.ip}, throttle.dict(exclude_none=True, by_alias=True)
        )
    print(f"Throttling {throttle.ip} for {delay}sec until {throttle.next_retry}")

    return format_datetime(throttle.next_retry, usegmt=True)
