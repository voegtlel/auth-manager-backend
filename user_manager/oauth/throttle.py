import asyncio
import math
from datetime import datetime, timedelta

from starlette.requests import Request

from user_manager.common.config import config
from user_manager.common.models import IpLoginThrottle
from user_manager.common.mongo import ip_login_throttle_collection, async_ip_login_throttle_collection

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
    delay = min(
        config.oauth2.login_throttler.base_delay * (2 ** throttle.retries), config.oauth2.login_throttler.max_delay
    )
    print(f"Throttle check from {request.client.host}: {delay}sec")
    await asyncio.sleep(delay)


def throttle_failure(request: Request):
    if not config.oauth2.login_throttler.enable:
        return
    throttle_data = ip_login_throttle_collection.find_one({'_id': request.client.host})
    now = datetime.utcnow()
    if throttle_data is None:
        throttle = IpLoginThrottle(
            ip=request.client.host,
            retries=1,
            last_retry=now,
            forget_time=now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff),
        )
        ip_login_throttle_collection.insert_one(throttle.dict(exclude_none=True, by_alias=True))
    else:
        throttle = IpLoginThrottle.validate(throttle_data)
        throttle.retries = min(throttle.retries + 1, _max_throttle_count)
        throttle.last_retry = now
        throttle.forget_time = now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff)
        ip_login_throttle_collection.replace_one({'_id': throttle.ip}, throttle.dict(exclude_none=True, by_alias=True))


async def async_throttle_failure(request: Request):
    if not config.oauth2.login_throttler.enable:
        return
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': request.client.host})
    now = datetime.utcnow()
    if throttle_data is None:
        throttle = IpLoginThrottle(
            ip=request.client.host,
            retries=1,
            last_retry=now,
            forget_time=now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff),
        )
        await async_ip_login_throttle_collection.insert_one(throttle.dict(exclude_none=True, by_alias=True))
    else:
        throttle = IpLoginThrottle.validate(throttle_data)
        throttle.retries = max(throttle.retries + 1, _max_throttle_count)
        throttle.last_retry = now
        throttle.forget_time = now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff)
        await async_ip_login_throttle_collection.replace_one({'_id': throttle.ip}, throttle.dict(exclude_none=True, by_alias=True))
