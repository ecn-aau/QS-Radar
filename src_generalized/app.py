import asyncio
import aiohttp
import numpy as np
import random
import ssl
import time

URL = "https://192.168.3.126:8200/api/v1/keys/Bob254250/enc_keys"
# URL = "https://google.com"

GROUP1_AMOUNT = 30
GROUP2_AMOUNT = 30
GROUP3_AMOUNT = 30

GROUP1_SCALE = 0.5
GROUP2_SCALE = 1.0
GROUP3_SCALE = 5.0

OUTPUT_FILENAME = "output_scenario1.txt"

REQUESTS_PER_APP = 100
NANO_TO_MILLI = 1000000

async def send_request(app_id: str, session: aiohttp.ClientSession,  request_id: int, ssl_context: ssl.SSLContext) -> None:
    try:
        async with session.get(URL, ssl=ssl_context) as response:
            pass
            # print(f"App {app_id}, Request {request_id}: Status {response.status}, Sleep was: {sleep}")
    except Exception as e:
        print(f"App {app_id}, Request {request_id}: Failed with error {e}")


def persist_data(data: list[str]) -> None:
    with open(f"../out/{OUTPUT_FILENAME}", "a") as file:
        for op in data:
           file.write(op)


cycle_data = []


async def simulate_app(app_id: str, scale: float) -> None:
    connector = aiohttp.TCPConnector(limit=100)
    async with aiohttp.ClientSession(connector=connector) as session:
        ssl_context = ssl.create_default_context(cafile='ca-cert.crt')
        # for i in range(REQUESTS_PER_APP):
        sleep_time = np.random.default_rng().exponential(scale=scale)
        await asyncio.sleep(sleep_time)

        time_start = time.perf_counter_ns()
        await send_request(app_id=app_id, session=session, request_id=i, ssl_context=ssl_context)
        time_end = time.perf_counter_ns()

        # App ID, request ID, request time, sleep time after request. Full application elapsed time can be determined by summing the cycle data with a bit of a loss from computation
        data = f"{app_id}, {i}, {(time_end - time_start) / NANO_TO_MILLI}, {sleep_time}\n"
        cycle_data.append(data)


async def main():
    group1 = [simulate_app(app_id=f"group1 {id}", scale=GROUP1_SCALE) for id in range(1, GROUP1_AMOUNT * REQUESTS_PER_APP + 1)]
    group2 = [simulate_app(app_id=f"group2 {id}", scale=GROUP2_SCALE) for id in range(1, GROUP2_AMOUNT * REQUESTS_PER_APP + 1)]
    group3 = [simulate_app(app_id=f"group3 {id}", scale=GROUP3_SCALE) for id in range(1, GROUP3_AMOUNT * REQUESTS_PER_APP + 1)]
    tasks = group1 + group2 + group3
    random.shuffle(tasks)
    await asyncio.gather(*tasks)
    persist_data(cycle_data)

asyncio.run(main())
