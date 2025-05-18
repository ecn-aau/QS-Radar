import asyncio
import aiohttp
import numpy as np

# URL = "https://192.168.3.126:8200/api/v1/keys/Bob254250/enc_keys"
URL = "https://google.com"
NUM_APPS = 90
REQUESTS_PER_APP = 10

async def send_request(app_id:str, session: aiohttp.ClientSession,  request_id: int, sleep: float) -> None:
    try:
        async with session.get(URL) as response:
            print(f"App {app_id}, Request {request_id}: Status {response.status}, Sleep was: {sleep}")
    except Exception as e:
        print(f"App {app_id}, Request {request_id}: Failed with error {e}")

async def simulate_app(app_id: str, scale: float) -> None:
    async with aiohttp.ClientSession() as session:
        for i in range(REQUESTS_PER_APP):
            # session.verify = "ca-cert.crt"
            sleep_time = np.random.default_rng().exponential(scale=scale)
            await send_request(app_id=app_id, session=session, request_id=i, sleep=sleep_time)
            await asyncio.sleep(sleep_time)

# def prepare()

async def main():
    group1 = [simulate_app(app_id=f"group1 {id}",scale=0.5) for id in range(1, 30 + 1)]
    group2 = [simulate_app(app_id=f"group2 {id}", scale=1.0) for id in range(1, 30 + 1)]
    group3 = [simulate_app(app_id=f"group3 {id}", scale=5.0) for id in range(1, 30 + 1)]
    tasks = group1 + group2 + group3
    await asyncio.gather(*tasks)

asyncio.run(main())
