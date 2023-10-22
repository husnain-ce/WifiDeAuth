import asyncio

async def function1():
    # do something
    print("Function 1 is running...")
    await asyncio.sleep(10)

async def function2():
    # wait for 5 seconds before doing something else
    print("Function 2 is waiting...")
    await asyncio.sleep(5)
    # do something else
    print("Function 2 is running...")

async def test():
    await asyncio.gather(function1(), function2())

loop = asyncio.get_event_loop()
loop.run_until_complete(test())