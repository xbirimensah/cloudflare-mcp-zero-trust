import asyncio

from fastmcp import Client

from examples.server import create_server


def test_example_is_an_actual_fastmcp_server() -> None:
    async def inspect() -> list[str]:
        async with Client(create_server()) as client:
            return [tool.name for tool in await client.list_tools()]

    assert asyncio.run(inspect()) == ["status"]
