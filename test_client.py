import asyncio
from mcp import Client


async def main():
    async with Client("http://127.0.0.1:8000/mcp") as client:
        tools = await client.list_tools()
        print("Tools:", [tool.name for tool in tools.tools])

        result = await client.call_tool(
            "system_status",
            {},
        )
        print("Hasil:", result)


if __name__ == "__main__":
    asyncio.run(main())
