"""Test standalone: connect to a stdio MCP server, list tools, call one."""
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(path: str, tool: str, args_json: str) -> None:
    # Spawn with the SAME runtime production uses (mcp v1 venv), not ambient python3.
    params = StdioServerParameters(
        command="/home/mael/.hermes/mcp-servers/venv/bin/python", args=[path])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            # mcp SDK renamed serverInfo -> server_info; support both.
            info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)
            print(f"SERVER: {getattr(info, 'name', info)}")
            print(f"TOOLS ({len(names)}): {names}")
            if tool:
                res = await session.call_tool(tool, json.loads(args_json))
                text = "".join(
                    c.text for c in res.content if getattr(c, "type", "") == "text"
                )
                print(f"CALL {tool} -> is_error={getattr(res, 'is_error', getattr(res, 'isError', None))}")
                print(text[:200000])


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "",
                     sys.argv[3] if len(sys.argv) > 3 else "{}"))
