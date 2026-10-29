"""
Vuln Tech Store — combined frontend + MCP server + AI Agent Sandbox.

Single process:
  - GET  /                      -> tech/gadgets e-commerce frontend (SPA)
  - GET  /static/<path>         -> static assets
  - POST /api/agent/chat        -> Interactive AI Shopping Agent (triggers MCP tools)
  - MCP SSE endpoint at         -> http://localhost:8000/mcp/sse

Run:
    python main.py
"""

from __future__ import annotations

from pathlib import Path
import json

from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from mcp_server import mcp

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


async def homepage(request):
    return FileResponse(STATIC_DIR / "index.html")


async def agent_chat(request):
    """
    Simulates an AI Shopping Assistant that acts as an MCP client.
    Routes user prompts to MCP tools, showing the raw JSON-RPC execution traces.
    Allows live, in-browser execution and demonstration of the vulnerabilities.
    """
    try:
        body = await request.json()
        user_msg = body.get("message", "").strip()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    # Simple keyword-based intent router (acts like an LLM dispatching tool calls)
    tool_calls = []
    response_text = ""
    msg_lower = user_msg.lower()

    if "profile" in msg_lower or "customer" in msg_lower or "ssn" in msg_lower or "card" in msg_lower:
        tool_name = "get_customer_profile"
        args = {"customer_id": "1"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "admin" in msg_lower or "system data" in msg_lower or "root" in msg_lower:
        tool_name = "admin_panel"
        args = {"command": "get_system_info"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "debug" in msg_lower or "inventory" in msg_lower or "cost" in msg_lower:
        tool_name = "debug_inventory"
        args = {"debug_level": "high"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "invoice" in msg_lower or "file" in msg_lower or "etc/passwd" in msg_lower or "passwd" in msg_lower:
        file_path = "invoice_1001.pdf"
        if "passwd" in msg_lower:
            file_path = "../../../etc/passwd"
        elif "invoice" in msg_lower and ".." in msg_lower:
            # Extract manual traversal string if present
            parts = user_msg.split("invoice")
            if len(parts) > 1 and ".." in parts[1]:
                file_path = parts[1].strip()
        tool_name = "download_order_invoice"
        args = {"file_path": file_path}
        tool_calls.append({"name": tool_name, "args": args})
    elif "search" in msg_lower or "find" in msg_lower or "product" in msg_lower or "'" in msg_lower:
        query = "Quantum"
        if "'" in msg_lower or "or 1=1" in msg_lower:
            query = user_msg
        tool_name = "search_products"
        args = {"query": query}
        tool_calls.append({"name": tool_name, "args": args})
    elif "discount" in msg_lower or "calculate" in msg_lower or "expr" in msg_lower or "math" in msg_lower or "7*7" in msg_lower:
        expr = "10+5"
        if "{{" in msg_lower or "${" in msg_lower:
            expr = "{{7*7}}"
        tool_name = "calculate_discount"
        args = {"expression": expr}
        tool_calls.append({"name": tool_name, "args": args})
    elif "export" in msg_lower or "csv" in msg_lower:
        tool_name = "safe_export_orders"
        args = {"export_path": "orders_export.csv"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "cart" in msg_lower or "get_cart" in msg_lower:
        tool_name = "get_cart"
        args = {"customer_id": "1"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "orders" in msg_lower or "list_orders" in msg_lower:
        tool_name = "list_orders"
        args = {"customer_id": "1"}
        tool_calls.append({"name": tool_name, "args": args})
    elif "coupon" in msg_lower:
        tool_name = "apply_coupon"
        args = {"code": "WINTER50"}
        tool_calls.append({"name": tool_name, "args": args})
    elif msg_lower:
        tool_name = "echo"
        args = {"message": user_msg}
        tool_calls.append({"name": tool_name, "args": args})

    execution_traces = []

    if tool_calls:
        for tc in tool_calls:
            try:
                # Format request trace representing JSON-RPC call
                req_trace = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tc["name"],
                        "arguments": tc["args"]
                    },
                    "id": 1
                }

                # Execute tool using MCPServer's call_tool
                tool_res = await mcp.call_tool(tc["name"], tc["args"])

                # Extract response text
                text_content = ""
                for item in tool_res.content:
                    if hasattr(item, "text"):
                        text_content += item.text
                    elif isinstance(item, dict) and "text" in item:
                        text_content += item["text"]

                resp_trace = {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {"type": "text", "text": text_content}
                        ],
                        "isError": getattr(tool_res, "isError", False)
                    },
                    "id": 1
                }

                execution_traces.append({
                    "tool": tc["name"],
                    "request": req_trace,
                    "response": resp_trace,
                    "result_text": text_content
                })

                response_text += f"\n[Agent used Tool: {tc['name']}]\n{text_content}\n"
            except Exception as e:
                execution_traces.append({
                    "tool": tc["name"],
                    "error": str(e)
                })
                response_text += f"\n[Agent Error calling {tc['name']}]: {e}\n"
    else:
        response_text = (
            "Hello! I am your NEXUS Assistant. I can help you search products, "
            "calculate discount formulas, manage profiles, download invoices, "
            "or access developer controls. What would you like me to do?"
        )

    return JSONResponse({
        "response": response_text.strip(),
        "traces": execution_traces
    })


# Mount the MCP SSE server under /mcp so its SSE path becomes /mcp/sse.
mcp_app = mcp.sse_app()

routes = [
    Route("/", homepage),
    Route("/api/agent/chat", agent_chat, methods=["POST"]),
    Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
    Mount("/mcp", app=mcp_app),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")
