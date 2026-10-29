"""Get a fresh OAuth token and save it to token.txt (or a custom file).

Usage:
    python get_token.py                          # saves to token.txt
    python get_token.py --output token_manish.txt
    python get_token.py --output token_ankur.txt
"""
import argparse
from src.oauth_browser import browser_login

MCP_ENDPOINT = "https://super-singularity-mcp-redteam-1006143863862.asia-south1.run.app/sse"
AUTH_SERVER  = "https://app.skill10x.com"

parser = argparse.ArgumentParser(description="Fetch a fresh OAuth token via browser login")
parser.add_argument("--output", default="token.txt", help="File to save the token (default: token.txt)")
args = parser.parse_args()

print(f"[*] Starting browser login (will save to {args.output})...")
token = browser_login(mcp_endpoint=MCP_ENDPOINT, auth_server=AUTH_SERVER, timeout=300)

with open(args.output, "w") as f:
    f.write(token)

print(f"[+] Token saved to {args.output}")
print(f"[+] Token preview: {token[:60]}...")
