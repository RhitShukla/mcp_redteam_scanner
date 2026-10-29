# CHAPTER 7: IMPLEMENTATION

## 7.1 Development Stack
The framework is implemented using a modern asynchronous Python stack to handle the streaming nature of MCP Server-Sent Events (SSE).
*   **Language**: Python 3.10.12.
*   **Protocol SDK**: `mcp` (Model Context Protocol) v2.1.1.
*   **Web Framework**: `Starlette` (for the high-performance Lab backend).
*   **Data Validation**: `Pydantic v2` (for the internal data contracts).
*   **CLI Infrastructure**: `argparse` with `asyncio` orchestration.

## 7.2 The NEXUS Lab Implementation
To prove the scanner's efficacy, we built "NEXUS"—a gadgets storefront that serves as a "Honey-Server."

### 7.2.1 Tool Implementation
Each MCP tool in NEXUS is a Python function decorated with `@mcp.tool()`. We implemented "Vulnerable Logic Sinks" for testing:
*   **`search_products`**: Implements a mock SQL interpreter that detects the `' OR 1=1 --` string and artificially inflates the product list length to trigger the **Boolean Differential Oracle**.
*   **`download_order_invoice`**: A function that accepts a `file_path`. If the string contains `..` or `/etc/passwd`, it returns a hardcoded system-file signature (`root:x:0:0`).
*   **`get_customer_profile`**: Returns a dictionary containing realistic but fake PII, including a generated SSN and a secret key starting with `sk-live_`.

## 7.3 Attack Module Logic (Source Code Analysis)
The scanner iterates through a registry of modules, each inheriting from a base `AttackModule` class.

### 7.3.1 Passive Module (Blueprint Analyzer)
Implemented as a series of regex-based rules. It calculates a "Risk Score" for each tool by looking for dangerous keywords like `exec` or `internal` in the JSON metadata.

### 7.3.2 Active Module (D1 - Sensitive Data)
This module invokes tools with benign "seed" arguments and passes the resulting text through a multi-regex PII scanner. It uses high-fidelity patterns for:
*   **AWS Keys**: `AKIA[0-9A-Z]{16}`.
*   **JWT Tokens**: `eyJ[A-Za-z0-9_-]+\.eyJ...`.
*   **Credit Cards**: Luhn-check compatible patterns.

---

# CHAPTER 8: RESULT AND ANALYSIS

## 8.1 Summary of Findings
The scanner was executed against the NEXUS Lab endpoint (`http://localhost:8000/mcp/sse`). The audit resulted in **46 security findings** distributed across the severity spectrum.

### 8.1.1 Severity Distribution
*   **Critical**: 6 findings (Description Poisoning, API Key leakage).
*   **High**: 10 findings (SQL Injection, Path Traversal, PII Leakage).
*   **Medium**: 17 findings (Resource Exposure, Broad Enumeration).
*   **Low**: 12 findings (Weak input schemas, Missing rate limits).

## 8.2 Key Vulnerability Analysis

### 8.2.1 Path Traversal (B3-001)
The scanner successfully identified that the `download_order_invoice` tool accepted relative path sequences. By receiving the `root:x:0:0` signature, the **B3 Module** confirmed the vulnerability with high confidence, providing the raw JSON-RPC trace as immutable evidence.

### 8.2.2 SQL Injection (B1-001)
The **Boolean Differential Oracle** detected a 500% variance in response length between the True and False predicates. This deterministic confirmation ensures that the vulnerability is actionable by developers without further manual triage.

## 8.3 OWASP Top 10 for LLMs Crosswalk
We mapped our findings to the standard framework to demonstrate industrial relevance:

| Finding ID | Category | OWASP Mapping |
| :--- | :--- | :--- |
| **D1-001** | PII Leakage | LLM06: Sensitive Information Disclosure |
| **B3-001** | Path Traversal | LLM02: Insecure Output Handling |
| **BP-003** | Prompt Injection | LLM01: Prompt Injection |
| **A4-001** | Broad Enumeration | LLM08: Excessive Agency |

## 8.4 Performance Metrics
The full audit of 11 tools took **less than 180 seconds**. The system recorded **169 interaction traces**, demonstrating that automated protocol-level probing is significantly faster and more comprehensive than manual prompt-based red-teaming.
