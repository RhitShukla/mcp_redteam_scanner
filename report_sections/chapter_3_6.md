# CHAPTER 3: PROBLEM DEFINITION AND OBJECTIVES

## 3.1 Problem Definition
The primary problem addressed by this project is the **"Authentication-to-Execution Transparency"** gap in agentic AI. 

When a developer integrates a backend tool into an AI agent via MCP, they are essentially exposing a function to a model that can be "convinced" to call that function in ways the developer never intended. Traditional web security assumes a human is at the browser; agentic security must assume an LLM is at the steering wheel.

### 3.1.1 Vulnerability Categories
We define the problem space into four critical surfaces:
1.  **Metadata Surface (Discovery)**: Discovery endpoints (`/tools/list`) leaking "architectural breadcrumbs"—names like `admin_v2` or `debug_console` that invite targeted attacks.
2.  **Input Surface (Injection)**: The lack of a "Schema Sandbox." If a tool accepts a `query` string, can an attacker inject `' OR 1=1` and receive data from other tenants?
3.  **Data Surface (Exfiltration)**: Tools that return "Too much data." A `get_user` tool should return a name, not an SSN or a password hash.
4.  **Identity Surface (Multi-tenancy)**: The failure to bind the LLM's session identity to the underlying tool's session, leading to IDOR (Insecure Direct Object Reference) at the protocol layer.

## 3.2 Objectives and Scope

### 3.2.1 Primary Objectives
*   **Automation**: Create a scanner that requires only an MCP URL to begin a full audit.
*   **Determinism**: Eliminate "AI Hallucinations" in security reports by using mathematical markers to confirm every finding.
*   **Verifiability**: Ensure every finding is actionable with a human-readable attack narrative and a machine-readable replay script.

### 3.2.2 Scope and Limitations
*   **Supported Transports**: The project focuses on SSE (Server-Sent Events) based MCP servers.
*   **Protocol Version**: Compliance with MCP SDK v2.1.1.
*   **Target Scope**: The scanner tests the MCP server *backend*; it does not test the model's neural weights or internal reasoning filters.

---

# CHAPTER 6: SYSTEM ARCHITECTURE

## 6.1 Architectural Block Diagram
The system is built on a decoupled, event-driven architecture consisting of the **Scanner Cluster** and the **NEXUS Lab Environment**.

### 6.1.1 The Scanner Core
1.  **Transport Adapter**: Abstracts the SSE connection.
2.  **Metadata Broker**: Parses JSON-RPC discovery payloads into a searchable attack map.
3.  **Oracle Engine**: The decision-making unit that evaluates response variance and marker presence.

### 6.1.2 The Lab (NEXUS)
The verification laboratory is built as a single-process Starlette application.
1.  **Web-Storefront**: A high-fidelity gadgets e-commerce UI to provide context.
2.  **MCP Hub**: The actual target. It implements 11 tools with "Simulated Sinks"—controlled vulnerabilities that allow for safe verification.

## 6.2 Data Flow Logic
The standard execution flow follows a strict sequence:
1.  **Connection**: Handshake via `initialize`.
2.  **Blueprint Enumeration**: Discovery of all tools, resources, and prompts.
3.  **Passive Analysis**: The `BlueprintAnalyzer` runs BP-series rules on the discovery metadata.
4.  **Active Probing**: The `ProbeEngine` iterates through the attack modules (D1, B1, B3, etc.).
5.  **Result Aggregation**: Findings are validated against the Pydantic schema and serialized to JSON.

## 6.3 Layered Defense Mapping
Our architecture maps directly to the "Defence-in-Depth" model:
*   **Outer Layer**: Authentication and Transport Security (Surface E).
*   **Middle Layer**: Metadata Sanitization and Tool Scoping (Surface A).
*   **Inner Layer**: Input Validation and Output Filtering (Surface B & D).
