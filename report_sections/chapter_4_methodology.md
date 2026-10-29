# CHAPTER 4: PROPOSED METHODOLOGY

## 4.1 System Overview
The proposed security assessment framework for Model Context Protocol (MCP) interfaces is designed as a multi-layered, deterministic probing system. Unlike traditional LLM red-teaming tools that rely on non-deterministic model responses (prompt-based jailbreaking), this methodology focuses on the protocol-level interaction between the AI agent and the backend tools. The architecture is divided into three functional layers to ensure modularity, reproducibility, and high-fidelity detection.

## 4.2 Layer 1: Probe Engine (Transport & Session)
The Probe Engine serves as the foundational layer of the scanner. It is responsible for the complete lifecycle of the MCP session and serves as the single point of truth for all protocol-level interactions.

### 4.2.1 Session Management
The engine supports multiple transport mechanisms, primarily Server-Sent Events (SSE) and Streamable HTTP. It manages the initial handshake, capability negotiation, and heartbeat maintenance. Each session is assigned a unique UUID to allow for concurrent multi-identity testing.

### 4.2.2 Unified Trace Logging
A critical component of this layer is the synchronous recording of every JSON-RPC request and response. Every tool invocation, resource read, or prompt retrieval is captured as a `TraceEntry` object, including:
*   **Request Params**: The exact arguments sent by the scanner.
*   **Response Payload**: The raw output from the MCP server.
*   **Timing Data**: Latency in milliseconds for performance analysis.
*   **Error Channels**: Capture of both protocol-level errors and application-level exceptions.

## 4.3 Layer 2: Attack Orchestration (Passive & Active)
Layer 2 houses the security logic, categorized into passive analysis and active adversarial probing.

### 4.3.1 Phase 0: Passive Blueprint Analysis
Before any tools are executed, the system performs a "Phase 0" scan of the server's metadata (the Blueprint). This is a non-intrusive analysis that uses regex-based heuristics to flag architectural smells:
*   **Suspicious Naming (BP-001)**: Identifying tools with names like `admin`, `shell`, `exec`, or `debug`.
*   **Description Poisoning (BP-002)**: Scanning tool descriptions for prompt-injection instructions that could steer an LLM to override its system instructions.
*   **Dangerous Parameters (BP-003)**: Identifying parameters with names like `path`, `url`, or `cmd` that suggest a large attack surface.
*   **Resource Exposure (BP-004)**: Flagging resource URIs that reveal internal file paths or database connection strings.

### 4.3.2 Phase 1-3: Active Adversarial Probing
Active modules move beyond metadata analysis to execute controlled tool calls. The framework utilizes "Deterministic Oracles" to verify vulnerabilities:
*   **Surface B (Invocation)**: Tests for input validation flaws using math polyglots and SQL metacharacters.
*   **Surface D (Data Flow)**: Scans tool outputs for PII patterns (SSN, Email, Credit Cards) using high-precision regex scanners.
*   **Surface E (Authentication)**: Validates if privileged tools are reachable without a valid token or if rate limits are absent.

## 4.4 Data Contracts and Evidence Vault
To ensure academic rigor and pass industrial audit standards, every "Finding" emitted by the system must adhere to a strict Pydantic model:
*   **Evidence Collection**: Findings must link back to specific `TraceEntry` IDs.
*   **Narrative Generation**: Each finding includes a step-by-step attack narrative explaining how the vulnerability was triggered.
*   **Replay Information**: A machine-readable `ReplayInfo` block allows developers to reproduce the exact vulnerability with a single command, eliminating the ambiguity common in AI-based security reports.
