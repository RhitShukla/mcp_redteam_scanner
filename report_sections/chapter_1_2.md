# CHAPTER 1: INTRODUCTION

## 1.1 Background
The landscape of Artificial Intelligence has undergone a tectonic shift from passive chatbots to autonomous "Agentic" systems. These agents are no longer confined to generating text; they are increasingly empowered to perform actions—such as querying databases, managing files, and executing code—through a mechanism known as "Tool-Use" or "Function Calling." As organizations race to integrate Large Language Models (LLMs) into their core operations, the need for a standardized, secure communication layer between the model and the backend has become paramount.

## 1.2 Introduction to Model Context Protocol (MCP)
The Model Context Protocol (MCP) is an open standard designed to facilitate this integration. It allows AI applications to discover and interact with backend tools, resources, and prompts through a unified JSON-RPC based interface. By abstracting the transport layer (supporting SSE and stdio), MCP enables a "plug-and-play" ecosystem where a single server can serve multiple different AI clients. However, this ease of integration also creates a direct, often unauthenticated, path from an untrusted model context to sensitive organizational data.

## 1.3 Motivation
Current security research in AI is heavily focused on "Jailbreaking"—the art of manipulating model prompts to bypass safety filters. While important, this approach ignores the "Downstream" vulnerabilities. Even a perfectly aligned model can be forced to execute a dangerous command if the tool it is calling is not properly sanitized. There is a critical lack of tools that can systematically probe the *protocol layer* of AI interfaces to identify traditional software vulnerabilities (like SQLi or Path Traversal) that are now exposed via AI agents.

## 1.4 Problem Statement
The integration of MCP-enabled backends into agentic workflows expands the traditional software attack surface. Specifically, the "O(N) to O(1)" problem arises where a single natural language prompt can trigger multiple complex tool calls. Existing red-teaming frameworks are non-deterministic, making it difficult for security engineers to obtain reliable, reproducible evidence of a vulnerability. There is a need for a deterministic, automated scanner that can validate the security boundaries of MCP interfaces.

## 1.5 Objectives
The primary goal of this project is to develop a high-fidelity security assessment framework for MCP-enabled systems. The specific objectives are:
1.  To design a multi-layered scanner architecture capable of passive metadata analysis and active deterministic probing.
2.  To implement "Deterministic Oracles" (Computed Markers and Boolean Differentials) to confirm high-impact vulnerabilities without false positives.
3.  To build a high-fidelity vulnerable laboratory (NEXUS) to serve as a verification ground for the scanner's efficacy.
4.  To map identified vulnerabilities to established industry frameworks like the OWASP Top 10 for LLMs (2025).

---

# CHAPTER 2: LITERATURE REVIEW

## 2.1 The AI Security Landscape
The security of LLM-based applications is a nascent but rapidly evolving field. Initial research focused on adversarial attacks on the model's neural weights. However, as applications moved into production, the focus shifted to the application layer. The "Indirect Prompt Injection" attack, where a model consumes data from a tool or resource that contains malicious instructions, highlighted the danger of the "Data-as-Code" confusion in agentic systems.

## 2.2 OWASP Top 10 for LLMs (v2025)
The Open Worldwide Application Security Project (OWASP) recently updated its guidance for LLM applications. Key categories relevant to this project include:
*   **LLM01: Prompt Injection**: Both direct and indirect methods to manipulate model behavior.
*   **LLM02: Insecure Output Handling**: Occurs when a tool's output is trusted blindly without sanitization.
*   **LLM06: Sensitive Information Disclosure**: The leakage of PII or secrets through model responses.
*   **LLM08: Excessive Agency**: Granting a model more permissions or tool access than strictly necessary.

## 2.3 Analysis of Existing Red-Teaming Tools
Several tools have been developed to test AI safety, but they have distinct limitations in the context of MCP:
*   **Garak**: An LLM vulnerability scanner that primarily focuses on prompt-based testing (jailbreaks, hallucination). It is not designed to probe the underlying JSON-RPC protocol of a tool.
*   **PyRIT**: Microsoft’s Python Risk Identification Tool. While robust, it is geared towards large-scale red-teaming of the model itself rather than the specific integration points of an MCP server.
*   **Burp Suite (MCP Plugin)**: Professional security suites are beginning to include MCP detection, but they often lack the deep, deterministic marker-based confirmation required for agentic tool-use.

## 2.4 The Model Context Protocol (MCP) Specification
An in-depth analysis of the MCP v1.0 and v2.0 specifications reveals several potential weak points:
*   **Discovery Surface**: The `tools/list` and `resources/list` methods often expose internal infrastructure details.
*   **Transport Security**: While SSE provides a robust streaming channel, it lacks built-in authentication, relying instead on the implementer to wrap it in a secure gateway.
*   **Context Window Pressure**: Tools that return large payloads can lead to "Denial of Wallet" or context-stuffing attacks, where the model's performance degrades due to excessive data.

## 2.5 Summary of Research Gap
Most existing research treats the AI agent as a "black box." This project identifies a gap in "Grey Box" testing, where the scanner has knowledge of the MCP schema and can precisely target individual parameters with deterministic probes, rather than relying on the stochastic nature of an LLM to find flaws.
