# CHAPTER 5: PROPOSED ALGORITHMS

## 5.1 Introduction
The core innovation of this research lies in the shift from qualitative AI "judgment" to quantitative deterministic oracles. This chapter details the two primary algorithms used to confirm vulnerabilities within the Model Context Protocol (MCP) ecosystem: the **Computed Marker Injection Algorithm** and the **Boolean Differential Oracle**.

## 5.2 Algorithm 1: Computed Marker Injection (B1-CM)
This algorithm is used to detect Expression and Template Injection. Instead of looking for generic error messages, it uses a mathematical challenge-response pattern.

**Algorithm Steps:**
1.  **Identity Selection**: Identify tool parameters typed as `string` with descriptions suggesting interpretation (e.g., "expression", "formula").
2.  **Nonce Generation**: Generate a cryptographically secure random nonce $N$.
3.  **Payload Construction**: Construct a polyglot payload $P$ that forces the interpreter to evaluate a specific mathematical identity. 
    *   *Example (Jinja/Twig)*: `{{7*7}}`
4.  **Expected Marker Definition**: Set the expected marker $M = 49$.
5.  **Execution**: Invoke the MCP tool with $P$ and capture the response text $R$.
6.  **Verification**: 
    *   If $M \in R$ AND $P \notin R$: The vulnerability is **Confirmed**.
    *   If $M \in R$ AND $P \in R$: The result is **Reflected Only** (Inconclusive).
    *   Else: No vulnerability detected.

## 5.3 Algorithm 2: Boolean Differential Oracle (B1-BD)
This algorithm is used to detect blind SQL injection and Query Filter injection where the response body changes based on the truth value of an injected predicate.

**Algorithm Steps:**
1.  **Baseline Establishment**: Call the tool with benign arguments to establish a baseline response length $L_{base}$ and structure.
2.  **Branch Generation**:
    *   **True Branch ($P_{true}$)**: Inject a predicate that is always true (e.g., `' OR 1=1 --`).
    *   **False Branch ($P_{false}$)**: Inject a predicate that is always false (e.g., `' OR 1=2 --`).
3.  **Observation Collection**:
    *   $O_{true} \leftarrow \text{Normalize}(\text{Call}(P_{true}))$
    *   $O_{false} \leftarrow \text{Normalize}(\text{Call}(P_{false}))$
4.  **Differential Analysis**:
    *   Calculate the relative difference $\Delta = \frac{|len(O_{true}) - len(O_{false})|}{max(len(O_{true}), len(O_{false}))}$.
5.  **Verdict Logic**:
    *   If $\Delta > 0.2$ (20% variance) OR structural mismatch (e.g., one branch returns an error, the other does not):
        *   If $len(O_{true}) \approx len(O_{base})$: **Confirmed Injection** via True-matching-baseline.
        *   Else: **Suspected Injection**.
    *   Else: **No Injection**.

## 5.4 High-Level Scanner Loop
The following pseudocode represents the overall orchestration of the scanning process:

```python
FOR tool IN discovered_tools:
    # Phase 0: Passive Analysis
    IF matches_suspicious_patterns(tool.metadata):
        emit_passive_finding(tool)
    
    # Phase 1: Active Baseline
    baseline = establish_baseline(tool)
    
    # Phase 2: Targeted Probing
    FOR parameter IN tool.parameters:
        IF parameter.name IN dangerous_names:
            # Run Computed Marker Algorithm
            run_computed_marker_probe(tool, parameter)
            
            # Run Boolean Differential Algorithm
            run_boolean_differential_probe(tool, parameter)
            
        # Run Data Exfiltration Check
        run_pii_scan(tool, parameter)
```

## 5.5 Normalization and Reflection Filtering
To prevent false positives caused by the simple echoing of inputs, both algorithms apply a **Reflection Filter**. Any text found in the response that matches the literal input payload is stripped before the oracle evaluates the result. This ensures that a confirmation only occurs if the backend *interpreted* the logic of the payload.
