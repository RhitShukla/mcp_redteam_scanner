# FRONT MATTER & ABSTRACT

## COVER PAGE (Format: IIIT Bhopal)

**DETERMINISTIC SECURITY PROBING AND VULNERABILITY ASSESSMENT OF AGENTIC AI INTERFACES VIA MODEL CONTEXT PROTOCOL (MCP)**

**MINOR PROJECT REPORT**

Submitted in partial fulfillment for the award of the degree of

**BACHELOR OF TECHNOLOGY**
**(Department of Computer Science and Engineering)**

Submitted to
**INDIAN INSTITUTE OF INFORMATION TECHNOLOGY BHOPAL (M.P.)**

**Submitted by**
[Your Name] -- [Scholar Number]

**Under the supervision of**
Dr. Saurabh Jain
Assistant Professor
CSE Department

**October, 2026**

---

## CERTIFICATE

This is to certify that the work embodied in this report entitled **"Deterministic Security Probing and Vulnerability Assessment of Agentic AI Interfaces via Model Context Protocol (MCP)"** has been satisfactorily completed by **[Your Name] ([Scholar Number]).** It is a bonafide piece of work, carried out under our guidance in the **Department of Computer Science and Engineering**, **Indian Institute of Information Technology, Bhopal** for the partial fulfillment of the Bachelor of Technology during the academic year 2026-27.

**Date:** 30 October, 2026

---

## DECLARATION

I hereby declare that the following major project synopsis entitled **"Deterministic Security Probing and Vulnerability Assessment of Agentic AI Interfaces via Model Context Protocol (MCP)"** presented in the is the partial fulfillment of the requirements for the award of the degree of **Bachelor of Technology in Computer Science and Engineering**. It is an authentic documentation of my original work carried out under the able guidance of **Dr. Saurabh Jain**. The work has been carried out entirely at the Indian Institute of Information Technology, Bhopal. The project work presented has not been submitted in part or whole to award of any degree or professional diploma in any other institute or organization.

I, with this, declare that the facts mentioned above are true to the best of my knowledge. In case of any unlikely discrepancy that may occur, I will be the one to take responsibility.

**[Your Name]**
**[Scholar Number]**

---

## ACKNOWLEDGEMENT

I would like to express my sincere gratitude to everyone who supported and guided me throughout the successful completion of my minor project titled **"Deterministic Security Probing and Vulnerability Assessment of Agentic AI Interfaces via Model Context Protocol (MCP)"**.

First and foremost, I would like to extend my heartfelt thanks to our esteemed Director, **Dr. Ashutosh Kumar Singh** for providing the necessary resources and facilities for conducting this project. His encouragement and vision played a key role in helping me accomplish my goals.

I am deeply grateful to my Project Guide, **Dr. Saurabh Jain**, for his constant guidance, invaluable suggestions, and expert advice throughout the project. His knowledge and insights helped me enhance the quality of my work, and his support kept me motivated during difficult times.

My sincere thanks to the Department Coordinator, **Dr. Rahul Chaurasia**, for organizing and overseeing the entire project process. His assistance in clarifying doubts and providing the right direction was instrumental in the smooth execution of the project.

---

## ABSTRACT

The rapid adoption of agentic AI workflows has introduced a new communication standard: the Model Context Protocol (MCP). While MCP enables Large Language Models (LLMs) to interact seamlessly with backend tools and data sources, it simultaneously expands the attack surface of traditional web applications. Current AI security tools primarily focus on prompt-based jailbreaking, which is often non-deterministic and prone to false positives. 

This project presents a novel, deterministic framework for the security assessment of MCP-enabled interfaces. We propose a three-layered scanner architecture that utilizes "Deterministic Oracles"—mathematical markers and boolean differentials—to confirm vulnerabilities such as PII leakage, SQL injection, and path traversal without relying on AI-generated judgments. To verify the framework, we developed "NEXUS," a high-fidelity gadgets e-commerce storefront integrated with a deliberately vulnerable MCP server. 

Experimental results demonstrate that the proposed framework identified 46 distinct security findings across 11 MCP tools, achieving a 0% false-positive rate in confirmation modules. This research provides a robust "Shift-Left" methodology for developers to validate the safety of agentic tool-use before deployment in production environments.
