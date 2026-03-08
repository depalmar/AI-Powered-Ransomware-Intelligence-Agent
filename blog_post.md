Stay Ahead of Ransomware: Building an AI-Powered Ransomware Intelligence Agent
Authored by Raymond DePalma & Ryan Chapman

[MONTH] [YEAR] (Episode recorded [DATE])

In the [MONTH] [YEAR] episode of the SANS "Stay Ahead of Ransomware" livestream, we went hands-on with AI-powered threat intelligence. Returning guest Raymond "Mr. AI" DePalma from Palo Alto Networks Unit 42 joined show hosts Ryan Chapman and Mari DeGrazia for a demo-driven session that picked up right where the February episode left off. In February (recording | blog), Ray introduced the defender's AI toolkit - LLM fundamentals, threat attribution, and live demos from his "AI for the Win" repository. This time, Ray showed what it looks like to put those concepts into production with a new open-source project: an AI-Powered Ransomware Intelligence Agent.

## From Concepts to a Working Pipeline

The February episode introduced the idea of agentic AI - systems that don't just answer questions but autonomously carry out multi-step tasks. This episode brought that idea to life. Ray demonstrated a fully working pipeline built in n8n (an open-source workflow automation tool) that pulls live ransomware victim data, processes it, runs it through AI analysis, and delivers a finished intelligence report - all on an automated schedule with no human intervention required.

Why n8n? Ray explained that it's visual (so you can see exactly what the pipeline does at a glance), self-hostable (important for security teams handling sensitive data), and supports LLM integrations natively. For security practitioners familiar with SOAR platforms, think of it as a lightweight, open-source alternative you can customize from scratch.

## What the Agent Does

The centerpiece of the demo was the Ransomware Group Threat Monitor workflow. Ray walked through the full data flow live on screen:

- A scheduled trigger pulls recent victim data from the ransomware.live API
- The data is immediately replaced with synthetic company profiles - randomized names, industries, and dates - so no real victim information is ever exposed downstream. This was a deliberate design choice: the entire pipeline can be demonstrated live without showing real victim data
- The workflow filters by industry, deduplicates by ransomware group, and enriches each group with profile data (descriptions, suspected origins, known tactics)
- The enriched dataset is passed to an AI model that produces a threat intelligence assessment
- The output is a polished HTML report with dashboard metrics, interactive charts, MITRE ATT&CK technique mappings, per-group profiles, and prioritized defensive recommendations

The finished report can be viewed in a browser or delivered as Markdown, with optional Slack and Google Docs delivery ready to enable.

## Making AI Output Reliable

One of the most interesting parts of the demo was how Ray solved a common problem with LLM-powered automation: getting consistent, usable output. Instead of asking the AI for free-text analysis, the pipeline enforces a structured schema - the AI must return specific fields like threat level, MITRE ATT&CK technique IDs, targeting patterns, and prioritized recommendations in a predictable format. This means downstream steps in the workflow can reliably use the AI's output without fragile text parsing. It's the difference between an AI chatbot and a composable automation component.

## Cloud AI or Fully Local - Your Choice

Every workflow in the project ships in two versions: one using Anthropic's Claude API and one using Ollama, which runs models entirely on local hardware. The rest of the pipeline is identical - only the AI node swaps out.

Ray discussed the tradeoffs: Claude generally produces more consistent structured output and nuanced analysis, while Ollama gives you full data privacy, zero API costs, and the ability to run in air-gapped environments. The dual-track design means a well-funded SOC can use Claude while a university lab, startup, or home-lab practitioner can run the same workflow locally at no cost.

## A Learning Path, Not Just a Tool

The project is structured as a progressive learning path. The 101-level workflow teaches API integration and AI-powered analysis. The 200-level builds on that foundation with IOC enrichment (VirusTotal, AbuseIPDB), AI-generated YARA rules, historical trend analysis, multi-channel delivery, confidence scoring, and negotiation intelligence. Each level introduces new automation concepts, so practitioners can start where their skills are and grow from there.

The repository also includes a demo mode with a mock API server, so you can run the full pipeline with synthetic data - perfect for training sessions, conference talks, or academic environments.

## AI Amplifies Expertise - It Doesn't Replace It

The session wrapped up with a discussion that echoed a key theme from the February episode: human oversight matters. The pipeline is designed for human-in-the-loop operation. The AI generates assessments, but the transparent data flow - visible in the n8n canvas with documented nodes throughout - means analysts can verify every claim. AI hallucinations are a real concern (models can fabricate attribution details or invent technique IDs), so pairing AI analysis with structured validation and human review gives you the speed benefits without sacrificing rigor.

As Ray put it: "AI doesn't replace expertise, it amplifies it."

The project is released under a CC BY-NC 4.0 license, free for educational and defensive use.

## Learning More and Looking Forward

To learn more, we invite you to watch the [MONTH] [YEAR] episode of the SANS "Stay Ahead of Ransomware" livestream. Want to watch prior episodes? Be sure to check out our Stay Ahead of Ransomware playlist on YouTube.

Get hands on with the project:

- AI-Powered Ransomware Intelligence Agent: github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent
- AI for the Win (50+ security AI labs): github.com/depalmar/ai_for_the_win

Join us each month for the SANS "Stay Ahead of Ransomware" livestream on the first Tuesday of each month at 1:00 PM Eastern (10:00 AM Pacific).

Remember to check out our upcoming SANS training events, including FOR528: Ransomware and Cyber Extortion, where we dive into the technical details of preventing, detecting, and responding to ransomware and cyber extortion attacks. On the AI side of things, we also have FOR563: Applied AI for Digital Forensics and Incident Response: Leveraging Local Large Language Models, which teaches cyber defenders to leverage AI to aid in DFIR and IR investigations.
