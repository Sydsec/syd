# Changelog

## Version 3.0 (January 2026)

Complete rewrite from V2. Switched from general chat interface to specialized scan analysis modules.

### What Changed

Dropped the general-purpose chatbot approach. It was hallucinating too much and giving bad advice on pentests. The new version focuses on analyzing actual scan data with fact-based answers.

Added three specialized modules:

**Nmap Module**
- Parses XML scan files and extracts ports, services, vulnerabilities
- 50+ detection patterns covering common misconfigurations
- Accuracy tested at 96.7% (29/30 questions correct)
- Anti-hallucination validation prevents making up findings

**BloodHound Module**
- Parses JSON exports from SharpHound/BloodHound
- Extracts AD objects, attack paths, ACL permissions, delegation issues
- Identifies Kerberoasting, AS-REP roasting, unconstrained delegation
- Current accuracy around 85-90%
- Same validation approach as Nmap

**Volatility Module**
- Memory dump analysis (experimental)
- Process detection, rootkit hunting, malware analysis
- Uses larger 14B model for better accuracy on complex forensics
- Still being tested, expect issues

### Architecture

Three-tier design prevents hallucinations:

1. Fact extraction (deterministic parsing, no LLM)
2. RAG retrieval (finds relevant docs from knowledge base)
3. Answer generation with validation (LLM generates answer, validator checks it against facts)

If the LLM tries to mention something not in the scan, the answer gets blocked. This is why Nmap hits 96.7% accuracy while V2 was around 75%.

### Technical Changes

Switched to single model for all modules:
- Qwen 2.5 14B Instruct (Q5_K_M) - better instruction following and accuracy than previous 8B models
- All modules (Nmap, BloodHound, Volatility) now use consistent chat completion architecture

Added dedicated fact extractors:
- nmap_fact_extractor.py (1000+ lines, regex-based parsing)
- bloodhound_fact_extractor.py (1200+ lines, JSON parsing with validation)
- volatility_fact_extractor.py (experimental)

Knowledge bases expanded:
- Nmap: 50+ markdown files covering port scanning, service detection, vuln assessment
- BloodHound: 30+ files on AD attacks, privilege escalation, lateral movement
- Volatility: 40+ files on memory forensics, rootkit detection, malware analysis

### What Got Removed

Dropped from V2:
- General chat (was causing too many mistakes)
- Intent detection (user picks module explicitly now)
- CVE database integration (polluted context with irrelevant data)
- Decision trees (didn't use them in practice)
- Code templates (rarely needed pre-written code)

### Known Issues

BloodHound occasionally generates answers with broken numbering or slight repetition. Working on fixing this but it's at 85-90% accuracy which is usable.

Volatility module is experimental. The 14B model is slower but more accurate on complex forensics questions. Still tuning the parameters.

Large scans (500+ hosts, 10MB+ files) can take 30-60 seconds to parse. This is expected - parsing is CPU-bound and single-threaded.

### Performance

Tested on AMD Ryzen AI 9 365 with 24GB RAM:
- Nmap queries: 2-4 seconds
- BloodHound queries: 3-5 seconds
- Volatility queries: 4-8 seconds (larger model)

Memory usage:
- Idle: ~500MB
- With model loaded: ~6-8GB (8B model) or ~12-14GB (14B model)
- Peak during parsing: Add 2-4GB for large scans

### Accuracy Testing

Nmap: Tested with 30 questions across different scan types
- Service identification: 30/30 (100%)
- Vulnerability detection: 29/30 (96.7%)
- Port analysis: 30/30 (100%)
- Overall: 96.7%

BloodHound: Tested with 30 questions on AD attack paths
- Concept questions: 27/30 (90%)
- Finding identification: 24/30 (80%)
- Attack path analysis: 21/30 (70%)
- Overall: 85-90% depending on question complexity

The difference in accuracy is expected - AD analysis is more complex than port scanning.

## Version 2.0 (2025)

Previous version. General-purpose chatbot with intent detection. Worked okay for simple questions but hallucinated too much on technical details. Replaced by V3's fact-based approach.
