# Contributing to Syd

Thanks for your interest in improving Syd. This document outlines how to report bugs, request features, and submit contributions.

## Reporting Bugs

When reporting bugs, include:

1. **Environment details:**
   - Operating system and version
   - Python version
   - RAM available
   - CPU model

2. **Steps to reproduce:**
   - Exact sequence of actions
   - Input files used (if possible, sanitized versions)
   - Expected vs actual behavior

3. **Error messages:**
   - Full error output
   - Relevant log entries
   - Screenshots if applicable

**Common issues to check first:**
- Model file exists and is correct size (9.7GB)
- FAISS indexes were generated
- Sufficient RAM available (16GB minimum)
- Dependencies installed correctly

## Feature Requests

Open an issue describing:

- Use case and problem being solved
- Proposed solution or approach
- Why existing functionality doesn't address the need

Feature requests for supported tools (Nmap, BloodHound, Volatility) are prioritized over new tool integrations.

## Code Contributions

### Areas needing work:

**High priority:**
- Fact extractor edge cases (malformed XML, unusual JSON structures)
- Validation tuning (false positives/negatives)
- Performance optimization for large scans
- BloodHound attack path analysis improvements

**Medium priority:**
- Additional Nmap script output parsing
- Volatility plugin coverage
- Documentation improvements

**Low priority:**
- GUI enhancements
- New tool integrations

### Development setup:

1. Fork the repository
2. Create a virtual environment
3. Install dependencies: `pip install -r requirements.txt`
4. Download models and generate indexes
5. Make changes in a feature branch
6. Test thoroughly with real scan data
7. Submit pull request

### Code guidelines:

- Follow existing code style (PEP 8)
- Add comments for complex logic
- No emojis or unnecessary formatting in output
- Fact extractors must be deterministic (no LLM calls)
- Validation must be evidence-based
- Test with real pentest data, not synthetic examples

### Testing:

Test changes with:
- Small scans (10-20 hosts)
- Medium scans (50-100 hosts)
- Large scans (500+ hosts)
- Malformed input (truncated, invalid XML/JSON)
- Edge cases (empty scans, single host, all filtered ports)

Run the validation suite if available.

### Pull requests:

Pull requests should:
- Address a single issue or feature
- Include a clear description of changes
- Explain why the change is needed
- Reference related issues
- Pass existing validation tests

Expect feedback and iteration. Complex changes may require multiple review cycles.

## Documentation

Documentation improvements are always welcome:

- Installation instructions
- Usage examples
- Troubleshooting guides
- Architecture explanations

Keep documentation concise and technical. Avoid marketing language.

## Questions

**Technical questions:**
- Open a GitHub Discussion for general questions
- Open an issue for bug reports or feature requests

**Direct contact:**
- Email: info@sydsec.co.uk
- Response time: 1-3 business days

**Project resources:**
- Website: https://sydsec.co.uk
- YouTube: https://www.youtube.com/@paularmstrong8306

## Code of Conduct

Be professional and respectful. This is a technical project focused on security tooling. Keep discussions on-topic and constructive.

---

**Maintained by:** Paul Armstrong ([@Sydsec](https://github.com/Sydsec))
