# Test suite

Automated tests that prove the tool is correct, robust, and scalable. They use
Python's built-in `unittest`, so **no extra packages are needed**.

Run all tests from the project root:

    python -m unittest discover -s tests -v

39 tests cover:
- Attack-path discovery and risk ranking on every sample
- Extractor permission resolution and the rule engine
- Remediation validation: eliminated / remaining / introduced
- Fix-advice generation (correct kubectl command per finding)
- Input robustness: empty, malformed, binary, non-Kubernetes, malformed objects
- Scalability: a large dense cluster completes quickly instead of hanging
- Web endpoints and friendly error handling

Every test states an expected result, so the suite is the evidence for
"how do you know the tool is correct?".
