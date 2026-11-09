"""pytest configuration.

The older test_*.py files (approval, dispatcher, guardrails, injection, model, tools) are demo
scripts: they run on import, some read input(), call the live model or need Presidio. Run them
directly (python test_dispatcher.py). pytest collects only the MAS governance suites below,
which need no network, no model and no Presidio (one output-guard behaviour test skips without it).
"""
collect_ignore = [
    "test_approval.py", "test_dispatcher.py", "test_guardrails.py",
    "test_injection.py", "test_model.py", "test_tools.py",
]
