"""Versioned prompt contract.

Kept outside ``impactgate.llm`` so cache fingerprints can include the prompt
version without importing the LLM package (and its cache dependency).
"""

PROMPT_VERSION = "v1"
