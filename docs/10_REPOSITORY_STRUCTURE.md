# Repository Structure

Recommended conceptual structure:

/docs            project specifications and decisions
/prompts         controlled Antigravity task prompts
/shared          contracts and common utilities
/services        independently owned runtime modules
/detectors       isolated detector implementations
/tests           cross-module/integration tests
/fixtures        deterministic input samples
/replay          demo and replay scenarios
/scripts         developer automation
/config          explicit configuration
/infra           deployment/container definitions

Tests should be located close to implementation where practical, with integration tests separated clearly.

Generated output and secrets must not be committed.
