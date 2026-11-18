1. Core Principles of github.com/lagigliaivan/cdcsec
Shift Security Left: Integrates security guarantees directly into the CI/CD pipeline alongside traditional contract tests.

Prevent Security Drift: Ensures that microservice refactoring doesn't silently remove security controls (like CORS settings, authentication, or anti-clickjacking headers).

Consumer Intent: Allows API consumers to state what security guarantees they depend on (e.g., expecting standard authorization failures rather than 500 errors).


