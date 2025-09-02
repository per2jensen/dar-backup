# Contributing to dar-backup

Thanks for considering contributing to **dar-backup**.  
This document outlines the basic rules and workflow for contributions.

## Ground Rules

- **Tests must pass**: All PRs must run with a clean test suite (`pytest`) before submission.  
- **Code must be documented**: Public functions, classes, and modules require docstrings. Inline comments should be clear and factual.  
- **Include test cases**: Any functional code change must include appropriate test coverage. Pull requests without tests will not be merged.  
- **English only**: All code comments, commit messages, and documentation must be written in English.  
- **Security awareness**: No unsafe shell expansions, unvalidated inputs, or credential leaks. Use of *external* libraries should be kept minimal.  
- **Consistency**: Follow existing coding style (PEP8, Black formatting).  
- **License**: Contributions are accepted under GPL-3.0-or-later, consistent with the project license.

## Development Workflow

**1. Fork and branch**  

- Fork the repository and create a branch off `main` (or the relevant maintenance branch).

- Use descriptive branch names: `fix-spelling`, `add-tests-verify`, etc.

**2. Run tests locally**  

```bash
   # Version 2
   cd v2; pytest -v
```

```bash
   # Version 1
   cd v1/test; ./runner.sh
```

**3. Ensure no regressions**

- Add tests.

- New functionality: add one or more test cases.

- Bug fix: include a regression test.

**4. Code style**

- Use Black for formatting.

- Use isort for import ordering.

- Use flake8 to catch basic errors.

**5. Commit and push**

- Write meaningful commit messages.

- Group related changes into a single commit when possible.

**6. Licensing Requirements**

All contributions to this project must be made under the GNU General Public License v3.0 or later (GPL-3.0+).

To ensure clarity and legal compliance, contributors must explicitly confirm in writing (e.g., in the PR comment or description) that:

“I am submitting this contribution under the terms of the GPL-3.0 or later.”

Checking the license box in the PR template is **not sufficient** on its own.

**7. Pull request**

- Open a PR against the correct branch.

- Describe what the PR does and why.

- Reference issues if applicable.

## CI Checks

All pull requests are automatically validated by GitHub Actions.

- The CI workflow runs tests for both v1 and v2.

- Code style checks (Black, isort, flake8) must pass.

- PRs will not be merged if CI fails.

- Run the same commands locally before pushing to avoid unnecessary iterations.

## Reporting Issues

- Use the GitHub issue tracker.

- Provide steps to reproduce, logs, or configuration details.

- Clearly state the expected vs actual behavior.

## Documentation

- Documentation changes are welcome, even for small fixes.

- Place user-facing docs in README.md or doc/.
  - Consider references in README.md to documentation in doc/.

- Use Markdown. Keep language concise and in English.
