# Contributing to Git Permalink Fixer

First off, thank you for considering contributing to Git Permalink Fixer! Your help is appreciated.

## How Can I Contribute?

### Reporting Bugs
*   Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/huyz/git-permalink-fixer/issues).
*   If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/huyz/git-permalink-fixer/issues/new). Be sure to include a title and clear description, as much relevant information as possible, and a code sample or an executable test case demonstrating the expected behavior that is not occurring.

### Suggesting Features/Enhancements
*   Open a new issue with the label `[Feat]`.
*   Clearly describe the enhancement and the motivation for it.

### Pull Requests
1.  Fork the repo and create your branch from `main` (or the primary development branch).
2.  If you've added code that should be tested, add tests.
3.  Ensure the test suite passes (`pytest`).
4.  Make sure your code lints (e.g., using `rye lint`, `ruff`, or `pylint` + `black`).
5.  Issue that pull request!

## Styleguides

### Git Commit Messages
*   Use the present tense ("Add feature" not "Added feature").
*   Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
*   Limit the first line to 72 characters or less.
*   Reference issues and pull requests liberally after the first line.

### Python Styleguide
*   Follow PEP 8, except that we allow 120 characters per line.
*   We use `ruff` for code formatting and linting, `pylint` for more linting, and `mypy` for type checking.
*   We use `pre-commit` to enforce some of these standards. Please install it (`pipx install pre-commit` or `brew install pre-commit`) and set up the hooks (`pre-commit install`) in your local clone.

## Any questions?

Feel free to open a discussion on GitHub at [Discussions](https://github.com/huyz/git-permalink-fixer/discussions).
