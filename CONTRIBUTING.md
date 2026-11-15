# Contributing to cunho

Thank you for helping. cunho is open source under the AGPL-3.0 and is also offered under a commercial licence, so
contributions follow a few rules.

## Before you start

- **Contributor licence agreement.** We can only merge a contribution whose author agrees that FOAAP, Lda may
  license it under both the AGPL-3.0 and a commercial licence. Write to [paulo@foaap.app](mailto:paulo@foaap.app)
  before opening a pull request and we will send the agreement.
- **Talk first about anything large.** Open an issue that describes the problem and the change you have in mind, so
  the design can be agreed before the work is done.
- **Security problems** go to [SECURITY.md](SECURITY.md), never to a public issue.

## How changes are made

Every rule cunho enforces has a row in the binder (`binder/`), a place in the code, and a test. A change that adds or
alters a rule updates all three, and names the rule in the refusal it adds.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[demo]' pytest ruff mypy
.venv/bin/ruff check src probe tools tests && .venv/bin/ruff format --check src probe tools tests
.venv/bin/mypy src probe/eudi_probe tools tests
.venv/bin/python -m pytest -q
```

All four must pass before a pull request is reviewed. Changes to a refusal should also survive mutation testing
(`tools/mutation/mutate.py`, see [docs/operations.md](docs/operations.md)).

## Pull requests

- One topic per pull request, with a description of what changes and why, and the specification or article behind it.
- Plain, precise English in code comments, documentation and commit messages.
- Tests with every change in behaviour, including the refusals.
