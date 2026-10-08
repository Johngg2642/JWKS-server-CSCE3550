# Project 2 validation

Validated on October 8, 2026 with Python 3.12.2 on macOS arm64.

## Automated tests

- 19 tests passed.
- Combined line and branch coverage: 97.83% (`app.py`: 97%; `storage.py`: 100%).
- Ruff lint and formatting checks passed.
- Tests use temporary databases and verify persistence across application
  recreation, JWT signatures using published JWKS, expiry behavior, and SQL-like
  input handled as data.

## Official blackbox client

Used CSCE3550 gradebot release v1.1.2 from:
https://github.com/jh125486/CSCE3550/releases/tag/v1.1.2

Command (run in the repository directory):

```bash
/path/to/gradebot project-2 --dir=. --run="python app.py"
```

| Check | Awarded |
| --- | --- |
| `/auth` valid JWT authentication | 15/15 |
| Valid JWK found in JWKS | 20/20 |
| Database exists | 15/15 |
| Database query uses parameters | 15/15 |
| Quality | 4.25/5 |
| Overall | 98.93% |

The quality feedback suggested additional configuration options and storage
function documentation. The database filename follows the assignment, and the
application factory accepts an alternate database path for tests or other uses.
Every storage function has a docstring. The qualitative score may vary between
client runs. The runtime database and test client binary are not committed.
