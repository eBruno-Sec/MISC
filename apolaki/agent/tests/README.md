# Tests

Apolaki's suite is **pytest-style** — plain `test_*` functions, not
`unittest.TestCase` classes. `python -m unittest discover` therefore reports
**0 tests** (unittest only collects `TestCase` subclasses); that is expected, not
a failure. Use pytest.

```bash
# in the container (pytest ships in the image)
docker compose exec agent python -m pytest tests/ -q

# locally, from apolaki/agent
python -m pytest tests/ -q
```

`conftest.py` puts the flat `agent/` modules on `sys.path`, and `pytest.ini`
(in `agent/`) sets `testpaths=tests`, so a bare `pytest` from `/app` works too.
The FastAPI endpoint tests need `fastapi` + `python-multipart` (both in
`requirements.txt`); pure-analyzer tests have no such dependency.
