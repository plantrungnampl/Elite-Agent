# v4.0 Self-Review Validation Results

Run from the package root on 2026-08-06.

| Command | Result |
|---|---:|
| `python validation/validate_v3.py` | 39/39 passed |
| `python validation/validate_v32_hardening.py` | 68/68 passed |
| `python validation/validate_v4_memory.py` | 79/79 passed |
| `python validation/validate_v4_traceability.py` | 30/30 passed |
| `python validation/validate_package.py` | 56/56 passed |

Additional structural result:

- SQLite v3 clean-install schema: 50 tables, 35 indexes, 209 triggers.
- Clean install and v2-to-v3 migrated schema: 294/294 normalized objects equivalent.
- Cognitive JSON Schema: 19/19 required canonical definitions present.
- Implementation plan: 12/12 bounded tasks present.

These results validate the package contracts and regressions. They do not substitute for runtime benchmark, migration rehearsal, performance, usability, crash/race, or installed-product containment evidence.
