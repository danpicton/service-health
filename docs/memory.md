# Reporter memory profile

The offline fixture in `tests/profile_memory.py` creates 21 services and 54
components with synthetic findings. Its serialized snapshot is 30,399,679
bytes. Finding arrays appear in deployment, component, and service aggregates;
the fixture's compact service rows total 61,264 bytes, compared with
30,399,637 bytes for detail rows. No real catalog, database, or credential was
used.

Run from the repository root, in separate processes:

```sh
profile_dir=$(mktemp -d /tmp/service-health-profile.XXXXXX)
PYTHONPATH=src:tests .venv/bin/python tests/profile_memory.py prepare "$profile_dir/state.db"
PYTHONPATH=src:tests .venv/bin/python tests/profile_memory.py legacy "$profile_dir/state.db"
PYTHONPATH=src:tests .venv/bin/python tests/profile_memory.py http "$profile_dir/state.db"
PYTHONPATH=src:tests .venv/bin/python tests/profile_memory.py scanner "$profile_dir/state.db"
```

`legacy` loads the HTTP handler from commit `803d54f` and restores its
whole-snapshot deep copy. `http` uses the current handler with a 256 MiB
address-space limit. Each sends 42 Homepage reads, summary/list requests,
health probes, and four detail JSON and HTML reads from four concurrent client
threads. A separate process writes three synthetic worker progress cycles to
the same SQLite database during the requests. The 2026-11-22 measurements on
the development host were:

| Process | Idle RSS | Peak RSS | After work RSS |
| --- | ---: | ---: | ---: |
| Legacy HTTP | 29 MiB | 471 MiB | 311 MiB |
| Current HTTP, 256 MiB address-space limit | 29 MiB | 53 MiB | 38 MiB |
| Worker progress writes, separate process | 29 MiB | 198 MiB | 91 MiB after three cycles |
| Injected Python scanner pass, separate process | 30 MiB | 102 MiB | 88 MiB |

The current HTTP process completed every request under the 256 MiB limit.
Largest response sizes were 859 bytes for summary, 61,386 bytes for services,
3,782 bytes for Homepage, and 1,688,159 bytes for one detail page. Before the
change, the services response was 30,399,759 bytes and one Homepage response
was 1,260,500 bytes. Four active request slots limit simultaneous parsing;
health and readiness no longer parse the snapshot. Detail reads load one
service, while summary/list/Homepage use compact rows.

Worker RSS after successive cycles was 116, 89, and 91 MiB, with no monotonic growth
in these three cycles. The Python scanner pass used an injected report and
did not launch Trivy. Trivy itself is unavailable on this development host,
so its external process peak remains unmeasured; the existing scanner 1 GiB
runtime limit is a configured limit, not a measured value. Repeat the scanner
profile with the actual deployed image and cache before lowering that limit.
RSS and address-space behavior can vary with Python, SQLite, finding sizes,
and allocator reuse. The HTTP result supports a 256 MiB limit for this fixture,
not a guarantee for arbitrarily larger catalogs or concurrent detail traffic.
Migrating a copied legacy 30.4 MB snapshot into compact rows under the same
256 MiB address-space limit completed with 93 MiB peak RSS; the migration
iterates SQLite `json_each` service rows rather than decoding the whole snapshot.
