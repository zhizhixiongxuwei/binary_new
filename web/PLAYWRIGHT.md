# Playwright UI workflows

The suite exercises the Vue application through a real Chromium browser while
Vite runs in `demo` mode. The in-memory demo API is deterministic, performs no
HTTP fallback, and never starts Ghidra, Trivy, or a report worker.

## Coverage

- login, logout, reader RBAC, and protected-route redirection;
- browser file selection, chunk hashing/upload state, and preview task creation;
- task navigation, recursive file-tree expansion, and node metadata;
- decompile request gating plus searchable, read-only fixed code samples;
- fixed vulnerability filtering and disabled JSON/HTML report downloads;
- completed-report delivery controls for original JSON and streamed gzip JSON,
  including the live sample-retention label;
- administrator runtime, storage, fixed database Bundle, user, and audit tabs;
- page-level horizontal overflow, `console.error`, and uncaught browser errors.

Desktop Chromium runs every scenario. Mobile Chromium runs the scenarios tagged
`@mobile`, which cover login, upload, task/tree, decompile, report delivery, and
maintenance. Wide tables and tab bars may scroll inside their own labelled
regions; the page itself must not scroll horizontally.

## Commands

```bash
npm run test:e2e
npm run test:e2e:headed
```

From the repository root, `make web-e2e` runs the same suite. Playwright starts
the demo Vite server on `127.0.0.1:4174` and reuses it only for local runs.
Failure traces, screenshots, and videos are written under `test-results/`; the
HTML report is written under `playwright-report/`.

## Live report consistency

The second suite uses no route mocks and does not share the fixed demo port:

```bash
make live-report-e2e
```

The harness selects dynamic loopback ports, creates a disposable bind-mounted
MySQL 9.7.1 datadir, applies the real migrations, starts Gin and live-mode Vite,
and generates JSON and HTML through the API. Chromium follows the protected
route redirect, signs in, reads the task and report APIs through the page, and
downloads both immutable reports. The test then compares page/API values and
report bytes, hashes, sizes, and key fields with a direct MySQL snapshot. The
fixture explicitly contains zero analyzer runs; it proves report presentation
consistency, not third-party analyzer execution. Cleanup owns and removes every
temporary process, container, directory, and port even when an assertion fails.

The pinned `@playwright/test` package does not imply that a Chromium binary is
present. On a connected development machine, install the matching browser once:

```bash
npx playwright install chromium
```

For an offline deployment pipeline, mirror that matching browser archive and
set `PLAYWRIGHT_BROWSERS_PATH` to the managed cache. The tests are UI workflow
acceptance only. They must not be cited as proof that a real analyzer executed.
