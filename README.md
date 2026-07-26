# datazoo-oauth2

A provider-agnostic OAuth2 library for DuckDB extensions: RFC 6749
authorization-code flow, RFC 7636 PKCE, a loopback redirect server for the
interactive browser flow, and a get-token/refresh/persist-to-secret manager
for keeping a DuckDB `SECRET` usable across restarts.

**Owner:** Joachim Rosskopf (jr@data-zoo.de).

## Why this exists

Two DuckDB extensions need OAuth2 against different identity providers:
`erpl-web` (SAP Datasphere, Microsoft Entra ID) and `duckdb-gdrive` (Google).
The mechanics -- build an authorization URL, catch the redirect, exchange a
code for tokens, refresh when they expire, keep the refreshed tokens in the
DuckDB secret -- are identical. Only the endpoints, scopes, and a couple of
provider-specific request parameters differ. This library is that shared
mechanism, extracted **behaviour-preservingly** out of `erpl-web` (see
`docs/EXTRACTION_NOTES.md` for exactly what changed and why).

`erpl-web` does not consume this library yet -- that migration is a
separate, deliberately time-boxed piece of work ("Wave 6" in
`duckdb-gdrive`'s implementation plan). Until then, this repo has one
consumer (`duckdb-gdrive`) and erpl-web keeps its own copies.

## The boundary: what's in here, what isn't

| In this library | Stays in the consuming extension |
|---|---|
| `OAuth2Config`, `OAuth2Tokens` | Endpoint URLs, scope strings |
| PKCE generation (RFC 7636) | The secret type name and its providers |
| `OAuth2FlowV2` -- build URL, exchange code, parse response | Extra authorization parameters your provider needs (set via `OAuth2Config::extra_auth_params`) |
| `OAuth2Server` -- loopback redirect catcher | Provider-specific grants (e.g. Entra client-credentials, Google service-account JWT) |
| `OAuth2Browser` -- cross-platform browser launch, port discovery | Anything naming a vendor |
| `OAuth2CallbackHandler` -- state/CSRF, timeout | |
| `OAuth2SecretTokenManager` -- get-token-with-refresh against a DuckDB secret | The concrete secret type registration and its refresh-request shape |

**REQ-A-03, made executable:** `scripts/check_no_vendor_names.sh` fails the
build if `src/` contains code (not comments) mentioning `microsoft`,
`entra`, `sap`, `datasphere`, `google`, `drive`, `azure`, or `dataverse`. Run
it yourself with `bash scripts/check_no_vendor_names.sh`, or `cmake --build
build --target check_no_vendor_names`, or just `ctest` (it's registered as
a test). See `docs/EXTRACTION_NOTES.md` for the one real violation this
caught during extraction, and one behavioural (not textual) provider leak it
*cannot* catch, that you should know about anyway.

## Two deliberate couplings (not a general-purpose OAuth2 client)

This is **not** meant to work outside a DuckDB extension:

- It depends on **DuckDB** (`ClientContext`, `KeyValueSecret`, the secret
  manager) -- the token manager's whole value is persisting refreshed
  tokens back into a DuckDB secret.
- It depends on DuckDB's **vendored httplib** (`duckdb_httplib_openssl`) for
  the loopback server and token requests, rather than inventing a second
  HTTP client or an injectable transport abstraction.

Both consumers are DuckDB extensions, so this costs nothing. Please don't
"fix" it into a generic library later.

## Consuming this library

Add as a git submodule, pinned by commit (each consumer upgrades on its own
schedule -- see the parent project's R-9), then:

```cmake
add_subdirectory(datazoo-oauth2)
target_link_libraries(your_extension PRIVATE datazoo_oauth2)
```

This repo's own `CMakeLists.txt` detects whether it has a parent directory
(i.e. whether it was `add_subdirectory()`'d) and only builds the full,
DuckDB-linked `datazoo_oauth2` target in that case -- the parent extension
is expected to already have `duckdb.hpp` and DuckDB's vendored httplib on
the include path (that's the two couplings above; this library does not
try to `find_package(DuckDB)` itself).

```cpp
#include "datazoo/oauth2/oauth2_flow_v2.hpp"
#include "datazoo/oauth2/oauth2_secret_token_manager.hpp"

using namespace erpl_web; // see "Namespace" below

OAuth2Config config;
config.client_id = "...";
config.custom_auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
config.custom_token_url = "https://oauth2.googleapis.com/token";
config.redirect_uri = "http://localhost:8080/callback";
config.scope = "https://www.googleapis.com/auth/drive.readonly";
config.extra_auth_params["access_type"] = "offline";
config.extra_auth_params["prompt"] = "consent";

OAuth2FlowV2 flow;
OAuth2Tokens tokens = flow.ExecuteFlow(config); // opens a browser, catches the redirect
```

### Namespace

Everything lives in `namespace erpl_web`, matching erpl-web's original code
exactly, so that migrating `erpl-web` onto this library (Wave 6) needs no
renames -- only include-path changes. This is a deliberate choice explained
further in `docs/EXTRACTION_NOTES.md`; new consumers should just `using
namespace erpl_web;` or fully qualify (`erpl_web::OAuth2Config`) and not
read anything into the name.

## Building and testing

Standalone (no DuckDB needed -- pure-logic sources only):

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

This builds `datazoo_oauth2_unit_tests` (Catch2 v3) from the pure-logic
sources (`oauth2_types.cpp`, `oauth2_browser.cpp`,
`oauth2_callback_handler.cpp`, `oauth2_url_pure.cpp`) plus everything in
`test/`, and also runs `check_no_vendor_names.sh` as a ctest. Every test
runs with **zero network access and zero credentials** (REQ-A-04) -- they
are pure functions over strings and in-memory state, including a live check
against the RFC 7636 Appendix B.1 published PKCE test vector.

The DuckDB-linked sources (`http_client.cpp`, `charset_converter.cpp`,
`timeout_http_client.cpp`, `oauth2_server.cpp`, `oauth2_flow_v2.cpp`,
`oauth2_secret_token_manager.cpp`) are **not** built or tested standalone --
DuckDB is not vendored into this repo. They are exercised when a consuming
extension `add_subdirectory()`s this repo and links `datazoo_oauth2`, and
covered there by that extension's own live/SQLLogicTest suite (in
`duckdb-gdrive`'s case; in `erpl-web`'s case at Wave 6, by
`test_microsoft_entra_auth.cpp` / `test_datasphere_oauth2_consolidated.cpp`,
which must pass **unchanged**).

## What's not tested here, on purpose

`OAuth2SecretTokenManager` needs a real `duckdb::ClientContext` and
`duckdb::KeyValueSecret` (secret lookup, `SecretManager::Get`,
`RegisterSecret`) to exercise end-to-end -- that is out of reach for a
no-mocks, no-DuckDB-vendored Catch2 binary. It is covered-by-consumer:
`duckdb-gdrive`'s own live SQL/e2e suite (Wave 1, `S-1.4`: a stored refresh
token survives a restart and yields a fresh access token once force-expired)
is the real test for this code path. See `docs/EXTRACTION_NOTES.md` for the
full list of what is and isn't verified yet.

## License

MIT. See `LICENSE`.
