# Extraction notes

This document records every place the move from `erpl-web` was **not** a
pure copy-paste, and why. It exists so Wave 6 (pointing `erpl-web` at this
library and deleting its copies) does not have to rediscover any of this the
hard way. Read this before touching anything in `src/`.

## Source

Everything here was copied from `erpl-web`'s `src/` and `src/include/` at
the commit current when this repo was created (2026-07-26):
`oauth2_types.{hpp,cpp}`, `oauth2_flow_v2.{hpp,cpp}`,
`oauth2_server.{hpp,cpp}`, `oauth2_browser.{hpp,cpp}`,
`oauth2_callback_handler.{hpp,cpp}`, `http_client.{hpp,cpp}`,
`timeout_http_client.{hpp,cpp}`, `charset_converter.{hpp,cpp}`, and the
token-manager half of `microsoft_entra_secret.cpp`.

## Namespace

Everything stays in `namespace erpl_web`, matching erpl-web exactly, so that
Wave 6's `erpl-web` call sites need zero changes beyond include paths. This
was a deliberate choice over `duckdb::datazoo_oauth2`: it makes the erpl-web
side of the migration (S-6.2) a pure "delete the old files, point includes
here" operation with no renames. The cost is that the namespace name reads
oddly from a library also consumed by `duckdb-gdrive` (`erpl_web::OAuth2Config`
in a Google Drive extension). That is a one-line problem to fix later with a
namespace alias if it starts to matter; it was not worth complicating the
Wave-6 gate for.

## Hidden dependencies discovered during extraction

`oauth2_flow_v2.cpp` alone pulled in a much larger dependency graph than the
five files named in the plan:

- **`timeout_http_client.{hpp,cpp}`** -- not in the original file list, but
  `OAuth2FlowV2` holds a `unique_ptr<TimeoutHttpClient>` and calls it
  directly. Moved unchanged.
- **`charset_converter.{hpp,cpp}`** -- pulled in transitively by
  `http_client.cpp` (`HttpResponse::Content()`/`ToRow()` both charset-decode
  the body). ~280 lines, self-contained (only needs `duckdb.hpp`), no vendor
  names. Moved unchanged.
- **`odata_edm.hpp`** -- `http_client.hpp` included this ~2500-line,
  OData-specific header from erpl-web purely to get the two-value
  `ODataVersion` enum used by `HttpRequest::SetODataVersion` /
  `AddODataVersionHeaders()`. Pulling in the whole OData EDM model (which
  also depends on `tinyxml2`) into an OAuth2 library would be real scope
  creep and a design smell in its own right. **Deviation:** `http_client.hpp`
  now declares a local, minimal `enum class ODataVersion { UNKNOWN, V2, V4 }`
  instead. `HttpRequest::AddODataVersionHeaders()`'s logic is byte-for-byte
  unchanged.
- **erpl-web's `tracing.hpp`** (the `ERPL_TRACE_*` macros and the
  `ErplTracer` singleton) is erpl-web's own file-rotating/leveled logger and
  was never in scope for this library. Every moved `.cpp` calls
  `ERPL_TRACE_{ERROR,WARN,INFO,DEBUG}` extensively, and `http_client.cpp`
  additionally calls `ErplTracer::Instance().IsEnabled()`. Rather than strip
  every call site (a real logic-adjacent edit, and one that would make
  future behaviour-preservation diffs against erpl-web harder to read),
  `src/include/datazoo/oauth2/tracing.hpp` provides drop-in replacements
  with the exact same macro names and a `SimpleTracer` class aliased to
  `erpl_web::ErplTracer`. By default they are silent no-ops; set
  `DATAZOO_OAUTH2_TRACE=1` in the environment (or define
  `DATAZOO_OAUTH2_TRACE_TO_STDERR` at compile time) to get simple stderr
  logging while debugging locally.

**Takeaway for Wave 6:** when erpl-web deletes its own copies of these files
and points at this library, its own `tracing.hpp` / `charset_converter.hpp` /
`timeout_http_client.hpp` become dead code in erpl-web unless something else
there still uses them directly -- check for that before deleting.

## The two named generalisations (S-0.13, S-0.14)

### S-0.13 -- `extra_auth_params`

`OAuth2Config` gained `std::map<std::string, std::string> extra_auth_params`.
`BuildAuthorizationUrl` (originally a private method of `OAuth2FlowV2`) was
extracted into a free, pure function `BuildAuthorizationUrlPure()` in
`oauth2_url_pure.{hpp,cpp}` (no DuckDB linkage) specifically so it could be
unit-tested without a live flow. `OAuth2FlowV2::BuildAuthorizationUrl` now
delegates to it in one line; the rest of `oauth2_flow_v2.cpp` is unchanged,
including its own separate, file-local, still-used `UrlEncode` and
`GenerateCodeChallenge` (see PKCE note below -- they are duplicates, on
purpose, not accidentally still there).

With an empty `extra_auth_params` map (erpl-web's current usage, and the
default), the emitted URL is byte-identical to the pre-extraction
implementation -- see `test/test_oauth2_url_pure.cpp`, the byte-identical
assertion is written out in full, not just spot-checked. With entries
present (e.g. `access_type=offline`, `prompt=consent` for Google), they are
appended as additional `&key=value` query parameters in ascending key order
(`std::map` iteration order).

### S-0.14 -- `OAuth2SecretTokenManager`

Generalised from `MicrosoftEntraTokenManager` in
`microsoft_entra_secret.cpp`. The get-token/check-expiry/refresh/write-back
skeleton is unchanged; the token URL and the exact refresh/acquisition POST
body are now supplied by the caller as an `OAuth2RefreshRequestBuilder`
(`std::function<OAuth2RefreshRequest(const KeyValueSecret&)>`), rather than
`MicrosoftEntraTokenManager` hard-coding `login.microsoftonline.com` and the
Entra `client_credentials`/`refresh_token` body shapes. The builder inspects
the secret's own fields (e.g. `grant_type`) to decide what kind of request
to build -- both "first acquisition via client_credentials" and "refresh via
refresh_token" are the builder's business, not the manager's. This covers
both erpl-web's Entra client_credentials/authorization_code secret and
Google's authorization_code + refresh_token secret with the same manager.
`RedactCommonKeys` was extracted verbatim (as a free function, since it no
longer belongs to a single concrete secret-creation class).

**Not tested by this repo's Catch2 binary**: `OAuth2SecretTokenManager`
needs a real `duckdb::ClientContext` and `duckdb::KeyValueSecret` to
exercise `GetToken`/`UpdateSecretWithTokens` end-to-end (secret lookup,
`SecretManager::Get`, `RegisterSecret`). Per the plan's own guidance ("test
what you can without a live DuckDB secret manager ... note in the README as
covered-by-consumer"), this is not stubbed out with a fake -- it is left for
the consuming extension's own SQLLogicTest / live suite (in `duckdb-gdrive`'s
case, Wave 1's `S-1.4`; in `erpl-web`'s case, the existing
`test_microsoft_entra_auth.cpp`, which is the Wave-6 gate).

## PKCE: a pre-existing defect preserved on purpose

`OAuth2Utils::GenerateCodeChallenge` in erpl-web is **not** RFC 7636
compliant -- it hashes the verifier with `std::hash` and formats it as a
64-hex-character string, not SHA-256 + base64url. It was copied
byte-for-byte, defect included, because erpl-web's own
`test_datasphere_oauth2_consolidated.cpp` (a Wave-6 gate test, must pass
**unchanged**) asserts exactly this behaviour:

```cpp
auto code_challenge = OAuth2Utils::GenerateCodeChallenge(code_verifier);
REQUIRE(code_challenge.length() == 64); // the "wrong" length pins the bug
```

"Fixing" this function to be real PKCE would change its output length to 43
characters and break that test at Wave 6. **Do not fix it.**

The *actual*, RFC-7636-correct PKCE SHA-256/base64url implementation used at
runtime by the live authorization-code flow lives, duplicated, as a private
method of `OAuth2FlowV2` (`GenerateCodeChallenge`) -- and was moved
unchanged. To give the library a testable, spec-correct primitive (needed
for `duckdb-gdrive`, since Google's real OAuth endpoint requires real PKCE),
a new, additive-only function `OAuth2Utils::GenerateCodeChallengeS256()` was
added with the identical algorithm. It is tested against the RFC 7636
Appendix B.1 published test vector in `test/test_oauth2_types.cpp` (S-0.12).
`OAuth2FlowV2`'s own private method was left untouched and still duplicates
the same algorithm inline -- deduplicating the two was judged out of scope
for a "no logic changes" extraction (see rule 1 in the task brief); a future
cleanup could have `OAuth2FlowV2::GenerateCodeChallenge` delegate to
`OAuth2Utils::GenerateCodeChallengeS256` once Wave 6 has landed and there is
a live erpl-web regression suite to run against the change.

**Consequence for `duckdb-gdrive`:** use `OAuth2Utils::GenerateCodeChallengeS256`,
never `OAuth2Utils::GenerateCodeChallenge`, for real PKCE against Google.

## REQ-A-03 (zero vendor-specific code) vs. behaviour preservation

One genuine, functional violation was found and fixed:
`OAuth2FlowV2::DisplayOAuth2Instructions` printed
`"Sign in with your SAP Datasphere credentials"` to the console during the
interactive flow. Not asserted by any test, so it was generalised to `"Sign
in with your identity provider credentials"`.

One was found and **deliberately not fixed**: `OAuth2Config::GetClientType()`
pattern-matches SAP's client-id conventions (`sb-...!b...` prefix, or a
36-character UUID) to distinguish "pre-delivered" from "custom" OAuth
clients, and `OAuth2Config::GetAuthorizationUrl()`/`GetTokenUrl()` default to
SAP BTP's URL format
(`https://<tenant>.authentication.<dc>.hana.ondemand.com/oauth/...`) when no
custom URL is set. This is genuine SAP-shaped business logic sitting inside
what HLD §5.4 designates as a library-boundary type (`OAuth2Config`). It
could not be removed without changing `GetClientType()`'s/`GetAuthorizationUrl()`'s
observable behaviour, which erpl-web's Basic-Auth-for-pre-delivered-clients
logic in `OAuth2FlowV2::ExchangeCodeForTokens` depends on, and which is
exercised by erpl-web's existing tests. It was left exactly as-is.

Neither of these two facts are visible as literal vendor-name string matches
in `scripts/check_no_vendor_names.sh` in the *compiled code* sense the
script checks (the check strips comments; the actual identifiers/patterns
involved -- `"sb-"`, a length-36 check, `.hana.ondemand.com` -- do not
contain any of the banned words). But the *behaviour* is still SAP-shaped,
and a future reader relying purely on the grep passing would miss it. This
paragraph is that documentation.

**Consequence for `duckdb-gdrive`:** do not rely on `OAuth2Config::GetClientType()`
or the default `GetAuthorizationUrl()`/`GetTokenUrl()` for anything --
`duckdb-gdrive`'s secret registration must always set `custom_auth_url` and
`custom_token_url` explicitly (which it needs to do anyway, since Google's
endpoints are fixed strings), and Google's client type is always "custom" in
this model, so `GetClientType()`'s SAP heuristics never fire for it in
practice. But they are still *there*, silently, in the type everyone shares.

## Known limitation, preserved as-is: `OAuth2Browser` port availability

`OAuth2Browser::IsPortAvailable{Windows,MacOS,Linux}` all unconditionally
`return true`; no platform actually probes the socket. `FindAvailablePort()`
therefore always returns `start_port` immediately and never detects a real
collision. This was true in erpl-web before extraction and is preserved
unchanged. Pinned by a regression test
(`test/test_oauth2_browser.cpp`, `"KNOWN LIMITATION"`) so nobody assumes
port selection is real. **`duckdb-gdrive`'s loopback `OAuth2Server` should
not rely on this for collision avoidance** -- if two flows run concurrently
on the same machine there is currently nothing stopping them from trying to
bind the same port.

## Not verified in this environment

The DuckDB-coupled sources (`http_client.cpp`, `charset_converter.cpp`,
`timeout_http_client.cpp`, `oauth2_server.cpp`, `oauth2_flow_v2.cpp`,
`oauth2_secret_token_manager.cpp`) cannot be linked or run standalone here
(no DuckDB build in this repo, by design -- see the CMake comments). They
were syntax-checked (`g++ -fsyntax-only`) against a real DuckDB source tree
(`erpl-web/duckdb`, DuckDB v1.5.x) with all of DuckDB's third-party include
paths and compiled cleanly (warnings only, no errors). They have **not**
been through a full link + run cycle, and `OAuth2SecretTokenManager` in
particular has no automated test coverage at all yet (see above). The first
real verification will be when `duckdb-gdrive` (Wave 1) or `erpl-web`
(Wave 6) actually `add_subdirectory()`s this repo and links it.
