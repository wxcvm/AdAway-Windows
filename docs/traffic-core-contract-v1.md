# M1 shared core contracts with an independent test pin

Depends on Windows M0 PR #3 and Android M0 PR #45 / M1 PR #46. All remain reviewable drafts; no merge, release or capture activation is requested by this phase.

The production Windows service remains pinned to `4470606366e614abdb308fdfe94734d28167439c` in `fetch-upstream.sh`. The proposed contract/test files alone are pinned to `c2bff508a1607c2f7a0ce19ef96109a50fa202b2` by `fetch-core-contract.sh`, in a separate verified `shared-contract/` cache. An attempted whole-server upgrade failed the actual Windows build because the newer server unconditionally includes Android headers; that upgrade was rejected. The complete newer local cache was preserved outside the checkout. A production upgrade needs a separate platform-compatibility review and regression validation.

The same C input/decision fixtures are tested by Android Java and Windows C: user override before allow exception, validated replacement before ordinary block, typed A/AAAA zero/replacement responses, REFUSED fallback for non-address zero policy, and fail-open INVALID_DATA on malformed configuration. Domain-only evidence never implies visible HTTP paths or successful network forwarding.

Native tests now accept the fixture path explicitly, avoiding duplicate fixture copies or assumptions about Android/Windows directory layout. CI fetches the pin, runs both test suites, then compiles and smoke-tests the complete Windows application/installer. PR events cannot publish the existing release feed.

Validation commands (Linux C helpers, then actual Windows CI):

```sh
bash tests/fetch-upstream-test.sh
bash fetch-upstream.sh
bash fetch-core-contract.sh
cc -std=c11 -Wall -Wextra -Werror -pedantic shared-contract/traffic_core_contract_test.c -o /tmp/core-contract-test
/tmp/core-contract-test shared-contract/traffic_core_vectors.txt
cc -std=c11 -Wall -Wextra -Werror -pedantic shared-contract/rule_norm_test.c -o /tmp/rule-norm-test
/tmp/rule-norm-test shared-contract/rule_vectors.txt
```

The contract is not yet connected to production Hosts/ABP loading, Windows native concurrent reloads, DNS response generation, general forwarding or OS recovery. Full rule-loader atomicity and real device/physical-Windows E2E remain unverified. A decrypted token-only model is never a valid OS rollback snapshot; the M0 capture gate still refuses every default route and never enables scoped capture from readiness flags alone.
