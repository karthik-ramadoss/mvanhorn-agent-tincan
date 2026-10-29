# Tincan findings handoff — reconstructed 2026-10-29

## Provenance and scope

This is a reconstruction from retained original candidate artifacts and task reports, plus the current GitHub reads identified below. It is **not** the byte-for-byte `TINCAN-PUBLIC.md` reportedly saved on 2026-10-16: that original file could not be recovered in the current workspace or exact-title artifact search. Its completeness and original wording are therefore not asserted here.

This documentation-only handoff preserves verified findings without restarting implementation. It does not approve the candidate, change runtime behavior, rewrite `main`, merge, release, deploy, or establish current installation status. Private infrastructure addresses, credentials, session commands and internal custody details are intentionally excluded.

## Current repository snapshot

Read on 2026-10-29 through the authenticated GitHub connector:

- Repository: [karthik-ramadoss/mvanhorn-agent-tincan](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan), public.
- `main`: `ef009967060b78f12e6cdf1dd61586888bdb73ca`.
- `production` and `working`: both `fab0c6cdf92578acf1834e94e224323208b35b3b`, tree `aa1a2babd1148ec338bed40ba4e26ff39c14a559`.
- The intended division remains an upstream-mirror `main` and separate custom production/working branches. This handoff is prepared for publication on a separate documentation branch; it does not move those three refs.
- Historical candidate artifacts use `codex/production` and `codex/working`. The observed current branch names omit `codex/`. Any later implementation must reconcile those names rather than applying the candidate unchanged.

## Completed historical source work

The original candidate manifest records:

- Base: `fab0c6cdf92578acf1834e94e224323208b35b3b`.
- Candidate: `f8d3ec7b1c25caa7f3ef443f5ba370c25d190439`.
- Candidate tree: `10961cf0f911b9f14a7fb2c59efd32426e15928e`.
- Six changed files: `.github/workflows/ci.yml`, `.github/workflows/lint.yml`, `.github/workflows/govulncheck.yml`, `Makefile`, `README.md`, `CONTRIBUTING.md`.
- Proposed changes extended workflow branch filters, made release branch/repository defaults fork-specific, and documented the custom branch/release flow.
- The original checkpoint reported verification of candidate head, tree, parent, six source hashes and evidence hashes. The candidate was retained for review, not published or marked complete.

The candidate patch was retrieved during reconstruction. It shows CI push/pull-request filters expanded from `main` to include the two historical `codex/` branches; lint and vulnerability-check pull-request filters were similarly expanded. It changes `RELEASE_BRANCH` from `main` to `codex/production` and `RELEASE_REPO` from `mvanhorn/agent-tincan` to `karthik-ramadoss/mvanhorn-agent-tincan`. Explicit overrides remain part of the intended contract.

## Verified review defect: existing release-test fixtures were not updated

The retained 2026-10-16 correction handoff records an independent review reproducing a blocking regression in the candidate. `internal/cli/releasetools_test.go` still initialized/pushed `main` and asserted the upstream repository while the candidate's Makefile selected the fork and `codex/production`.

Reported affected tests:

- `TestMakeReleaseDryRun`, `TestMakeReleaseRuns`, and `TestMakeReleaseFailureDeletesLocalTag` failed the branch guard.
- `TestMakeReleaseChecks` expected the old `main` diagnostic.
- `TestMakeReleaseDryRun` expected `--repo mvanhorn/agent-tincan`.

This is a finding about candidate `f8d3ec7...`, not a claim that the current unchanged public branch has that candidate regression. The review failure was preserved in the original correction handoff; it was not rerun during this documentation-only reconstruction.

The proposed correction was to update fixture branches, related comments and branch/repository assertions while preserving explicit `RELEASE_REMOTE`, `RELEASE_BRANCH`, `RELEASE_REPO` overrides and existing release safety checks. It was not permission to weaken production release behavior to accommodate stale tests. No completed corrected candidate is established by the retained evidence.

## Test coverage and evidence limits

The original manifest records **21 passing offline checks**, explicitly limited to YAML comparisons and local Git/Make dry-run fixtures. It also explicitly records omissions:

- No Go test/race suite execution.
- No lint-binary or live vulnerability-check execution.
- No GitHub Actions execution or external-provider validation.
- Independent no-mistakes review was pending at the candidate checkpoint.
- No push, PR, merge, release, deployment, canonical completion, verified backup or cleanup.

The later release-test regression demonstrates why those 21 checks were insufficient. The correction handoff required actual complete outputs and exit statuses for:

```sh
go test ./internal/cli -run '^TestMakeRelease' -count=1
go test -race ./...
```

It also required rerunning applicable focused workflow/release checks and retaining explicit-override coverage. Those are unresolved acceptance requirements, not tests run or passed by this publication.

Current `working` reads still show `ci.yml` filtering pushes and pull requests to `main`, and the Makefile defaults `RELEASE_BRANCH ?= main` and `RELEASE_REPO ?= mvanhorn/agent-tincan`. These reads corroborate that the historical candidate changes are not on that observed branch tip.

## Remaining work, if separately resumed

1. Reconcile candidate branch names with the actual `production`/`working` layout.
2. Correct the release-test fixture/assertions alongside the branch/repository default changes.
3. Run the actual release tests, race suite and applicable focused checks; preserve failures and any environment limitations without claiming unrun checks passed.
4. Obtain independent review of the corrected exact commit and evidence.
5. Apply the repository's required delivery/review process before any implementation publication, promotion or release. This handoff grants none of those actions.

The retained task was stopped before completion. Historical session loss and unverified worker continuation were execution limitations, not evidence that the correction succeeded. No current installation, host ownership, relay identity, native quota, or infrastructure-policy claim is made here.

## Source record

Public source snapshot (immutable base ref):

- [Base commit](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan/commit/fab0c6cdf92578acf1834e94e224323208b35b3b)
- [CI workflow](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan/blob/fab0c6cdf92578acf1834e94e224323208b35b3b/.github/workflows/ci.yml)
- [Makefile](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan/blob/fab0c6cdf92578acf1834e94e224323208b35b3b/Makefile)
- [Release tests](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan/blob/fab0c6cdf92578acf1834e94e224323208b35b3b/internal/cli/releasetools_test.go)
- [Contribution instructions](https://github.com/karthik-ramadoss/mvanhorn-agent-tincan/blob/fab0c6cdf92578acf1834e94e224323208b35b3b/CONTRIBUTING.md)

Retained original artifacts read in full during reconstruction; these are historical records, not newly executed tests:

- `candidate.patch`, 9,048 bytes, recorded SHA-256 `fc7dc6ee7a8cf9648f02054b14c261576da4d1c45289371f383effed573984ee`.
- `manifest.json`, 4,925 bytes, recorded SHA-256 `1f9aae8b232c62f4c67ddca5fd12026041045547bc601a2132085d9f3f768b74`.
- Retained release-fixture correction handoff, 30,991 bytes, recorded SHA-256 `34252468859564c92664350892670a339f572e20ca7eb921227fcf37d03726ee`. Only its repository/test findings are summarized; its private operational data is not republished.
- Original task checkpoint and correction messages dated 2026-10-15/16 agree with those artifacts.

This report preserves the recoverable findings and their limits. It does not claim to reproduce any unrecovered portions of the original report.

