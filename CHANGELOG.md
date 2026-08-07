# [1.2.0](https://github.com/polarpoint-io/tenable-exporter/compare/v1.1.4...v1.2.0) (2026-08-07)


### Features

* add exporter self-monitoring metrics (scrape duration, success, counts) ([17d2d40](https://github.com/polarpoint-io/tenable-exporter/commit/17d2d40cceca7b48d2494b8d651af166c105df6e))

## [1.1.4](https://github.com/polarpoint-io/tenable-exporter/compare/v1.1.3...v1.1.4) (2026-08-06)


### Bug Fixes

* add workflow_dispatch to build and cancel stale CI queues. ([62172b9](https://github.com/polarpoint-io/tenable-exporter/commit/62172b96ee8026ce324918e26df1fecab832e5ce))
* correct helm-release workflow file permissions. ([afd4620](https://github.com/polarpoint-io/tenable-exporter/commit/afd46205b18413be02fd7a79c165d24c1cf3d2b7))
* restore push-triggered semantic-release on main. ([c8185fc](https://github.com/polarpoint-io/tenable-exporter/commit/c8185fc3de15d5996b98a73c5107fcc9d4efbe58))
* unblock semantic-release and add manual CI dispatch. ([9aad550](https://github.com/polarpoint-io/tenable-exporter/commit/9aad55057e3bf89025d29209c2bfffdc7bbf82da))

## [1.1.3](https://github.com/polarpoint-io/tenable-exporter/compare/v1.1.2...v1.1.3) (2026-06-09)


### Bug Fixes

* use py-modules so exporter.py is included in the wheel ([926f78d](https://github.com/polarpoint-io/tenable-exporter/commit/926f78d63b572b8a1d6c05413324a977dff16acb))

## [1.1.2](https://github.com/polarpoint-io/tenable-exporter/compare/v1.1.1...v1.1.2) (2026-06-05)


### Bug Fixes

* REGISTRY_HOST env was overriding registry path in semantic-release-helm3 ([8e98125](https://github.com/polarpoint-io/tenable-exporter/commit/8e98125d39f135c15d75c802c082f8ef188668a7))

## [1.1.1](https://github.com/polarpoint-io/tenable-exporter/compare/v1.1.0...v1.1.1) (2026-06-05)


### Bug Fixes

* semantic-release-helm3 registry/folder split for GHCR OCI push ([e4da63e](https://github.com/polarpoint-io/tenable-exporter/commit/e4da63e312240a36498dfeb24dded08159e7ad89))

# [1.1.0](https://github.com/polarpoint-io/tenable-exporter/compare/v1.0.0...v1.1.0) (2026-06-05)


### Features

* add Helm chart and semantic-release-helm3 pipeline ([07a39fa](https://github.com/polarpoint-io/tenable-exporter/commit/07a39fa0c3b344e4ed3f050e688283a1c81879ab))

# 1.0.0 (2026-06-02)


### Bug Fixes

* add pythonpath to pytest config so tests can import exporter ([533b8fc](https://github.com/polarpoint-io/tenable-exporter/commit/533b8fcb97349c1869dfb48bbb86ffdd157e04de))


### Features

* exploit risk, VPR bands, state tracking, compliance, tag metrics ([7932c91](https://github.com/polarpoint-io/tenable-exporter/commit/7932c91258470766317f8e31683b7d3820fec6c9))
