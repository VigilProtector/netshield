## [0.1.5](https://github.com/VigilProtector/netshield/compare/v0.1.4...v0.1.5) (2026-05-15)

### Bug Fixes

* **ci:** pin semantic-release deps via package.json + lockfile ([cd48cea](https://github.com/VigilProtector/netshield/commit/cd48cea3699cadbe66bd909ce7443030cf3feaf6))

## [0.1.4](https://github.com/VigilProtector/netshield/compare/v0.1.3...v0.1.4) (2026-05-15)

### Bug Fixes

* **ci:** adopt pulsepatrol package.json + lockfile verbatim ([f2a2702](https://github.com/VigilProtector/netshield/commit/f2a270233d610a7e228b5440b43a14c73a06985e))
* **ci:** make semantic-release dry-run version parser specific ([b47420c](https://github.com/VigilProtector/netshield/commit/b47420c607b7653f2a05664cf133d17c7340b1c6))

## [0.1.3](https://github.com/VigilProtector/netshield/compare/v0.1.2...v0.1.3) (2026-05-15)

### Bug Fixes

* **ci:** drop setup-node npm cache (no package-lock.json in repo) ([f13ff72](https://github.com/VigilProtector/netshield/commit/f13ff72bf32edaae28db7e30522abe87c74440dd))
* **ci:** port working pulsepatrol/vigilnet release pattern ([007ee37](https://github.com/VigilProtector/netshield/commit/007ee37ea62e50faac8cb5f0eaf41ccf45009ec3))

## [0.1.2](https://github.com/VigilProtector/netshield/compare/v0.1.1...v0.1.2) (2026-05-15)

### Bug Fixes

* **docker:** drop inline comments from EXPOSE + uppercase AS ([2ab90d5](https://github.com/VigilProtector/netshield/commit/2ab90d5e2c44373a9d4691965ab3ac7f71d61de6))

## [0.1.1](https://github.com/VigilProtector/netshield/compare/v0.1.0...v0.1.1) (2026-05-15)

### Bug Fixes

* **ci:** downcase docker image name + use PIPELINE_TOKEN for semantic-release ([fd7c5db](https://github.com/VigilProtector/netshield/commit/fd7c5dbe6d802fa2b088d35e367a35a0957d20f8))

## [0.1.0](https://github.com/VigilProtector/netshield/compare/v0.0.0...v0.1.0) (2026-05-15)

### Features

* **client:** real pull-cursor baseline subscriber per VP-2225 + VP-2233 ([23726b2](https://github.com/VigilProtector/netshield/commit/23726b26f6ec091ab42f9b24c9c437a12d34e36f))
* **crossbc:** explicit conflict resolution for cross-BC enrichment per VP-2235 ([e415cb0](https://github.com/VigilProtector/netshield/commit/e415cb02c1c3104bbb4052606f2088a57208767a))
* **main:** add BaselineCache and integrate StratoSage with caching in NetShield ([3675e0b](https://github.com/VigilProtector/netshield/commit/3675e0b9e4daf9f7e86712aeb6f044a55cd38493))
* **netshield:** implement NH-CC-005 cross-BC queries and wire NH-LM-005/006/007 ([c31b6ac](https://github.com/VigilProtector/netshield/commit/c31b6ac3672f6f9120ca5337b30d8104dc49668f))
* **netshield:** Phase 10 implementation complete ([2eb7bcc](https://github.com/VigilProtector/netshield/commit/2eb7bccc3bdc3829fc744b1adf73eca2a624e6bf))
* **netshield:** wire FlowSeekerConsumer for finding subscription (NH-LM-005) ([f381e02](https://github.com/VigilProtector/netshield/commit/f381e0290cf01808707978e4d6d4ee60f56a497e))
* **router:** dual-path migration to /api/stratoward/v1/netshield/ per VP-2252 ([d3131b0](https://github.com/VigilProtector/netshield/commit/d3131b07e3e146d1dc6661e8d0c13db6c37f49cc))
* **sensor:** assign default ruleset on Register per VP-2231 ([62d6a78](https://github.com/VigilProtector/netshield/commit/62d6a786333ef3182b077dc6102f2c83d9c0d4cf))
* **service:** add AuthZ checks to all service methods ([cb0d10a](https://github.com/VigilProtector/netshield/commit/cb0d10a797451456030918c1ad5a99348cd53572))
* **service:** implement Lateral Movement detection (NH-LM-001..007) ([490a8be](https://github.com/VigilProtector/netshield/commit/490a8becf050f8ced4dc93029582813002ac4e15))
* **service:** implement SS-BP-004 StratoSage subscription consumer ([614f06f](https://github.com/VigilProtector/netshield/commit/614f06fa3a7dd89adddf3843fafb5ecac10e3c26))
* **service:** surface lateral-movement reason codes on emitted Finding per VP-2234 ([9349c00](https://github.com/VigilProtector/netshield/commit/9349c00d7d46cdfd8dbc89553745c041aa53e7d8))

### Bug Fixes

* **ci:** install conventional-changelog-conventionalcommits in release workflow ([8c30794](https://github.com/VigilProtector/netshield/commit/8c3079462603507ef9d552daa3cdaf1f42cd3fb3))
* **crossbc:** dampen confidence + emit AdapterErrors when sources fail ([c83d78b](https://github.com/VigilProtector/netshield/commit/c83d78bb1986782bbd4bb3eae7da763ec7fde59b))
* **handler:** add CorrelationID propagation and Limit Max-Cap validation ([b38b8ec](https://github.com/VigilProtector/netshield/commit/b38b8ec3635168f1ce96ddb085d1182a743a4e61))
* **lint:** migrate .golangci.yaml to v2 schema and add nolint explanations ([3160afe](https://github.com/VigilProtector/netshield/commit/3160afe1a4eea19b618f156284372e4af5588804))
* **lint:** replace if-else chains with tagged switches (QF1003) ([554d62c](https://github.com/VigilProtector/netshield/commit/554d62c642c90ab3f1f5e277749d7ecd8f023563))
* **lint:** resolve all 216 golangci-lint issues ([1cc2e76](https://github.com/VigilProtector/netshield/commit/1cc2e7622a91875b0818570f5afaec2940eac7c7))
* **netshield:** add AuthZ checks to DetectionService methods ([4eb3900](https://github.com/VigilProtector/netshield/commit/4eb3900f68e37c28c41cb1501d908c546c74a821)), closes [#2](https://github.com/VigilProtector/netshield/issues/2) [#6](https://github.com/VigilProtector/netshield/issues/6) [#4](https://github.com/VigilProtector/netshield/issues/4)
* **netshield:** add webhook handlers for NH-SM-006/007 cross-repo compatibility ([64203bd](https://github.com/VigilProtector/netshield/commit/64203bd884452d78c778700c6d69c07dd4622bda))
* **netshield:** fix failing whitespace test in utils_test.go and broken Makefile test target ([81345e8](https://github.com/VigilProtector/netshield/commit/81345e895221062315b3f1f3ebe4882a506c2961)), closes [#3](https://github.com/VigilProtector/netshield/issues/3)
* **netshield:** resolve DATA RACE issues in service layer ([ea71b73](https://github.com/VigilProtector/netshield/commit/ea71b73f61729f1b0c2ec764383d33ae91f3f2d9))
* **netshield:** resolve P0 blockers for Phase 10 PR ([e611a76](https://github.com/VigilProtector/netshield/commit/e611a76f49c92f3ff609107cbadda5557c5f4432)), closes [#1](https://github.com/VigilProtector/netshield/issues/1) [#2](https://github.com/VigilProtector/netshield/issues/2) [#6](https://github.com/VigilProtector/netshield/issues/6) [#4](https://github.com/VigilProtector/netshield/issues/4) [#1](https://github.com/VigilProtector/netshield/issues/1) [#2](https://github.com/VigilProtector/netshield/issues/2) [#4](https://github.com/VigilProtector/netshield/issues/4) [#6](https://github.com/VigilProtector/netshield/issues/6)
* **nh-lm-004:** window-aggregate lateral-movement features over time window ([a4d8feb](https://github.com/VigilProtector/netshield/commit/a4d8feb50995568bc2fd2a1746da4212b34f930b))
* **router:** resolve Gin route conflicts and add basic tests ([6249ba1](https://github.com/VigilProtector/netshield/commit/6249ba1cd5874ff44c5047de1f75d6402f35b99b))
* **service:** address CodeX P1/P2 findings in netshield[#4](https://github.com/VigilProtector/netshield/issues/4) ([9ab0130](https://github.com/VigilProtector/netshield/commit/9ab0130d21e02f4da74efa801d297fee245de354))
* **service:** update lateral movement tests for new constructor signature ([c611f9d](https://github.com/VigilProtector/netshield/commit/c611f9d7a9456bbf625b8da4be2cb2b4e779accf))
