# Changelog

## [0.6.1](https://github.com/opentdf/java-sdk/compare/v0.7.0...v0.6.1) (2024-08-27)


### Features

* update README.md ([#142](https://github.com/opentdf/java-sdk/issues/142)) ([198d335](https://github.com/opentdf/java-sdk/commit/198d3351c544cc1e23d62b4d097fb7310a7a3625))


### Bug Fixes

* **nano:** Store key ids if found ([#134](https://github.com/opentdf/java-sdk/issues/134)) ([94c672b](https://github.com/opentdf/java-sdk/commit/94c672b1e6617a5e6bd0b4339d38a9aae3ae2ae1))


### Miscellaneous Chores

* release 0.6.1 Release-As: 0.6.1 ([#135](https://github.com/opentdf/java-sdk/issues/135)) ([09ec548](https://github.com/opentdf/java-sdk/commit/09ec5480c6ad5c4f958d051c0ef668b68e13637c))

## [0.6.1](https://github.com/opentdf/java-sdk/compare/v0.6.0...v0.6.1) (2024-08-26)


### Bug Fixes

* **core:** Add support for certs ([#131](https://github.com/opentdf/java-sdk/issues/131)) ([2f98a3a](https://github.com/opentdf/java-sdk/commit/2f98a3a099a1bde796669bf84eeb3f673cbb5d40))


### Miscellaneous Chores

* release 0.6.1 Release-As: 0.6.1 ([#135](https://github.com/opentdf/java-sdk/issues/135)) ([09ec548](https://github.com/opentdf/java-sdk/commit/09ec5480c6ad5c4f958d051c0ef668b68e13637c))

## [0.6.0](https://github.com/opentdf/java-sdk/compare/v0.5.0...v0.6.0) (2024-08-23)


### Features

* **core:** Add autoconfigure for key splitting ([#120](https://github.com/opentdf/java-sdk/issues/120)) ([7ecbf23](https://github.com/opentdf/java-sdk/commit/7ecbf231d9fa1fd07c1c426489fd160602c2883a))
* **core:** Adding key cache, tests for specificity ([#126](https://github.com/opentdf/java-sdk/issues/126)) ([a149887](https://github.com/opentdf/java-sdk/commit/a14988781f9ad83d8e01b83a3a612aa8f2563bbb))


### Bug Fixes

* **core:** Revert "feat(core): Add attributes client" ([#124](https://github.com/opentdf/java-sdk/issues/124)) ([3d1ef2b](https://github.com/opentdf/java-sdk/commit/3d1ef2b5791de989c4242498787617286fad44bf))
* ztdf support both base and handling assertions ([#128](https://github.com/opentdf/java-sdk/issues/128)) ([5f72e94](https://github.com/opentdf/java-sdk/commit/5f72e9448aa03ca43065cb024d6e783573a3ba29))

## [0.5.0](https://github.com/opentdf/java-sdk/compare/v0.4.0...v0.5.0) (2024-08-19)


### Features

* BACK-2316 add a simple method to detect TDFs ([#111](https://github.com/opentdf/java-sdk/issues/111)) ([bfbef70](https://github.com/opentdf/java-sdk/commit/bfbef70d05bdf8a0e6784d27395966f97d42d90d))
* **cmd:** Adds command `--mime-type` opt ([#113](https://github.com/opentdf/java-sdk/issues/113)) ([45a2c30](https://github.com/opentdf/java-sdk/commit/45a2c30d1a822bfe629daf032f95f13065c36126))
* **core:** Add attributes client ([#118](https://github.com/opentdf/java-sdk/issues/118)) ([98ba6a9](https://github.com/opentdf/java-sdk/commit/98ba6a9e91f8e4b1903f907583356c084abb3313))
* **core:** Handle split keys on tdf3 encrypt and decrypt ([#109](https://github.com/opentdf/java-sdk/issues/109)) ([943751f](https://github.com/opentdf/java-sdk/commit/943751ff83b67089472e4422fcfa087e76a8072a))
* **core:** KID in NanoTDF ([#112](https://github.com/opentdf/java-sdk/issues/112)) ([33b5982](https://github.com/opentdf/java-sdk/commit/33b59820b2830b15c9ec467f45cfab0f1eb38017))
* **sdk:** Update the assertion support to match go sdk ([#117](https://github.com/opentdf/java-sdk/issues/117)) ([f9badb3](https://github.com/opentdf/java-sdk/commit/f9badb383d769ecbf51c551483633ccb94b2915a))


### Bug Fixes

* Issue [#115](https://github.com/opentdf/java-sdk/issues/115) - fix for SSL Context for IDP and plaintext platform ([#116](https://github.com/opentdf/java-sdk/issues/116)) ([36a29df](https://github.com/opentdf/java-sdk/commit/36a29dfd66660c04d55cd100bdcd7e8742edd40b))

## [0.4.0](https://github.com/opentdf/java-sdk/compare/v0.3.0...v0.4.0) (2024-08-09)


### Features

* **ci:** Add xtest workflow trigger ([#96](https://github.com/opentdf/java-sdk/issues/96)) ([bc54b63](https://github.com/opentdf/java-sdk/commit/bc54b636c183c99d86a10e566aa33455879ac084))
* **core:** NanoTDF resource locator protocol bit mask ([#107](https://github.com/opentdf/java-sdk/issues/107)) ([159d2f1](https://github.com/opentdf/java-sdk/commit/159d2f1c5cb4bb3f1257dc5a15a61789211d6848))
* **sdk:** add mime type. ([#108](https://github.com/opentdf/java-sdk/issues/108)) ([6c4a27b](https://github.com/opentdf/java-sdk/commit/6c4a27b0c608e198b41c395491aff837e883c77b))


### Bug Fixes

* make sure we do not deserialize null ([#97](https://github.com/opentdf/java-sdk/issues/97)) ([9579c42](https://github.com/opentdf/java-sdk/commit/9579c427eb26d1020585fdd359551e4e0685a85a))
* policy-binding new structure ([#95](https://github.com/opentdf/java-sdk/issues/95)) ([b10a61e](https://github.com/opentdf/java-sdk/commit/b10a61ecb30c6cbf2f6cf190a249269b824bf5d3))

## [0.3.0](https://github.com/opentdf/java-sdk/compare/v0.2.0...v0.3.0) (2024-07-18)


### Features

* **sdk:** expose GRPC auth service components ([#92](https://github.com/opentdf/java-sdk/issues/92)) ([2595cc5](https://github.com/opentdf/java-sdk/commit/2595cc57f65b1757d60e4ae04814f85bc340c2e6))


### Bug Fixes

* **sdk:** give a test framework test scope ([#90](https://github.com/opentdf/java-sdk/issues/90)) ([b99de43](https://github.com/opentdf/java-sdk/commit/b99de43461b96c05b6997999a4187bfad8927b44))

## [0.2.0](https://github.com/opentdf/java-sdk/compare/v0.1.0...v0.2.0) (2024-07-15)


### Features

* **sdk:** the authorization service is needed for use by gateway ([#85](https://github.com/opentdf/java-sdk/issues/85)) ([73cac82](https://github.com/opentdf/java-sdk/commit/73cac825e0367d502d542cf0eae30a6ac38f6a00))
* support key id in ztdf key access object ([#84](https://github.com/opentdf/java-sdk/issues/84)) ([862460a](https://github.com/opentdf/java-sdk/commit/862460a16875693a421bbe57983bb829a49866bb))


### Bug Fixes

* **sdk:** assertion support in tdf3 ([#82](https://github.com/opentdf/java-sdk/issues/82)) ([c299dbd](https://github.com/opentdf/java-sdk/commit/c299dbdcb0c714a4c69faf24c60e2da58a68e99e))


### Documentation

* **sdk:** Adds brief usage code sample ([#26](https://github.com/opentdf/java-sdk/issues/26)) ([79215c7](https://github.com/opentdf/java-sdk/commit/79215c7b1ff694914df438491a40662803462dc6))

## 0.1.0 (2024-06-13)


### Features

* add code to create services for SDK ([#35](https://github.com/opentdf/java-sdk/issues/35)) ([28513e6](https://github.com/opentdf/java-sdk/commit/28513e6df1f31f762eddd50ee81b2d57cd7aa753))
* add logging ([#49](https://github.com/opentdf/java-sdk/issues/49)) ([9d20647](https://github.com/opentdf/java-sdk/commit/9d20647cdf2b8862ab54259d915958057f1c3986))
* Add NanoTDF E2E Tests ([#75](https://github.com/opentdf/java-sdk/issues/75)) ([84f9bd1](https://github.com/opentdf/java-sdk/commit/84f9bd1d73d511b6a29c5782643cef674eec798b))
* **codegen:** Generate and publish Java Proto generated artifacts ([#2](https://github.com/opentdf/java-sdk/issues/2)) ([2328fd2](https://github.com/opentdf/java-sdk/commit/2328fd2bec21fb6060beca2b1bac34550eadca4e))
* crypto API ([#33](https://github.com/opentdf/java-sdk/issues/33)) ([b8295b7](https://github.com/opentdf/java-sdk/commit/b8295b74ae172fef101447e989a693c56da555a6))
* NanoTDF Implementation ([#46](https://github.com/opentdf/java-sdk/issues/46)) ([6485326](https://github.com/opentdf/java-sdk/commit/6485326f5d70762b223871f9f8b91306aed75f15))
* **PLAT-3087:** zip reader-writer ([#23](https://github.com/opentdf/java-sdk/issues/23)) ([3eeb626](https://github.com/opentdf/java-sdk/commit/3eeb6265805e18f1cf80970b2627b1ff47825c1b))
* SDK Encrypt (with mocked rewrap) ([#45](https://github.com/opentdf/java-sdk/issues/45)) ([d67daa2](https://github.com/opentdf/java-sdk/commit/d67daa262a6c3c8a40c1bbab9b86b31460bf6474))
* **sdk:** add CLI and integration tests ([#64](https://github.com/opentdf/java-sdk/issues/64)) ([df20e6d](https://github.com/opentdf/java-sdk/commit/df20e6dbc6fc1d37553b79b769315db5a64334a1))
* **sdk:** add ssl context ([#58](https://github.com/opentdf/java-sdk/issues/58)) ([80246a9](https://github.com/opentdf/java-sdk/commit/80246a9da9d5507da77318e9f7916058270a9526))
* **sdk:** get e2e rewrap working ([#52](https://github.com/opentdf/java-sdk/issues/52)) ([fe2c04b](https://github.com/opentdf/java-sdk/commit/fe2c04b6a903e587ba8ee790fe87c6b1c529d06a))
* **sdk:** Issue [#60](https://github.com/opentdf/java-sdk/issues/60) - expose SDK ([#61](https://github.com/opentdf/java-sdk/issues/61)) ([ddef62a](https://github.com/opentdf/java-sdk/commit/ddef62ad28bde23fe24b3908ddb86c7a01336560))
* **sdk:** provide access tokens dynamically to KAS ([#51](https://github.com/opentdf/java-sdk/issues/51)) ([04ca715](https://github.com/opentdf/java-sdk/commit/04ca71509019b3903b20bfcea2b8cb479d68aade))
* **sdk:** update archive support ([#47](https://github.com/opentdf/java-sdk/issues/47)) ([29a80a9](https://github.com/opentdf/java-sdk/commit/29a80a917fcb60625107ebb278955624d5dc5463))


### Bug Fixes

* create TDFs larger than a single segment ([#65](https://github.com/opentdf/java-sdk/issues/65)) ([e1da325](https://github.com/opentdf/java-sdk/commit/e1da32564f7f2ef0a32dbe39657f2cf3459badb4))
* fix pom for release please ([#77](https://github.com/opentdf/java-sdk/issues/77)) ([3a3c357](https://github.com/opentdf/java-sdk/commit/3a3c357be1490a9a780877af0da9ee29f14ebbba))
* Force BC provider use ([#76](https://github.com/opentdf/java-sdk/issues/76)) ([1bc9dd9](https://github.com/opentdf/java-sdk/commit/1bc9dd988dd79fbfeb7ee9422ad66d967deaffa6))
* get rid of duplicate channel logic ([#59](https://github.com/opentdf/java-sdk/issues/59)) ([1edd666](https://github.com/opentdf/java-sdk/commit/1edd666c4141ee7cc71eda1d1f51cc792b24a874))
* **sdk:** allow SDK to handle protocols in addresses ([#70](https://github.com/opentdf/java-sdk/issues/70)) ([97ae8ee](https://github.com/opentdf/java-sdk/commit/97ae8eebb53d619d8b31ca780c7dea89ec605aaa))
* **sdk:** make sdk auto closeable ([#63](https://github.com/opentdf/java-sdk/issues/63)) ([c1bbbb4](https://github.com/opentdf/java-sdk/commit/c1bbbb43b6d5528ff878ab8b32ba3b6d6c29839d))
