# Changelog

## [0.7.7](https://github.com/opentdf/java-sdk/compare/v0.7.6...v0.7.7) (2025-04-07)


### Features

* **sdk:** EC-wrapped key support for ZTDF ([#224](https://github.com/opentdf/java-sdk/issues/224)) ([d062691](https://github.com/opentdf/java-sdk/commit/d062691887320b16e4271a63de6bae3bb8645000))


### Bug Fixes

* **cmdline:** Disable failing encryptnano ecdsa ([#227](https://github.com/opentdf/java-sdk/issues/227)) ([80ca207](https://github.com/opentdf/java-sdk/commit/80ca207bf663f2797bfc02b3f9135e169ef5f66d))
* **cmdline:** Enable ec-wrapped cfg ([#231](https://github.com/opentdf/java-sdk/issues/231)) ([ee39ed5](https://github.com/opentdf/java-sdk/commit/ee39ed573c40e66e028ea48c0e71885f37472a52))
* if a version &lt; 4.3.0 is specified create an old-style TDF ([#234](https://github.com/opentdf/java-sdk/issues/234)) ([082a9e7](https://github.com/opentdf/java-sdk/commit/082a9e71657ff18f811b5f560aec0099ebe623b3))
* **sdk:** Fixes nano ECDSA policy binding config ([#225](https://github.com/opentdf/java-sdk/issues/225)) ([f3e9fed](https://github.com/opentdf/java-sdk/commit/f3e9fedcc68c85625e4a1aab46600c046d65e244))
* **sdk:** Remove temporary ec salt value ([#228](https://github.com/opentdf/java-sdk/issues/228)) ([0fe37c6](https://github.com/opentdf/java-sdk/commit/0fe37c6cd136c9a58708677ceac56488ec1c1e46))
* **sdk:** Set ec-wrapped to new salt value ([#230](https://github.com/opentdf/java-sdk/issues/230)) ([d3be28e](https://github.com/opentdf/java-sdk/commit/d3be28ee1dcff63b8e146c01eaf7d797af122856))
* **sdk:** Update version information ([#232](https://github.com/opentdf/java-sdk/issues/232)) ([f9eeb0d](https://github.com/opentdf/java-sdk/commit/f9eeb0da8b2cf07d1dea222bd16f7eac5a8de390))

## [0.7.6](https://github.com/opentdf/java-sdk/compare/v0.7.5...v0.7.6) (2025-02-06)


### Features

* Add assertion verification ([#216](https://github.com/opentdf/java-sdk/issues/216)) ([e0f8caf](https://github.com/opentdf/java-sdk/commit/e0f8caf34055a829a5f40dc3608b7573bfbd5f71))
* **cmdline:** assertions cli support ([#204](https://github.com/opentdf/java-sdk/issues/204)) ([3325114](https://github.com/opentdf/java-sdk/commit/332511402d9cdaf57e3e25f5030dbc0107994d9b))
* **sdk:** Add and expose tamper error types ([#187](https://github.com/opentdf/java-sdk/issues/187)) ([b4f95e6](https://github.com/opentdf/java-sdk/commit/b4f95e6756f1f60fdfc8b0c2addc4e51aca4352b))
* **sdk:** adds Collections API ([#212](https://github.com/opentdf/java-sdk/issues/212)) ([1ee1367](https://github.com/opentdf/java-sdk/commit/1ee13672aa22cad1d6ca391508eb859c5617a9a0))


### Bug Fixes

* Correct null assertions when deserializing ([#211](https://github.com/opentdf/java-sdk/issues/211)) ([b075194](https://github.com/opentdf/java-sdk/commit/b07519407ee128c6fed0596a679cdf637cf749fc))
* incorrect isStreamable serialized name ([#210](https://github.com/opentdf/java-sdk/issues/210)) ([32825b0](https://github.com/opentdf/java-sdk/commit/32825b0b79e004a19f5099e4af2bcc8754d78622))
* NanoTDF secure key from debug logging and iv conflict risk ([#208](https://github.com/opentdf/java-sdk/issues/208)) ([6301d32](https://github.com/opentdf/java-sdk/commit/6301d32c17b31c710073d898edcc2fb4ff1d3e36))
* **sdk:** deserialize object statement values correctly ([#219](https://github.com/opentdf/java-sdk/issues/219)) ([c513e8c](https://github.com/opentdf/java-sdk/commit/c513e8c7204d1c0b15a0031d9b829be3a98d04e6))
* **sdk:** Fuzz testing and protocol fixes ([#214](https://github.com/opentdf/java-sdk/issues/214)) ([cf6f932](https://github.com/opentdf/java-sdk/commit/cf6f9328ef32efbb130ce0f2ba39f5655125282c))
* **sdk:** group splits with empty/missing split IDs together ([#217](https://github.com/opentdf/java-sdk/issues/217)) ([0f47702](https://github.com/opentdf/java-sdk/commit/0f477029ce355eced8710b9d7f09ab5840ba680e))
* **sdk:** remove hex encoding ([#213](https://github.com/opentdf/java-sdk/issues/213)) ([e076d11](https://github.com/opentdf/java-sdk/commit/e076d1174edbcf9e03b52d356a4b3f73d7fea6eb))
* **sdk:** uses offset for ByteBuffer array offset ([#209](https://github.com/opentdf/java-sdk/issues/209)) ([0d6e761](https://github.com/opentdf/java-sdk/commit/0d6e7616f0d57d461a0f9002f395f8e2c7365cd3))
* Use reusable start-additional-kas workflow ([#215](https://github.com/opentdf/java-sdk/issues/215)) ([cb6f757](https://github.com/opentdf/java-sdk/commit/cb6f757b170e326872767bc0b68a7d1dcf9ac24c))

## [0.7.5](https://github.com/opentdf/java-sdk/compare/v0.7.4...v0.7.5) (2024-10-29)


### Features

* Examples module ([#202](https://github.com/opentdf/java-sdk/issues/202)) ([ac13a0a](https://github.com/opentdf/java-sdk/commit/ac13a0a7c82caed920238244cf7adaca3039fdea))


### Bug Fixes

* **sdk:** option to disable assertion verification ([#205](https://github.com/opentdf/java-sdk/issues/205)) ([78d7b66](https://github.com/opentdf/java-sdk/commit/78d7b66e40bb52340e604ab645830287c91ba534))

## [0.7.4](https://github.com/opentdf/java-sdk/compare/v0.7.3...v0.7.4) (2024-10-24)


### Bug Fixes

* **sdk:** returns the correct string associated with enums ([#200](https://github.com/opentdf/java-sdk/issues/200)) ([1dffd35](https://github.com/opentdf/java-sdk/commit/1dffd35374c40ebaa095594d2a5db138957c6e38))


### Documentation

* JavaDoc ([#196](https://github.com/opentdf/java-sdk/issues/196)) ([33c9513](https://github.com/opentdf/java-sdk/commit/33c9513de68954cccba854d501ba26b62216df89))
* minor Java SDK README updates ([#193](https://github.com/opentdf/java-sdk/issues/193)) ([e9dc738](https://github.com/opentdf/java-sdk/commit/e9dc738cc40ffc97d3f0084086b1afa1c283850c))

## [0.7.3](https://github.com/opentdf/java-sdk/compare/v0.7.2...v0.7.3) (2024-10-09)


### Features

* **sdk:** deserialize policy objects ([#179](https://github.com/opentdf/java-sdk/issues/179)) ([39582f3](https://github.com/opentdf/java-sdk/commit/39582f37944890af287a4acc2219bcf45642c93a))

## [0.7.2](https://github.com/opentdf/java-sdk/compare/v0.7.0...v0.7.2) (2024-10-08)


### ⚠ BREAKING CHANGES

* move to single jar ([#160](https://github.com/opentdf/java-sdk/issues/160))

### Features

* add code to create services for SDK ([#35](https://github.com/opentdf/java-sdk/issues/35)) ([28513e6](https://github.com/opentdf/java-sdk/commit/28513e6df1f31f762eddd50ee81b2d57cd7aa753))
* add logging ([#49](https://github.com/opentdf/java-sdk/issues/49)) ([9d20647](https://github.com/opentdf/java-sdk/commit/9d20647cdf2b8862ab54259d915958057f1c3986))
* Add NanoTDF E2E Tests ([#75](https://github.com/opentdf/java-sdk/issues/75)) ([84f9bd1](https://github.com/opentdf/java-sdk/commit/84f9bd1d73d511b6a29c5782643cef674eec798b))
* adds token exchange and general auth ([#176](https://github.com/opentdf/java-sdk/issues/176)) ([bb325c4](https://github.com/opentdf/java-sdk/commit/bb325c442c7d6c34062d568319549d711e9ccc35))
* BACK-2316 add a simple method to detect TDFs ([#111](https://github.com/opentdf/java-sdk/issues/111)) ([bfbef70](https://github.com/opentdf/java-sdk/commit/bfbef70d05bdf8a0e6784d27395966f97d42d90d))
* **build:** maven refactor for maven central ([#174](https://github.com/opentdf/java-sdk/issues/174)) ([c640773](https://github.com/opentdf/java-sdk/commit/c6407739f6424c36ca7fc8e731cd0eb6540c1344)), closes [#79](https://github.com/opentdf/java-sdk/issues/79)
* **ci:** Add xtest workflow trigger ([#96](https://github.com/opentdf/java-sdk/issues/96)) ([bc54b63](https://github.com/opentdf/java-sdk/commit/bc54b636c183c99d86a10e566aa33455879ac084))
* **cmd:** Adds command `--mime-type` opt ([#113](https://github.com/opentdf/java-sdk/issues/113)) ([45a2c30](https://github.com/opentdf/java-sdk/commit/45a2c30d1a822bfe629daf032f95f13065c36126))
* **cmdline:** Adds --ecdsa-binding and help ([#164](https://github.com/opentdf/java-sdk/issues/164)) ([ed6e982](https://github.com/opentdf/java-sdk/commit/ed6e9822fe14db1e4b9f68eebf4877a21b72ff8c))
* **codegen:** Generate and publish Java Proto generated artifacts ([#2](https://github.com/opentdf/java-sdk/issues/2)) ([2328fd2](https://github.com/opentdf/java-sdk/commit/2328fd2bec21fb6060beca2b1bac34550eadca4e))
* **core:** Add attributes client ([#118](https://github.com/opentdf/java-sdk/issues/118)) ([98ba6a9](https://github.com/opentdf/java-sdk/commit/98ba6a9e91f8e4b1903f907583356c084abb3313))
* **core:** Add autoconfigure for key splitting ([#120](https://github.com/opentdf/java-sdk/issues/120)) ([7ecbf23](https://github.com/opentdf/java-sdk/commit/7ecbf231d9fa1fd07c1c426489fd160602c2883a))
* **core:** Adding key cache, tests for specificity ([#126](https://github.com/opentdf/java-sdk/issues/126)) ([a149887](https://github.com/opentdf/java-sdk/commit/a14988781f9ad83d8e01b83a3a612aa8f2563bbb))
* **core:** Handle split keys on tdf3 encrypt and decrypt ([#109](https://github.com/opentdf/java-sdk/issues/109)) ([943751f](https://github.com/opentdf/java-sdk/commit/943751ff83b67089472e4422fcfa087e76a8072a))
* **core:** KID in NanoTDF ([#112](https://github.com/opentdf/java-sdk/issues/112)) ([33b5982](https://github.com/opentdf/java-sdk/commit/33b59820b2830b15c9ec467f45cfab0f1eb38017))
* **core:** NanoTDF resource locator protocol bit mask ([#107](https://github.com/opentdf/java-sdk/issues/107)) ([159d2f1](https://github.com/opentdf/java-sdk/commit/159d2f1c5cb4bb3f1257dc5a15a61789211d6848))
* crypto API ([#33](https://github.com/opentdf/java-sdk/issues/33)) ([b8295b7](https://github.com/opentdf/java-sdk/commit/b8295b74ae172fef101447e989a693c56da555a6))
* **lib:** add fallback to namespace kas ([#166](https://github.com/opentdf/java-sdk/issues/166)) ([4368840](https://github.com/opentdf/java-sdk/commit/4368840fa6a08eed39fcce50dab6f7d9e7c7076c))
* NanoTDF Implementation ([#46](https://github.com/opentdf/java-sdk/issues/46)) ([6485326](https://github.com/opentdf/java-sdk/commit/6485326f5d70762b223871f9f8b91306aed75f15))
* **PLAT-3087:** zip reader-writer ([#23](https://github.com/opentdf/java-sdk/issues/23)) ([3eeb626](https://github.com/opentdf/java-sdk/commit/3eeb6265805e18f1cf80970b2627b1ff47825c1b))
* SDK Encrypt (with mocked rewrap) ([#45](https://github.com/opentdf/java-sdk/issues/45)) ([d67daa2](https://github.com/opentdf/java-sdk/commit/d67daa262a6c3c8a40c1bbab9b86b31460bf6474))
* **sdk:** add CLI and integration tests ([#64](https://github.com/opentdf/java-sdk/issues/64)) ([df20e6d](https://github.com/opentdf/java-sdk/commit/df20e6dbc6fc1d37553b79b769315db5a64334a1))
* **sdk:** add mime type. ([#108](https://github.com/opentdf/java-sdk/issues/108)) ([6c4a27b](https://github.com/opentdf/java-sdk/commit/6c4a27b0c608e198b41c395491aff837e883c77b))
* **sdk:** add ssl context ([#58](https://github.com/opentdf/java-sdk/issues/58)) ([80246a9](https://github.com/opentdf/java-sdk/commit/80246a9da9d5507da77318e9f7916058270a9526))
* **sdk:** expose GRPC auth service components ([#92](https://github.com/opentdf/java-sdk/issues/92)) ([2595cc5](https://github.com/opentdf/java-sdk/commit/2595cc57f65b1757d60e4ae04814f85bc340c2e6))
* **sdk:** get e2e rewrap working ([#52](https://github.com/opentdf/java-sdk/issues/52)) ([fe2c04b](https://github.com/opentdf/java-sdk/commit/fe2c04b6a903e587ba8ee790fe87c6b1c529d06a))
* **sdk:** Issue [#60](https://github.com/opentdf/java-sdk/issues/60) - expose SDK ([#61](https://github.com/opentdf/java-sdk/issues/61)) ([ddef62a](https://github.com/opentdf/java-sdk/commit/ddef62ad28bde23fe24b3908ddb86c7a01336560))
* **sdk:** provide access tokens dynamically to KAS ([#51](https://github.com/opentdf/java-sdk/issues/51)) ([04ca715](https://github.com/opentdf/java-sdk/commit/04ca71509019b3903b20bfcea2b8cb479d68aade))
* **sdk:** the authorization service is needed for use by gateway ([#85](https://github.com/opentdf/java-sdk/issues/85)) ([73cac82](https://github.com/opentdf/java-sdk/commit/73cac825e0367d502d542cf0eae30a6ac38f6a00))
* **sdk:** update archive support ([#47](https://github.com/opentdf/java-sdk/issues/47)) ([29a80a9](https://github.com/opentdf/java-sdk/commit/29a80a917fcb60625107ebb278955624d5dc5463))
* **sdk:** Update the assertion support to match go sdk ([#117](https://github.com/opentdf/java-sdk/issues/117)) ([f9badb3](https://github.com/opentdf/java-sdk/commit/f9badb383d769ecbf51c551483633ccb94b2915a))
* support key id in ztdf key access object ([#84](https://github.com/opentdf/java-sdk/issues/84)) ([862460a](https://github.com/opentdf/java-sdk/commit/862460a16875693a421bbe57983bb829a49866bb))
* update README.md ([#142](https://github.com/opentdf/java-sdk/issues/142)) ([198d335](https://github.com/opentdf/java-sdk/commit/198d3351c544cc1e23d62b4d097fb7310a7a3625))


### Bug Fixes

* Align identifier bytes correctly in ResourceLocator ([#148](https://github.com/opentdf/java-sdk/issues/148)) ([2efe226](https://github.com/opentdf/java-sdk/commit/2efe2269e894799d58ab80ccc7b25ea9881bcc91))
* **core:** Add support for certs ([#131](https://github.com/opentdf/java-sdk/issues/131)) ([2f98a3a](https://github.com/opentdf/java-sdk/commit/2f98a3a099a1bde796669bf84eeb3f673cbb5d40))
* **core:** Revert "feat(core): Add attributes client" ([#124](https://github.com/opentdf/java-sdk/issues/124)) ([3d1ef2b](https://github.com/opentdf/java-sdk/commit/3d1ef2b5791de989c4242498787617286fad44bf))
* create TDFs larger than a single segment ([#65](https://github.com/opentdf/java-sdk/issues/65)) ([e1da325](https://github.com/opentdf/java-sdk/commit/e1da32564f7f2ef0a32dbe39657f2cf3459badb4))
* fix pom for release please ([#77](https://github.com/opentdf/java-sdk/issues/77)) ([3a3c357](https://github.com/opentdf/java-sdk/commit/3a3c357be1490a9a780877af0da9ee29f14ebbba))
* Force BC provider use ([#76](https://github.com/opentdf/java-sdk/issues/76)) ([1bc9dd9](https://github.com/opentdf/java-sdk/commit/1bc9dd988dd79fbfeb7ee9422ad66d967deaffa6))
* get rid of duplicate channel logic ([#59](https://github.com/opentdf/java-sdk/issues/59)) ([1edd666](https://github.com/opentdf/java-sdk/commit/1edd666c4141ee7cc71eda1d1f51cc792b24a874))
* GitHub packages snapshot repo ([#178](https://github.com/opentdf/java-sdk/issues/178)) ([713cb2b](https://github.com/opentdf/java-sdk/commit/713cb2ba4ee88297bc211b1089bdd82e540a3cb6))
* GPG key and Maven credentials in release workflow ([#171](https://github.com/opentdf/java-sdk/issues/171)) ([864e9ce](https://github.com/opentdf/java-sdk/commit/864e9ce88e40f3298e99381c8a36cbbc9fcb6300))
* Issue [#115](https://github.com/opentdf/java-sdk/issues/115) - fix for SSL Context for IDP and plaintext platform ([#116](https://github.com/opentdf/java-sdk/issues/116)) ([36a29df](https://github.com/opentdf/java-sdk/commit/36a29dfd66660c04d55cd100bdcd7e8742edd40b))
* make sure we do not deserialize null ([#97](https://github.com/opentdf/java-sdk/issues/97)) ([9579c42](https://github.com/opentdf/java-sdk/commit/9579c427eb26d1020585fdd359551e4e0685a85a))
* **nano:** Store key ids if found ([#134](https://github.com/opentdf/java-sdk/issues/134)) ([94c672b](https://github.com/opentdf/java-sdk/commit/94c672b1e6617a5e6bd0b4339d38a9aae3ae2ae1))
* passpharse ([#169](https://github.com/opentdf/java-sdk/issues/169)) ([8b3cbed](https://github.com/opentdf/java-sdk/commit/8b3cbed1e16cb4404fb0b986e1c7f66258eced05))
* policy-binding new structure ([#95](https://github.com/opentdf/java-sdk/issues/95)) ([b10a61e](https://github.com/opentdf/java-sdk/commit/b10a61ecb30c6cbf2f6cf190a249269b824bf5d3))
* **sdk:** allow SDK to handle protocols in addresses ([#70](https://github.com/opentdf/java-sdk/issues/70)) ([97ae8ee](https://github.com/opentdf/java-sdk/commit/97ae8eebb53d619d8b31ca780c7dea89ec605aaa))
* **sdk:** assertion support in tdf3 ([#82](https://github.com/opentdf/java-sdk/issues/82)) ([c299dbd](https://github.com/opentdf/java-sdk/commit/c299dbdcb0c714a4c69faf24c60e2da58a68e99e))
* **sdk:** give a test framework test scope ([#90](https://github.com/opentdf/java-sdk/issues/90)) ([b99de43](https://github.com/opentdf/java-sdk/commit/b99de43461b96c05b6997999a4187bfad8927b44))
* **sdk:** make sdk auto closeable ([#63](https://github.com/opentdf/java-sdk/issues/63)) ([c1bbbb4](https://github.com/opentdf/java-sdk/commit/c1bbbb43b6d5528ff878ab8b32ba3b6d6c29839d))
* **sdk:** Mixed split fix ([#163](https://github.com/opentdf/java-sdk/issues/163)) ([649dac7](https://github.com/opentdf/java-sdk/commit/649dac7794f58f9fb3d94203b0dd61080ebc8d9a))
* ztdf support both base and handling assertions ([#128](https://github.com/opentdf/java-sdk/issues/128)) ([5f72e94](https://github.com/opentdf/java-sdk/commit/5f72e9448aa03ca43065cb024d6e783573a3ba29))


### Documentation

* **sdk:** Adds brief usage code sample ([#26](https://github.com/opentdf/java-sdk/issues/26)) ([79215c7](https://github.com/opentdf/java-sdk/commit/79215c7b1ff694914df438491a40662803462dc6))


### Miscellaneous Chores

* release 0.6.1 Release-As: 0.6.1 ([#135](https://github.com/opentdf/java-sdk/issues/135)) ([09ec548](https://github.com/opentdf/java-sdk/commit/09ec5480c6ad5c4f958d051c0ef668b68e13637c))
* release 0.7.2 ([#184](https://github.com/opentdf/java-sdk/issues/184)) ([ea6cf12](https://github.com/opentdf/java-sdk/commit/ea6cf128720cd4bf24d94f165a195152808139aa))


### Code Refactoring

* move to single jar ([#160](https://github.com/opentdf/java-sdk/issues/160)) ([ba9b2d5](https://github.com/opentdf/java-sdk/commit/ba9b2d59535a7bd3050f5b7095c217517ac463ca))

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
