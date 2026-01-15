# Repository Guidelines

## Project Structure & Modules

- Multi-module Maven repo (root `pom.xml`) with three modules:
  - `sdk/`: the OpenTDF Java SDK (`sdk/src/main/java`, `sdk/src/main/kotlin`, tests in `sdk/src/test/java`)
  - `cmdline/`: shaded CLI jar (`cmdline/src/main/java`, resources in `cmdline/src/main/resources`)
  - `examples/`: runnable examples (`examples/src/main/java`)
- Protobuf/gRPC sources are generated during the build into `sdk/target/generated-sources` (do not hand-edit generated code).

## Build, Test, and Dev Commands

- Build everything (runs codegen): `mvn clean install`
- Fast local build (skip tests): `mvn clean install -DskipTests`
- SDK unit tests: `mvn -pl sdk test`
- Verify like CI (coverage profile): `mvn clean verify -P coverage`
- Build CLI jar: `mvn -pl cmdline -am package` (output: `cmdline/target/cmdline.jar`)
- Run an example via exec plugin: `mvn -pl examples exec:java@EncryptExample`

## Coding Style & Naming

- Target runtime: Java 11 (`maven.compiler.release=11`). CI runs on newer JDKs but compiles to 11 bytecode.
- No repo-wide formatter is enforced; match surrounding style (4-space indent, no tabs, consistent import grouping).
- Packages use `io.opentdf.platform...`; keep public SDK APIs stable and additive where possible.

## Testing Guidelines

- Tests use JUnit (Jupiter) plus Mockito/AssertJ; place new tests under `sdk/src/test/java` and name `*Test`.
- Prefer focused unit tests over integration tests; keep network calls mocked (e.g., `MockWebServer`).

## Commit & Pull Request Guidelines

- Use Conventional Commits (enforced on PR titles): `feat(sdk): ...`, `fix(cmdline): ...`, `chore(docs): ...` (use `!` for breaking changes).
- DCO sign-off is required: `git commit -s`.
- PRs should include: summary, rationale, test plan/commands run, and any public API notes.
- Build/dependency files (e.g., `pom.xml`, `sdk/pom.xml`) are code-owned and may require security/architecture review.

## Security & Configuration Tips

- Builds require the `buf` CLI (see `sdk/buf.yaml` / `sdk/buf.gen.yaml`). Authenticate to avoid rate limits; CI uses `BUF_INPUT_HTTPS_USERNAME`/`BUF_INPUT_HTTPS_PASSWORD`. Never commit tokens.
