# Changelog

Notable changes to truststores. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0-dev`, no tag: consumers pin this crate **by path**, so the commit is the
version.

## [Unreleased]

### Added

- The suite says what the reader saw before it skips. A host with no system
  anchors is a real answer and this skips it — and that skip was also perfect
  camouflage for a broken reader, so the run now records where `powershell` was
  found, whether it ran, and what the store answered. It is how the Windows
  root count (563, against a consumer's limit of 512) was found.
- What a caller may pass, and every state it may be handed, named in the spec.
- Documentation checked on the declarations rather than on names in a README.

## Releasing

No procedure yet.
