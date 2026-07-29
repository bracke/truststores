# Changelog

## 0.1.0-dev

First release, extracted from devcert.

* Read what a host trusts: `System_Anchors`, `System_Trusts`, and the same for
  the NSS and Java stores. Where the bytes come from differs by host and none of
  it is guessable -- a bundle file whose path no two distributions agree on, two
  keychains read through `security`, or the machine `Root` store through
  PowerShell because `certutil` has no switch that exports it.
* Install and remove a CA anchor in the Linux system store (three backends), the
  NSS databases, a Java keystore, the macOS keychain, and the Windows machine
  `Root` store.
* Every store of each kind is used, not the first one found. Firefox is packaged
  three ways on Linux and each confines its profiles to its own directory, and a
  machine with two JDKs has two keystores; installing into one left the other
  untrusting. Aliases are deduplicated by resolved path.
* Each adapter states its own outcome: `installed`, `removed`,
  `permission-required`, `tool-missing`, `partial`, `error`. A store that refuses
  an unprivileged caller is not a broken store, and telling them apart is the
  whole of what a caller can act on.
* Removal is fingerprint-authoritative and verified by reading the store back.
  `certutil` exits zero having deleted nothing when handed a SHA-256 instead of
  the SHA-1 it indexes by, and `keytool` has reported an import the keystore did
  not keep.
* Configuration is passed in rather than read from the caller's environment: a
  path, or the name of a variable the application documents.
* Reading is validated by CI on all three hosts; mutating is validated by hand,
  per host, and recorded in `docs/platform_evidence.md` -- which also names what
  nobody has run.
