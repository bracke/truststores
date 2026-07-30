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
  several ways on Linux and each confines its profiles to its own directory, and
  a machine with two JDKs has two keystores; installing into one left the other
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

Found by running the platform validations that had never been run, and fixed
before the first release rather than after it:

* `trust anchor`, the third Linux backend, reported failure for work it had
  done. p11-kit stores the anchor and then runs a compat extractor that Debian
  and Ubuntu package nowhere, so `trust` exits 2 having installed the
  certificate. The store decides now, not the exit status -- and removal asks
  before it acts, so removing what was never installed says so instead of
  claiming a removal.
* A host with p11-kit and no `ca-certificates` read as trusting nothing.
  Ubuntu ships `/etc/ssl/certs/ca-certificates.crt` as a zero-length file, and
  the bundle lookup tested whether the path existed rather than whether it held
  anything. Where there are no bytes, p11-kit is asked.
* The Flathub Firefox was invisible. Its profiles are under
  `config/mozilla/firefox`, because a flatpak gives the application its own
  `XDG_CONFIG_HOME`; a snap sets `HOME` and leaves that alone, so Firefox falls
  back to `~/.mozilla` inside it. Confinement is not what decides the layout,
  and both are searched.
* On Windows the NSS store used the wrong program. `certutil.exe` in `System32`
  is Microsoft's, a different tool sharing NSS's name, and it is the one `PATH`
  finds first -- so NSS was reported available on every Windows and then handed
  arguments it cannot read. Which program answered is asked now, and the rest of
  `PATH` is walked when the first is not NSS's, because a host with NSS
  installed and its directory appended has both.

New in the interface, for callers that have to describe this library rather than
use it:

* `Store_Name_Count` and `Store_Name` report the store names `Target_From_Name`
  accepts. They were an if-chain, so every caller listing them wrote them out
  again, and `mac` and `win` went undocumented.
* `Firefox_Profile_Root_Count` and `Firefox_Profile_Root_Candidate` report every
  directory searched for Firefox profiles, asked per host rather than about this
  one, so a document covering all of them can be generated anywhere.
