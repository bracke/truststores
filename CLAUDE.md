# CLAUDE.md

Guidance for AI agents (Claude Code and others) working in this repository.

## What this is

truststores is an Ada 2022 library that owns two questions about a host's
certificate authorities: **what does this machine already trust**, and **what may
a program do about it**. It was carved out of devcert, where it had grown a
complete set of answers that had nothing to do with issuing certificates.

It depends on `hostkit` (what differs because the host differs) and `cryptolib`
(what the armour holds). It does not depend on devcert, and must not: devcert is
one consumer, and a program that verifies a chain itself is another.

## Build, test, verify

Built with [Alire](https://alire.ada.dev/) (`alr`), pinned to
`gnat_native = "=15.2.1"`.

```sh
alr build                                        # the library
cd tests && alr build && ./bin/truststores_tests # the suite
cd check_truststores && alr build && ./bin/check_truststores   # the release gate
```

The gate is not optional before a release: every rule in it is there because
something went wrong here once, and each one names what.

## The rules that govern every change

1. **Does the caller have to be told this, or can it be inferred?** A store that
   refuses an unprivileged process is not a broken store, and only one of those
   is something a caller can act on. Every adapter states its own outcome. It was
   once inferred by searching the message the adapter had just written for the
   words "requires permission" — so translating a sentence would have changed an
   exit code, and nothing would have failed.

2. **Ask the store, not the tool.** `certutil` on Windows exits zero having
   deleted nothing when it is handed a SHA-256 instead of the SHA-1 it indexes by.
   `keytool` has reported a successful import the keystore did not keep. Both were
   found by reading the store back afterwards, and neither would have been found
   any other way.

3. **A library does not read its caller's environment.** `TRUSTSTORES_*` are this
   crate's own. An application's variables — `DEVCERT_NSS_DB` and its kind —
   arrive through `Configure`, either as paths or as the *names* of the variables
   the application documents. The release gate refuses a quoted `DEVCERT_` in the
   library sources.

4. **Every store of each kind, not the first one found.** Firefox is packaged
   three ways on Linux and each confines its profiles to its own directory; a
   machine can have two JDKs. Installing into one and reporting success left the
   other untrusting — which is what happened on every Ubuntu desktop since 22.04,
   where Firefox is a snap and `~/.mozilla` is empty.

## What a test can and cannot prove here

Reading needs no privileges and mutates nothing, so CI reads the system store on
all three hosts and reports what it found — 121 anchors on Ubuntu, 159 on macOS,
564 on Windows at the time of writing.

Mutating cannot be done by a runner: it needs a disposable host and, on two of
the three, elevated privileges. Those runs are performed by hand and recorded in
`docs/platform_evidence.md`, which also carries a standing list of what nobody
has run. Adding a feature without adding to that list is how six features in
devcert came to have passing tests and never work.

A test that would mutate a real store must stop rather than adapt. The denial
test uses a keystore nobody can create, and refuses to run when elevated:
otherwise it would install a development CA into the trust store of whoever ran
the suite.

## Conventions

- Comments say *why*, with the history that made the code look like that. A
  comment restating the code is noise.
- The specification (`src/truststores.ads`) is where a caller's contract lives,
  including what has never been run.
- Three-host CI is mandatory. Where a host keeps its anchors is the entire
  subject of this crate, so a green Linux run says nothing about the other two.
