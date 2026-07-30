# Platform Validation Evidence

Records of host trust-store validation runs. They mutate a real trust store and
need administrator rights on two hosts out of three, so they are performed by
hand and recorded here; no test suite touches a host store.

These runs were made while this code lived in devcert, which is where the
transcripts came from. They are evidence about these adapters, so they moved
with them.

A platform with no entry below has not been validated. That is the honest
reading of an absent row, and it is the reason this file lists what has *not*
been run as plainly as what has.

## Reading, On Every Host

Reading a trust store needs no privileges and mutates nothing, so unlike the
rest of this file it is validated by CI rather than by hand. Run 2026-07-29,
truststores `67922d0`:

| Host | Anchors read | Where from |
| --- | --- | --- |
| ubuntu-latest | 121 | `/etc/ssl/certs/ca-certificates.crt` |
| macos-15-intel | 159 | both keychains, through `security` |
| windows-latest | 564 | machine `Root`, through PowerShell |

Each run also asked the store whether it held an anchor it had just handed over,
and each said yes -- which exercises the comparison against a real anchor rather
than a constructed one, and the armour-at-a-time reading that a whole-text
comparison would get wrong.

## Not Validated

Every store below has been exercised against a real one. What has not, as of
2026-07-28:

* **An anchor installed into a real confined Firefox profile.** The paths
  themselves are no longer in doubt: the suite walks each host's profile root
  with a staged profile, and the two confined layouts match what Mozilla and the
  Flathub packaging document --
  `~/snap/firefox/common/.mozilla/firefox` and
  `~/.var/app/org.mozilla.firefox/.mozilla/firefox`. That matters because a
  staged test proves the code finds what it was told to look for, and nothing
  else: it would pass just as well against a path that no Firefox uses. What
  remains unrun is installing into a profile a browser made, and watching that
  browser accept the certificate.

* **A real Firefox on macOS or Windows.** The profile root each host keeps them
  under is walked by the suite on that host -- a directory holding a `cert9.db`
  is staged under a relocated home, so the paths that differ (a snap's
  confinement, the space in `Application Support`, a backslash under `APPDATA`)
  are exercised where they belong. What has not happened is an anchor installed
  into a browser's own profile there and Firefox accepting it.
* **`update-ca-trust` and `trust anchor` under SELinux enforcing.** The Fedora
  container ran permissive.

## Linux System Store

| | |
| --- | --- |
| Date | 2026-07-27 |
| Operating system | TUXEDO OS 24.04.4 LTS, a Kubuntu derivative (`noble`) |
| Kernel | Linux 6.17.0-122035-tuxedo |
| Backend | `update-ca-certificates` (`trust` also present, but lower in precedence) |
| devcert commit | `5bfdb5f` |
| cryptolib commit | `dc9331b` |
| Command | `DEVCERT_RUN_PLATFORM_TRUST_TESTS=1 devcert_tools platform-check linux-system` |
| Result | Passed: the root certificate was installed into the host trust store and removed again |

Run by the maintainer, who holds the administrator rights the host store
requires. Independently confirmed afterwards by inspection of the host store:
no `devcert-*.crt` remains under `/usr/local/share/ca-certificates/`, and no
devcert anchor under `/etc/ssl/certs/`, so the removal completed rather than
merely reporting success.

"Linux" is not one target. The host is a Kubuntu derivative, so this validates
the Debian and Ubuntu family and the `update-ca-certificates` backend, which
devcert prefers when it is present. The other two Linux backends are untouched
by it: `update-ca-trust`, as used by Fedora and RHEL, and `trust`, as used by
Arch. Each needs its own run on a host that has it.

Not captured for this run: the command transcript, the before/after listing as
seen at the time, and the SHA-256 fingerprint of the root CA. `platform-check`
creates its CA root under the host's temporary directory and deletes it on the
way out, so the fingerprint is gone with it. A future run should keep the
transcript, which carries the fingerprint in the install and removal lines.

## Linux System Store: update-ca-trust

| | |
| --- | --- |
| Date | 2026-07-28 |
| Operating systems | `fedora:latest` and `archlinux:latest`, in rootless podman |
| Binary | The `devcert-linux-x86_64` artifact, built on TUXEDO OS |
| devcert commit | `b55545a` plus the two fixes this run produced |
| Result | Passed on both, after two bugs this run found |

Fedora writes the anchor to `/etc/pki/ca-trust/source/anchors/`, Arch to
`/etc/ca-certificates/trust-source/anchors/`; both then run `update-ca-trust`.
On Arch, `trust list` shows the anchor while it is installed and does not once
it is removed. A second removal reports there is nothing to remove and exits 0.

Two bugs, both found here rather than by reasoning:

* The `update-ca-trust` backend hardcoded Fedora's anchor directory, so on Arch
  every install wrote into a directory that does not exist -- and reported it
  as wanting privileges, exit 7, which is a plausible enough answer that it
  could have stood for a long time.
* Removal said `removed ... anchor` and exited 0 when nothing of ours was
  there, including immediately after an install that had failed.

### `trust anchor`, 2026-07-30

The third Linux backend, exercised at last. It is selected only where neither
`update-ca-certificates` nor `update-ca-trust` exists, and Arch -- the
distribution it was meant for -- ships `update-ca-trust` too, so the path had
never run. A container reaches it: `ubuntu:24.04` with `p11-kit` installed and
`ca-certificates` not, which is a configuration rather than a contrivance -- it
is the one the backend order describes.

Both operations were wrong, in the direction that matters.

```
install    system=error: linux trust refresh failed        exit 6
  but:     trust list --filter=ca-anchors -> devcert-local-development-ca
```

p11-kit stores the anchor and then runs
`/usr/libexec/p11-kit/trust-extract-compat` to rewrite the bundle files. No
Ubuntu package ships that program -- not `p11-kit`, not `ca-certificates` -- so
`trust` exits 2 having done the work asked of it. This library believed the exit
code and called a trusted certificate a failure. `trust anchor --remove` exits 2
the same way, having removed the anchor.

Underneath that, `System_Anchors` could not have checked even if it had been
asked: Ubuntu ships `/etc/ssl/certs/ca-certificates.crt` as a zero-length file,
and the bundle lookup tested whether the path existed rather than whether it
held anything, so the host read as trusting nothing at all.

Both now ask p11-kit -- `trust extract --format=pem-bundle --filter=ca-anchors`
works there whatever `trust anchor` exits -- and the store decides. Verified by
fingerprint from outside this library, against `trust extract`:

```
install     system=installed: installed linux trust anchor for b2:d5:66:0c...
  store holds it (independent check): yes
uninstall   system=removed:   removed linux trust anchor for b2:d5:66:0c...
  store holds it (independent check): no
uninstall   system=removed:   no linux trust anchor for 3e:be:5f:48...
```

That last line is the third case: removing what was never installed says so
rather than claiming a removal, which the other backends already did. The
`update-ca-certificates` backend was re-run the same way afterwards -- 121
anchors in the bundle, ours among them by fingerprint, absent after `uninstall`
-- to confirm this did not disturb the store that already worked.


## macOS System Store

| | |
| --- | --- |
| Date | 2026-07-28 |
| Operating system | macOS 14.8.7 (23J520), x86_64 |
| devcert commit | `e1b31a7` |
| cryptolib commit | `1025377` |
| Result | Passed: installed, validated, removed, and a denial reported as a denial |

The keychain adapter could not be reached before `5bfdb5f`: the host was
detected by comparing `OSTYPE` to `darwin`, and `OSTYPE` is a shell variable a
spawned process does not inherit, so every macOS was treated as a Linux. What
follows is the first time it has run on a Mac.

Unprivileged, an install is refused, and says so:

```text
system=permission-required: macOS trust store update requires permission
  for /Library/Keychains/System.keychain
exit 7
```

That is the fix this run tested. On the first pass, at `f0f587f`, the same
command answered `system=error: failed to update macOS trust store` and exit 6:
the adapter was right and the report was wrong, and the one thing it did not say
was that the system keychain belongs to root. Run by hand, `security` gave the
reason -- `SecCertificateAddToKeychain: Write permissions error.` -- and the
same command under `sudo` returned 0.

With privileges, the whole check passes:

```text
sudo DEVCERT_RUN_PLATFORM_TRUST_TESTS=1 devcert_tools platform-check macos-system
==> macos-system trust install    system=installed: updated macOS trust store
==> macos-system trust doctor     doctor: ca complete
==> macos-system trust uninstall  system=removed: updated macOS trust store
platform-check macos-system passed
```

A separately recorded root confirms the certificate that reached the keychain is
the one devcert issued: devcert reported
`1F:86:10:FB:53:78:BB:2B:84:2D:F6:31:AF:5C:67:21:7F:A6:B4:F9:9F:E1:10:CF:10:60:0B:0F:37:0D:5C:23`,
and `security find-certificate -Z` reported
`1F8610FB5378BB2B842DF631AF5C67217FA6B4F99FE110CF10600B0F370D5C23` for the same
CA. After `uninstall` the keychain holds no certificate under that name.

Two questions this settles beyond the run itself. The keychain accepts the P-384
CA, so the algorithm NSS refused is no trouble here. And
`security delete-certificate -Z` takes the SHA-256 hash devcert computes, not
the SHA-1 its manual page documents, so fingerprint-authoritative removal works
as written.

## Windows System Store

| | |
| --- | --- |
| Date | 2026-07-28 |
| Operating system | Windows Server 2025 (10.0.26100.32995), GitHub-hosted runner |
| devcert commit | `3b341f6` |
| cryptolib commit | `5c57a7e` |
| Result | Passed, elevated: installed, validated, removed, and the store read back |

Run by the `platform-windows` workflow, which is manual-trigger only. A hosted
runner is a disposable virtual machine, which is what
[platform_validation.md](platform_validation.md) asks for.

```text
==> windows-system trust install    system=installed: updated Windows trust store
==> windows-system trust doctor     doctor: ca complete
==> windows-system trust uninstall  system=removed: updated Windows trust store
platform-check windows-system passed
```

A separately recorded root confirms the certificate that reached the machine
`Root` store is devcert's: `certutil -store Root` reported
`Cert Hash(sha1): a8b8ac3541f30ce149e04242bb9837bdd1b55e7a` for the CA it had
just issued, and after `uninstall` the store holds nothing of ours.

It took three runs to get there, and each failure was devcert's rather than the
runner's.

The first found every operation failing, elevated or not. Not `certutil`: the
captured output of every trust-store command went to `/tmp`, spelled out, which
is a directory Windows has not got. The spawn could not create the file it was
told to capture into, and a failed spawn reads exactly like a command that ran
and refused. `nss` and `java` on Windows had the same fate, unnoticed because
nothing had run them there either.

The second found `uninstall` reporting removals that had not happened.
`certutil` indexes by SHA-1 and matches `-delstore` against that; handed
devcert's SHA-256 identity it exits zero having deleted nothing. Two devcert
roots were left trusted while the tool reported both gone -- the same defect
fixed for the Linux backend before anything had run there either. Removal now
asks by the hash the store keeps and reads the store back afterwards, because
the exit status has been wrong about this once already.

The unprivileged case is closed too, on the same runner, 2026-07-30, devcert
`8022f5e`:

```text
system=permission-required: Windows trust store update requires permission
  for the machine Root certificate store
exit=7
```

A hosted runner is elevated, so an ordinary user had to be arranged rather than
found. `runas /trustlevel` cannot do it there -- the Secondary Logon service is
stopped and starting it does not help -- but the Task Scheduler is always
running and starts a process as another account without it. A local account with
no group memberships, granted exactly one privilege (`SeBatchLogonRight`, or a
task will not start for it), running a command from a file so no quoting is lost
on the way.

That account can do nothing else: it is not an administrator and holds no right
over a certificate store, which is what makes the refusal the real one rather
than a simulated one.

Four attempts, each stopped by something worth writing down: `net user` asks
whether to continue when a password exceeds fourteen characters and a step with
no console cannot answer; `schtasks /tr` loses the quotes around a nested command
line and reads `cmd`'s `/c` as its own; a task will not start without the batch
logon right; and group membership does not carry it. What is unexercised is therefore the
reporting -- `permission-required` and exit 7 -- and not the store operations
themselves. On macOS the equivalent path was exercised on a real machine and the
two adapters answer the same way.

## NSS Databases

| | |
| --- | --- |
| Date | 2026-07-28 |
| Operating system | TUXEDO OS 24.04.4 LTS, a Kubuntu derivative (`noble`) |
| Kernel | Linux 6.17.0-122035-tuxedo |
| Tool | `certutil`, `libnss3-tools` 2:3.98-1ubuntu0.2 |
| devcert commit | `c8b4ca3` |
| cryptolib commit | `b98e524` |
| Databases | A disposable `HOME`: a shared `.pki/nssdb` and one Firefox |
| | profile, both created with `certutil -N --empty-password` |
| Result | Passed: installed into both, removed from both, and a |
| | second removal was a no-op rather than a failure |

The transcript, in order: `install --trust-store nss` reported
`installed NSS trust anchor devcert-2036333c…` for each database and exited 0;
`certutil -L` listed the anchor in both; `uninstall --trust-store nss` reported
`removed …` for each and exited 0; `certutil -L` then listed it in neither; a
second `uninstall` reported `no NSS trust anchor … in …` for each and still
exited 0.

This run is the reason the CA is P-384. The same sequence against an Ed25519
CA failed at the first step: `certutil` answers `SEC_ERROR_ADDING_CERT` and
refuses to import such a certificate at all, so the NSS store had never been
able to work -- for Firefox or for Chromium -- whatever the adapter did. An
RSA certificate imported into the same database, which is how the key, rather
than the database or the tool, was identified as the cause.

What it does not cover: the databases were disposable ones created for the
run, not the profiles a person browses with, and no browser was launched
against the result. It covers the adapter and the certificate NSS will accept,
not the experience of visiting a site.

## Java Keystores

| | |
| --- | --- |
| Date | 2026-07-28 |
| Environment | eclipse-temurin:21-jdk container (Ubuntu 26.04, OpenJDK 21.0.11) |
| devcert commit | `b84462a` |
| cryptolib commit | `c393a83` |
| Result | Passed: imported, matched by fingerprint, removed |

A container rather than a machine: the host has no JDK and wants none, and the
adapter only needs a real `keytool` and a real keystore, both of which an image
has. devcert's own binary runs inside it, against
`DEVCERT_JAVA_KEYSTORE=/work/javaval/cacerts`.

```text
install    java=installed: installed Java trust anchor devcert-d80cf9c6...
keytool    Alias name: devcert-d80cf9c6...
           Owner: CN=devcert-local-development-ca
           SHA256: D8:0C:F9:C6:...:D2:03:AE
uninstall  java=removed: removed Java trust anchor devcert-d80cf9c6...
           absent after uninstall
```

The SHA-256 `keytool` reports is the fingerprint devcert issued.

The first run failed, and not in the keystore. `install` reported failure while
the anchor sat in the keystore with the right fingerprint, and `uninstall` then
refused to remove it -- "Java trust anchor fingerprint mismatch". devcert asks
`keytool -list -rfc` for the anchor and compares it with its own CA, and
`keytool` names the alias, the creation date and the entry type before the
armour. cryptolib's decoder began one line into the text, so every letter of
that preamble was swept into the base64 and the comparison was against nothing.
Fixed in cryptolib `c393a83`; `openssl x509 -text` output had the same shape and
the same fate.

The JDK's own `cacerts` -- the default, which `DEVCERT_JAVA_KEYSTORE` goes
around -- was then run the same way, with the variable unset. A container runs
as root, so the installation's keystore is writable:

```text
anchors before:          144
install                  java=installed: devcert-2934454b...
anchors while installed: 145
keytool SHA256:          29:34:45:4B:...:AD:38
devcert issued:          29:34:45:4B:...:AD:38
uninstall                java=removed
anchors after:           144
```

The count returning to 144 is the part worth keeping: devcert added one anchor
to a store of 144 and took that one back out.
