# truststores

Read and mutate the certificate authorities a host trusts.

Two things a program needs and neither is portable: what this machine already
trusts, and how to add or remove an anchor without lying about whether it
worked.

## Reading

```ada
with Truststores;

if Truststores.System_Trusts (Certificate_PEM) then
   --  the host already trusts it
end if;

--  Or the whole set, to hand to a verifier:
Anchors : constant String := To_String (Truststores.System_Anchors);
```

Where the bytes come from is the part that differs. Linux assembles a bundle
whose path no two distributions agree on -- `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`,
`/etc/ca-certificates/extracted/tls-ca-bundle.pem`, `/etc/ssl/cert.pem` -- and
they are tried in that order. macOS keeps them in two keychains and `security`
is what reads them. Windows has no `certutil` switch that exports the store, so
PowerShell hands back the bytes.

`System_Trusts` compares what the armour holds, one anchor at a time. Comparing
the text would answer about the first certificate in the bundle and nothing
else.

## Mutating

```ada
Truststores.Apply
  (Selection, Truststores.Install, Certificate_Path, Fingerprint,
   State, Message);
```

Every store says what became of it: `installed`, `removed`,
`permission-required`, `tool-missing`, `partial`, `error`. The distinction
between a store that refuses an unprivileged caller and a store that is broken
is the whole of what the caller can act on, and each adapter states its own --
nothing infers it from the wording of a message.

Removal is fingerprint-authoritative and verified by reading the store back.
`certutil` on Windows exits zero having deleted nothing when it is handed a
SHA-256, so the exit status is not what the answer rests on.

## Configuration

A library does not read its caller's environment. An application with
documented variables of its own names them once:

```ada
Truststores.Configure
  (Linux_Directory_Variable => "DEVCERT_LINUX_TRUST_DIR",
   NSS_Database_Variable    => "DEVCERT_NSS_DB",
   Java_Keystore_Variable   => "DEVCERT_JAVA_KEYSTORE");
```

or passes paths directly, which is what a test with a disposable store does.
Absent both, `TRUSTSTORES_LINUX_DIR`, `TRUSTSTORES_NSS_DB` and
`TRUSTSTORES_JAVA_KEYSTORE` are consulted.

## What is discovered

* the Linux system backend: `update-ca-certificates`, `update-ca-trust`,
  `trust anchor`, or a configured directory
* every NSS database: the shared one Chromium reads, and one per Firefox
  profile -- a certificate installed only in the shared database is trusted by
  Chromium and by nothing else
* the JDK's own `cacerts`, found through `JAVA_HOME` or by resolving `keytool`
  through the symlink a distribution puts it behind

Not yet: Firefox under Snap or Flatpak, which keep their profiles outside the
usual root, and reading NSS or Java stores rather than the system one.

## Validation

The mutating side cannot be proved by a test suite: it needs a real store on a
real host. Those runs are recorded in `docs/platform_evidence.md` -- Linux,
NSS/Firefox, macOS keychain, Windows machine `Root`, and Java, each with what
it established and what it left uncovered.
