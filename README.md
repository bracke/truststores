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

The other two stores read as well:

```ada
Truststores.NSS_Anchors    --  every NSS database, including snap and flatpak
Truststores.Java_Anchors   --  the configured keystore, or the JDK's cacerts
Truststores.NSS_Trusts (Certificate_PEM)
Truststores.Java_Trusts (Certificate_PEM)
```

`keytool` dumps a keystore whole, so Java costs one spawn. NSS has no such
switch -- certutil lists nicknames and exports one certificate at a time -- so
reading it costs a spawn per anchor, and a caller with one certificate in mind
should ask `NSS_Trusts` rather than reading the lot.

All three read. CI runs the suite on each host and it reports what that runner
trusted: 121 anchors on Ubuntu, 159 on macOS, 564 on Windows, each store holding
an anchor it had just handed over. `docs/platform_evidence.md` records the runs.

What CI cannot do is mutate a store, so install and remove are validated by hand
per host -- also in that file.

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

## Choosing a store

A caller that takes a store name from a user -- an option, a configuration file
-- parses it here rather than matching strings of its own:

```ada
if Truststores.Target_From_Name (Value, Target) then ...
if Truststores.Selection_From_Text ("nss,system", Selection) then ...
```

`Target_From_Name` takes one name. `Selection_From_Text` takes a comma-separated
list and fills a `Store_Selection`, which holds up to `Max_Selected_Stores` of
them; `Default_Selection` is what to use when the caller was given nothing.

The accepted names are not a list to copy. `Store_Name_Count` and `Store_Name`
report them, so an error message offering the choices, or a document claiming to
list them, can be written from the library rather than from memory:

```ada
for Index in 1 .. Truststores.Store_Name_Count loop
   Put_Line ("  " & Truststores.Store_Name (Index));
end loop;
```

`system` resolves to whichever system store this host has --
`Detect_Default_Target` is what decides that -- and the store can also be named
directly. `Kind_From_Name` parses the three kinds rather than the targets, and
`Target_For` maps a kind onto the target this host would use for it.

`Name` renders a target or a kind back to the name it was parsed from, and
`State_Image` renders a `Trust_State`. Both exist so that a caller printing a
result and a caller parsing an argument agree about the spelling.

## Asking before acting

Nothing here has to be attempted to be understood.

`Probe` reports what a store would do without touching it: `Tool_Missing` where
the tool it needs is absent, `Unsupported` where this host has no such store,
`Available` where it could be used. It is what a `doctor` command is built from.

`Plan` describes an operation in one line -- "install linux system trust for
`<fingerprint>` using `<certificate>`" -- for a caller that wants to say what it
is about to do, or to show it under a dry run.

Where a store is is answerable too. `NSS_Database_Count` and `NSS_Database_Path`
name every NSS database that would be acted on, which is how a caller reports an
anchor that landed nowhere. `Firefox_Profile_Root` gives the first profile
directory that exists; `Firefox_Profile_Root_Count` and
`Firefox_Profile_Root_Candidate` give every directory that would be searched,
asked per host rather than about this one, so a document describing all of them
can be generated anywhere. `System_Anchor_Count` counts what the system store
holds without concatenating it.

`Fingerprint_Alias` derives the alias an anchor is stored under from its
fingerprint. A caller inspecting a store with the platform's own tool needs the
same spelling this library used.

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

Firefox is packaged several ways on Linux and each confines its profiles to its
own directory: `~/.mozilla/firefox`, `~/snap/firefox/common/.mozilla/firefox`,
`~/.var/app/org.mozilla.firefox/.mozilla/firefox` and
`~/.var/app/org.mozilla.firefox/config/mozilla/firefox`. A flatpak is listed
twice because a flatpak gives the application its own `XDG_CONFIG_HOME` and
Firefox 153 writes profiles into it, while a snap gives the application its own
`HOME` and leaves `XDG_CONFIG_HOME` alone, so Firefox falls back to `~/.mozilla`
inside it -- confinement is not what decides the layout. All of them are
searched, and all of them that exist are used -- a machine can have two, and installing into
one leaves the other untrusted. Ubuntu has shipped Firefox as a snap since
22.04, which is why looking only at the traditional directory meant installing
an anchor into nothing and reporting success.

Every Java keystore on the host, not one. A machine with two JDKs has two
stores, and an anchor in java-21's `cacerts` is not in java-17's -- installing
into whichever `keytool` came first on PATH left the rest untrusting and said
nothing about it. `/usr/lib/jvm/*`, `/usr/java/*`,
`/Library/Java/JavaVirtualMachines/*/Contents/Home` and the Windows Java
directories are searched, deduplicated by resolved path: a distribution fills
that directory with aliases -- `default-java` and `java-1.21.0-openjdk-amd64`
are both `java-21-openjdk-amd64`, and on Debian all of them resolve to
`/etc/ssl/certs/java/cacerts` -- so one anchor is one store, reported once.

A named keystore, passed to `Configure` or given in the environment, is the whole
answer instead: a caller pointing at one is not asking about the machine.

Not yet: reading the NSS and Java stores has only run on Linux -- the system
store is the one CI exercises everywhere.

## Working on this

`CLAUDE.md` carries the rules that govern a change here, and why each one exists:
what a caller has to be told rather than left to infer, why an outcome is asked of
the store rather than taken from the tool, why a library does not read its
caller's environment, and why every store of each kind is used rather than the
first one found. `AGENTS.md` points at it.

## Release gate

```
cd check_truststores && alr build && ./bin/check_truststores
```

Every rule in it is there because something went wrong once: a build tree was
committed and came within a command of being published, the documentation
claimed one host had read a store when CI had already read three, and a library
that starts reading its caller's environment variables has stopped being one.

## Validation

The mutating side cannot be proved by a test suite: it needs a real store on a
real host. Those runs are recorded in `docs/platform_evidence.md` -- Linux,
NSS/Firefox, macOS keychain, Windows machine `Root`, and Java, each with what
it established and what it left uncovered.
