with Ada.Strings.Unbounded;

package Truststores is
   subtype Unbounded_String is Ada.Strings.Unbounded.Unbounded_String;

   type Trust_Target is (Linux, NSS, Java, MacOS, Windows);
   type Action is (Install, Remove);
   type Trust_Store_Kind is (System_Store, NSS_Store, Java_Store);
   type Trust_State is
     (Unsupported,
      Available,
      Installed,
      Not_Installed,
      Tool_Missing,
      Permission_Required,
      Partial,
      Error);

   --  Where the stores are, when they are not where this host usually keeps
   --  them. A library does not read its caller's environment: an application
   --  with its own variables -- or a test with a disposable store -- passes
   --  them in here, and they take precedence over anything the environment
   --  says. Empty means "ask the host", which is the ordinary case.
   --
   --  @param Linux_Anchor_Directory A directory to drop anchors into instead of
   --                                the host's, with no refresh command run.
   --  @param NSS_Database A single NSS database instead of discovering them.
   --  @param Java_Keystore A keystore file instead of the JDK's own cacerts.
   --  @param Linux_Directory_Variable Name of the variable to read the Linux
   --         anchor directory from, when the caller passes none.
   --  @param NSS_Database_Variable Name of the variable for the NSS database.
   --  @param Java_Keystore_Variable Name of the variable for the keystore.
   --  The variable names carry the same idea one step further: an application
   --  with its own documented environment -- DEVCERT_NSS_DB, say -- names them
   --  here once, and they are read whenever a store is looked at rather than
   --  captured now. A test that sets one later still gets what it set.
   procedure Configure
     (Linux_Anchor_Directory : String := "";
      NSS_Database           : String := "";
      Java_Keystore          : String := "";
      Linux_Directory_Variable : String := "";
      NSS_Database_Variable    : String := "";
      Java_Keystore_Variable   : String := "");

   Max_Selected_Stores : constant := 3;
   subtype Selection_Index is Positive range 1 .. Max_Selected_Stores;
   type Store_Array is array (Selection_Index) of Trust_Store_Kind;

   type Store_Selection is record
      Count : Natural range 0 .. Max_Selected_Stores := 0;
      Items : Store_Array := [others => System_Store];
   end record;

   --  Render a target, a kind or a state back to the name it is parsed from
   --  and reported under, so a caller printing a result and a caller reading an
   --  argument agree about the spelling.

   --  @param Target The target to name.
   --  @return Its name, as Target_From_Name accepts it.
   function Name (Target : Trust_Target) return String;

   --  @param Kind The kind to name.
   --  @return Its name, as Kind_From_Name accepts it.
   function Name (Kind : Trust_Store_Kind) return String;

   --  @param State The state to render.
   --  @return Its name. "removed" is not among them: that is how Installed is
   --          shown after a removal, and the caller decides it.
   function State_Image (State : Trust_State) return String;

   --  @param Value The name a user gave.
   --  @param Target The target it names, when it names one.
   --  @return True when Value is a name this library accepts.
   function Target_From_Name (Value : String; Target : out Trust_Target) return Boolean;

   --  Every name Target_From_Name accepts, so a caller can say what it will
   --  take rather than describe it from memory: an error message listing the
   --  choices, or a document that has to stay true. "mac" and "win" were
   --  accepted and undocumented for as long as both lists were written by
   --  hand.
   --
   --  @return How many names there are.
   function Store_Name_Count return Natural;

   --  @param Index in 1 .. Store_Name_Count; "" outside that.
   --  @return The name at that position.
   function Store_Name (Index : Positive) return String;

   --  @param Value The name a user gave.
   --  @param Kind The store kind it names, when it names one.
   --  @return True when Value is a kind this library accepts.
   function Kind_From_Name
     (Value : String;
      Kind  : out Trust_Store_Kind) return Boolean;

   --  @return The system store this host actually has, which is what the name
   --          "system" resolves to.
   function Detect_Default_Target return Trust_Target;

   --  @return The stores to act on when the caller named none.
   function Default_Selection return Store_Selection;

   --  @param Value A comma-separated list of store names.
   --  @param Selection The stores it names, when they are all accepted.
   --  @return True when every name in Value was one this library accepts.
   function Selection_From_Text
     (Value     : String;
      Selection : out Store_Selection) return Boolean;

   --  @param Kind The store kind.
   --  @return The target this host would use for it.
   function Target_For (Kind : Trust_Store_Kind) return Trust_Target;

   --  What that store would say, without touching it: Tool_Missing where the
   --  program it needs is absent, Unsupported where this host has no such
   --  store, Available where it could be used.
   --
   --  @param Kind The store kind to ask about.
   --  @return Its state, unchanged by the asking.
   function Probe (Kind : Trust_Store_Kind) return Trust_State;
   --  Where this host keeps Firefox profiles. Each holding a cert9.db is an
   --  NSS database of its own; the path differs per host, which is why a test
   --  has to ask rather than assume.
   --
   --  @return The first such directory that exists, or "" where none does.
   function Firefox_Profile_Root return String;

   --  Every directory a Firefox profile could be under, whether or not one is
   --  there. Firefox_Profile_Root answers with the first that exists, which is
   --  what a caller acting on a profile wants and no use to a caller that has
   --  to say where this library looks: documentation listing those paths, or a
   --  doctor reporting where an anchor did not land.
   --
   --  Asked per host rather than about this one, so a document describing all
   --  of them can be generated anywhere. The paths use the separator of the
   --  host named, not of the host asking, and the home directory of a host
   --  other than this one is written as a placeholder rather than guessed.
   type Host_Kind is (Linux, MacOS, Windows, Other);

   --  @param Host The host to ask about, which need not be this one.
   --  @return How many directories would be searched there.
   function Firefox_Profile_Root_Count (Host : Host_Kind) return Natural;

   --  @param Host The host to ask about.
   --  @param Index in 1 .. Firefox_Profile_Root_Count (Host); "" outside that.
   --  @return The directory, with the home part left as a mark for the caller
   --          to render however its readers expect.
   function Firefox_Profile_Root_Candidate
     (Host : Host_Kind; Index : Positive) return String;

   --  The NSS databases devcert would act on: the shared one Chromium reads
   --  under ~/.pki/nssdb, plus one per Firefox profile, which reads no other.
   --  TRUSTSTORES_NSS_DB names one instead of all of them.
   --
   --  @return How many databases would be acted on.
   function NSS_Database_Count return Natural;

   --  @param Index in 1 .. NSS_Database_Count; "" outside that.
   --  @return That database's path, which is what a caller reports when an
   --          anchor landed nowhere.
   function NSS_Database_Path (Index : Positive) return String;

   --  The name an anchor is stored under, derived from its fingerprint. A
   --  caller inspecting a store with the platform's own tool needs the same
   --  spelling this library used.
   --
   --  @param Fingerprint The certificate's fingerprint.
   --  @return The alias, safe to use as a store nickname or file name.
   function Fingerprint_Alias (Fingerprint : String) return String;

   --  What Apply would do, in one line, for a caller that wants to say so
   --  first -- a dry run, or a prompt before touching a machine's trust.
   --
   --  @param Target Which store.
   --  @param Operation Install or Remove.
   --  @param Certificate Path to the certificate the operation is about.
   --  @param Fingerprint Its fingerprint, which names the anchor.
   --  @return One line describing the operation; it performs nothing.
   function Plan
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String) return String;

   --  Apply the operation to one store, and say what became of it. The state
   --  is the store's own answer, not an inference from the message: a caller
   --  deciding between "denied" and "broken" must not depend on the wording.
   --
   --  @param Target Which store to act on.
   --  @param Operation Install or Remove.
   --  @param Certificate Path to the certificate to install or remove.
   --  @param Fingerprint Its fingerprint; removal is authoritative on it, so a
   --         store holding a different certificate under the same name is
   --         refused rather than overwritten.
   --  @param State What became of that store.
   --  @param Message What it said, for a person; not for branching on.
   procedure Apply
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String);

   --  The same across several stores at once, reporting one state for the lot.
   --
   --  @param Selection Which stores to act on.
   --  @param Operation Install or Remove.
   --  @param Certificate Path to the certificate to install or remove.
   --  @param Fingerprint Its fingerprint.
   --  @param State Partial when some stores took it and others did not, which
   --         is a different answer from every store failing.
   --  @param Message Each store's own message, joined.
   procedure Apply
     (Selection   : Store_Selection;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String);
   ---------------------------------------------------------------------------
   --  Reading
   --
   --  What this host trusts, for a program that has to verify a certificate
   --  chain itself rather than hand the job to a library that already knows.
   ---------------------------------------------------------------------------

   --  Every anchor the host's system store holds, concatenated as PEM.
   --
   --  Where the bytes come from differs by host and none of it is guessable: a
   --  bundle file assembled by update-ca-certificates or update-ca-trust, the
   --  system roots keychain, or the machine Root certificate store. What comes
   --  back is one text a verifier can be pointed at.
   --
   --  Read on all three hosts by the test suite, which is what CI runs: 121
   --  anchors from a Debian bundle, 159 from a macOS keychain, 564 from a
   --  Windows machine Root store, each of them holding an anchor it had just
   --  handed over. So an empty answer means the store is empty or unreadable,
   --  not that the path was never tried.
   --
   --  @return The anchors in PEM, or "" where this host would not say.
   function System_Anchors return Unbounded_String;

   --  How many certificates that text holds. Zero means the store was empty or
   --  could not be read; the two are told apart by whether System_Anchors is
   --  itself empty.
   --
   --  @return The number of anchors, without concatenating them.
   function System_Anchor_Count return Natural;

   --  Every anchor the NSS databases hold, concatenated as PEM.
   --
   --  All of them: the shared database Chromium reads, and one per Firefox
   --  profile -- including a snap's or a flatpak's, which are separate stores
   --  that happen to belong to the same browser.
   --
   --  certutil lists nicknames and exports one certificate at a time, so this
   --  costs a spawn per anchor. A caller that wants one answer about one
   --  certificate should ask NSS_Trusts instead.
   --
   --  @return The anchors in PEM, or "" where none could be read.
   function NSS_Anchors return Unbounded_String;

   --  Every anchor the host's Java keystores hold, concatenated as PEM.
   --
   --  All of them, not one: a machine with two JDKs has two stores and an anchor
   --  in java-21's cacerts is not in java-17's. A named keystore -- passed to
   --  Configure or given in the environment -- is the whole answer instead,
   --  because a caller pointing at one is not asking about the machine.
   --
   --  @return The anchors in PEM, or "" where none could be read.
   function Java_Anchors return Unbounded_String;

   --  Does that store hold this certificate? By what the armour holds.
   --
   --  @param Certificate_PEM The certificate to look for.
   --  @return True when the NSS databases hold it.
   function NSS_Trusts (Certificate_PEM : String) return Boolean;

   --  @param Certificate_PEM The certificate to look for.
   --  @return True when a Java keystore holds it.
   function Java_Trusts (Certificate_PEM : String) return Boolean;

   --  Does the host's system store hold this certificate?
   --
   --  By what the armour holds, not by name: a certificate is in the store or
   --  it is not, whatever the store chose to call it.
   --
   --  @param Certificate_PEM The certificate to look for.
   --  @return True when the host's system store holds it.
   function System_Trusts (Certificate_PEM : String) return Boolean;

end Truststores;
