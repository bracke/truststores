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

   function Name (Target : Trust_Target) return String;
   function Name (Kind : Trust_Store_Kind) return String;
   function State_Image (State : Trust_State) return String;
   function Target_From_Name (Value : String; Target : out Trust_Target) return Boolean;

   --  Every name Target_From_Name accepts, so a caller can say what it will
   --  take rather than describe it from memory: an error message listing the
   --  choices, or a document that has to stay true. "mac" and "win" were
   --  accepted and undocumented for as long as both lists were written by
   --  hand.
   function Store_Name_Count return Natural;

   --  @param Index in 1 .. Store_Name_Count; "" outside that.
   function Store_Name (Index : Positive) return String;
   function Kind_From_Name
     (Value : String;
      Kind  : out Trust_Store_Kind) return Boolean;
   function Detect_Default_Target return Trust_Target;
   function Default_Selection return Store_Selection;
   function Selection_From_Text
     (Value     : String;
      Selection : out Store_Selection) return Boolean;
   function Target_For (Kind : Trust_Store_Kind) return Trust_Target;
   function Probe (Kind : Trust_Store_Kind) return Trust_State;
   --  Where this host keeps Firefox profiles. Each holding a cert9.db is an
   --  NSS database of its own; the path differs per host, which is why a test
   --  has to ask rather than assume.
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

   function Firefox_Profile_Root_Count (Host : Host_Kind) return Natural;

   --  @param Index in 1 .. Firefox_Profile_Root_Count (Host); "" outside that.
   function Firefox_Profile_Root_Candidate
     (Host : Host_Kind; Index : Positive) return String;

   --  The NSS databases devcert would act on: the shared one Chromium reads
   --  under ~/.pki/nssdb, plus one per Firefox profile, which reads no other.
   --  TRUSTSTORES_NSS_DB names one instead of all of them.
   function NSS_Database_Count return Natural;
   function NSS_Database_Path (Index : Positive) return String;

   function Fingerprint_Alias (Fingerprint : String) return String;
   function Plan
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String) return String;

   --  Apply the operation to one store, and say what became of it. The state
   --  is the store's own answer, not an inference from the message: a caller
   --  deciding between "denied" and "broken" must not depend on the wording.
   procedure Apply
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String);

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
   function NSS_Anchors return Unbounded_String;

   --  Every anchor the host's Java keystores hold, concatenated as PEM.
   --
   --  All of them, not one: a machine with two JDKs has two stores and an anchor
   --  in java-21's cacerts is not in java-17's. A named keystore -- passed to
   --  Configure or given in the environment -- is the whole answer instead,
   --  because a caller pointing at one is not asking about the machine.
   function Java_Anchors return Unbounded_String;

   --  Does that store hold this certificate? By what the armour holds.
   function NSS_Trusts (Certificate_PEM : String) return Boolean;
   function Java_Trusts (Certificate_PEM : String) return Boolean;

   --  Does the host's system store hold this certificate?
   --
   --  By what the armour holds, not by name: a certificate is in the store or
   --  it is not, whatever the store chose to call it.
   --
   --  @param Certificate_PEM The certificate to look for.
   function System_Trusts (Certificate_PEM : String) return Boolean;

end Truststores;
