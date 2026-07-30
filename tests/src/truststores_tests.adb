with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;  use Ada.Strings.Unbounded;
with Ada.Text_IO;

with Hostkit.Fs;
with Hostkit.Host;

with Truststores;

--  What this host trusts, and what it will let a program do about it.
--
--  Nothing here mutates a real store. The mutating side is validated by hand,
--  per host, and recorded in docs/platform_evidence.md; what a suite can check
--  is the reading, the discovery, and the refusals.
procedure Truststores_Tests is
   use type Hostkit.Host.Kind;
   use type Truststores.Trust_State;

   Failures : Natural := 0;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      if Condition then
         Ada.Text_IO.Put_Line ("OK   " & Message);
      else
         Ada.Text_IO.Put_Line ("FAIL " & Message);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Skip (Message : String) is
   begin
      Ada.Text_IO.Put_Line ("SKIP " & Message);
   end Skip;

   --  The first certificate in a PEM text, armour and all.
   function First_Certificate (Text : String) return String is
      Opening : constant String := "-----BEGIN CERTIFICATE-----";
      Closing : constant String := "-----END CERTIFICATE-----";
      Head    : constant Natural := Ada.Strings.Fixed.Index (Text, Opening);
      Tail    : Natural;
   begin
      if Head = 0 then
         return "";
      end if;
      Tail := Ada.Strings.Fixed.Index (Text (Head .. Text'Last), Closing);
      if Tail = 0 then
         return "";
      end if;
      return Text (Head .. Tail + Closing'Length - 1);
   end First_Certificate;
begin
   Ada.Text_IO.Put_Line ("truststores: reading what this host trusts");

   declare
      Anchors : constant String := To_String (Truststores.System_Anchors);
      Count   : constant Natural := Truststores.System_Anchor_Count;
   begin
      if Hostkit.Host.Current = Hostkit.Host.Unsupported then
         Skip ("no body for this host");
      elsif Anchors = "" then
         --  A host with no anchors at all is a real answer -- a container built
         --  without ca-certificates is exactly that -- and it is not a failure.
         Skip ("this host holds no system anchors to read");
      else
         Check (Count > 0, "the anchors it returns are certificates:" & Count'Image);
         Check
           (Ada.Strings.Fixed.Index (Anchors, "-----BEGIN CERTIFICATE-----") /= 0,
            "and they arrive as PEM a verifier can be pointed at");

         --  The store trusts what the store holds. Taking a certificate out of
         --  the bundle and asking about it exercises the comparison against a
         --  real anchor rather than a made-up one.
         declare
            Own : constant String := First_Certificate (Anchors);
         begin
            Check (Own /= "", "a single anchor can be taken out of the bundle");
            if Own /= "" then
               Check
                 (Truststores.System_Trusts (Own),
                  "and the store says it trusts one of its own anchors");
            end if;
         end;
      end if;
   end;

   --  A certificate no host trusts. The text is a valid PEM block whose base64
   --  is not a certificate, which is the shape a wrong answer would come from.
   Check
     (not Truststores.System_Trusts
        ("-----BEGIN CERTIFICATE-----" & ASCII.LF
         & "bm90IGEgY2VydGlmaWNhdGU=" & ASCII.LF
         & "-----END CERTIFICATE-----" & ASCII.LF),
      "and does not claim to trust something that is not a certificate");

   Check
     (not Truststores.System_Trusts (""),
      "nor an empty text");

   Ada.Text_IO.Put_Line ("truststores: what it will let a program do");

   --  Probing must not mutate anything, and must answer for every store.
   declare
      System_State : constant Truststores.Trust_State :=
        Truststores.Probe (Truststores.System_Store);
      NSS_State : constant Truststores.Trust_State :=
        Truststores.Probe (Truststores.NSS_Store);
      Java_State : constant Truststores.Trust_State :=
        Truststores.Probe (Truststores.Java_Store);
   begin
      --  Every answer a probe may give, and no more: available, no tool for it,
      --  the tool but nothing to write into, or a host this crate has no body
      --  for. Not_Installed belongs on that list -- a runner with certutil and
      --  no database is exactly that, which is how a hosted runner arrives and
      --  what this test first got wrong.
      Check
        (System_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Not_Installed | Truststores.Unsupported,
         "the system store answers a probe: " & System_State'Image);
      Check
        (NSS_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Not_Installed | Truststores.Unsupported,
         "so does NSS: " & NSS_State'Image);
      Check
        (Java_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Not_Installed | Truststores.Unsupported,
         "so does Java: " & Java_State'Image);

      --  And a probe says nothing about what it found: it must not mutate.
      Check
        (Truststores.Probe (Truststores.NSS_Store) = NSS_State,
         "and answers the same way twice");
   end;

   --  Configure is what a library takes instead of reading its caller's
   --  environment. Pointed at a directory of ours, the Linux system store is
   --  that directory: available, and nothing outside it is touched.
   if Hostkit.Host.Current = Hostkit.Host.Linux then
      declare
         Scratch : constant String :=
           Ada.Directories.Compose
             (Hostkit.Fs.Temp_Directory, "truststores-tests-anchors");
      begin
         if Ada.Directories.Exists (Scratch) then
            Ada.Directories.Delete_Tree (Scratch);
         end if;
         Ada.Directories.Create_Path (Scratch);

         Truststores.Configure (Linux_Anchor_Directory => Scratch);
         Check
           (Truststores.Probe (Truststores.System_Store)
              = Truststores.Available,
            "a configured anchor directory is the system store");

         Truststores.Configure;
         Ada.Directories.Delete_Tree (Scratch);
      end;
   end if;

   Ada.Text_IO.Put_Line ("truststores: reading the other stores");

   --  A Java keystore dumps whole, so this is one certificate set and a
   --  membership question that has to agree with it.
   declare
      Java : constant String := To_String (Truststores.Java_Anchors);
   begin
      if Java = "" then
         Skip ("no Java keystore on this host to read");
      else
         Check
           (Ada.Strings.Fixed.Index (Java, "-----BEGIN CERTIFICATE-----") /= 0,
            "a Java keystore reads back as PEM");
         declare
            Own : constant String := First_Certificate (Java);
         begin
            Check
              (Own /= "" and then Truststores.Java_Trusts (Own),
               "and the keystore holds an anchor it just handed over");
         end;
         Check
           (not Truststores.Java_Trusts
              ("-----BEGIN CERTIFICATE-----" & ASCII.LF
               & "bm90IGEgY2VydGlmaWNhdGU=" & ASCII.LF
               & "-----END CERTIFICATE-----" & ASCII.LF),
            "and not something that is not a certificate");
      end if;
   end;

   --  NSS costs a spawn per anchor, so this asks only whether it answers at all
   --  and whether an answer agrees with itself.
   declare
      NSS : constant String := To_String (Truststores.NSS_Anchors);
   begin
      if NSS = "" then
         Skip ("no NSS anchors to read here -- certutil: "
               & (if Truststores.Probe (Truststores.NSS_Store)
                    = Truststores.Tool_Missing
                  then "not installed"
                  else "installed, databases:"
                       & Truststores.NSS_Database_Count'Image));
      else
         Check
           (Truststores.NSS_Database_Count > 0,
            "the databases it read were discovered:"
            & Truststores.NSS_Database_Count'Image);
         declare
            Own : constant String := First_Certificate (NSS);
         begin
            Check
              (Own /= "" and then Truststores.NSS_Trusts (Own),
               "an NSS database holds an anchor it just handed over");
         end;
      end if;
   end;

   --  A machine can have several JDKs, and an anchor in one is not in another.
   --  What the suite can check is that they are counted rather than taken as one,
   --  and that the aliases a distribution fills that directory with -- default-java
   --  and java-1.21.0-openjdk-amd64 both being java-21-openjdk-amd64 -- are the
   --  same store rather than three.
   declare
      Java : constant String := To_String (Truststores.Java_Anchors);
   begin
      if Java = "" then
         Skip ("no Java keystore to count");
      else
         Check
           (Truststores.Probe (Truststores.Java_Store) = Truststores.Available,
            "a host with a keystore says the Java store is available");

         --  Reading twice must agree: discovery resolves and deduplicates, and
         --  a set that grew between calls would mean it does neither.
         Check
           (To_String (Truststores.Java_Anchors)'Length = Java'Length,
            "and reading the keystores twice returns the same set");
      end if;
   end;

   --  Where this host keeps Firefox profiles, walked rather than assumed.
   --
   --  A profile is a directory holding cert9.db, so one can be staged: relocate
   --  the directory the host reports as home (or as application data on
   --  Windows), put a file of that name under the root this host is supposed to
   --  search, and ask. No Firefox is involved, and the paths that differ per
   --  host -- a snap's confinement, a space in "Application Support", a
   --  backslash under APPDATA -- are exercised on the host they belong to.
   declare
      Fake : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-tests-home");

      --  What to relocate, and the root that should then be searched. Windows
      --  reads APPDATA for application data; the other two build theirs from
      --  the home directory.
      Variable : constant String :=
        (case Hostkit.Host.Current is
            when Hostkit.Host.Windows => "APPDATA",
            when others               => "HOME");

      Profile : constant String :=
        (case Hostkit.Host.Current is
            when Hostkit.Host.Windows =>
              Fake & "\Mozilla\Firefox\Profiles\abc.default",
            when Hostkit.Host.MacOS =>
              Fake & "/Library/Application Support/Firefox/Profiles/abc.default",
            when others =>
              Fake & "/snap/firefox/common/.mozilla/firefox/abc.default");

      --  The part of the path that proves the right root was searched rather
      --  than some other one that happened to exist.
      Mark : constant String :=
        (case Hostkit.Host.Current is
            when Hostkit.Host.Windows => "Firefox",
            when Hostkit.Host.MacOS   => "Application Support",
            when others               => "/snap/");

      Restore : constant String :=
        (if Ada.Environment_Variables.Exists (Variable)
         then Ada.Environment_Variables.Value (Variable)
         else "");

      File  : Ada.Text_IO.File_Type;
      Found : Boolean := False;
   begin
      if Hostkit.Host.Current = Hostkit.Host.Unsupported then
         Skip ("no body for this host to ask");
      else
         if Ada.Directories.Exists (Fake) then
            Ada.Directories.Delete_Tree (Fake);
         end if;
         Ada.Directories.Create_Path (Profile);
         Ada.Text_IO.Create
           (File, Ada.Text_IO.Out_File,
            Ada.Directories.Compose (Profile, "cert9.db"));
         Ada.Text_IO.Put_Line (File, "not a database, but named like one");
         Ada.Text_IO.Close (File);

         Ada.Environment_Variables.Set (Variable, Fake);

         Check
           (Truststores.NSS_Database_Count > 0,
            "a staged Firefox profile is discovered on this host");

         for Index in 1 .. Truststores.NSS_Database_Count loop
            if Ada.Strings.Fixed.Index
                 (Truststores.NSS_Database_Path (Index), Mark) /= 0
            then
               Found := True;
            end if;
         end loop;
         Check
           (Found,
            "and it is the root this host keeps them under: " & Mark);

         if Restore = "" then
            Ada.Environment_Variables.Clear (Variable);
         else
            Ada.Environment_Variables.Set (Variable, Restore);
         end if;
         Ada.Directories.Delete_Tree (Fake);
      end if;
   end;

   --  The Flathub Firefox, which does not keep its profiles where the other
   --  flatpak candidate says. A flatpak gives the application its own
   --  XDG_CONFIG_HOME, and Firefox 153 writes into it rather than into the
   --  ~/.mozilla the sandbox also offers -- so a run against a real one found
   --  profiles.ini and a cert9.db under config/mozilla/firefox and nothing at
   --  all under .mozilla/firefox. Linux only: the other two hosts have no
   --  flatpaks to confine.
   if Hostkit.Host.Current = Hostkit.Host.Linux then
      declare
         Fake : constant String :=
           Ada.Directories.Compose
             (Hostkit.Fs.Temp_Directory, "truststores-tests-flatpak-home");
         Profile : constant String :=
           Fake
           & "/.var/app/org.mozilla.firefox/config/mozilla/firefox/abc.default";
         Mark : constant String := "/.var/app/org.mozilla.firefox/config/";
         Restore : constant String :=
           (if Ada.Environment_Variables.Exists ("HOME")
            then Ada.Environment_Variables.Value ("HOME")
            else "");
         File  : Ada.Text_IO.File_Type;
         Found : Boolean := False;
      begin
         if Ada.Directories.Exists (Fake) then
            Ada.Directories.Delete_Tree (Fake);
         end if;
         Ada.Directories.Create_Path (Profile);
         Ada.Text_IO.Create
           (File, Ada.Text_IO.Out_File,
            Ada.Directories.Compose (Profile, "cert9.db"));
         Ada.Text_IO.Put_Line (File, "not a database, but named like one");
         Ada.Text_IO.Close (File);

         Ada.Environment_Variables.Set ("HOME", Fake);

         for Index in 1 .. Truststores.NSS_Database_Count loop
            if Ada.Strings.Fixed.Index
                 (Truststores.NSS_Database_Path (Index), Mark) /= 0
            then
               Found := True;
            end if;
         end loop;
         Check
           (Found,
            "a flatpak Firefox profile is discovered where Firefox puts it: "
            & Mark);

         if Restore = "" then
            Ada.Environment_Variables.Clear ("HOME");
         else
            Ada.Environment_Variables.Set ("HOME", Restore);
         end if;
         Ada.Directories.Delete_Tree (Fake);
      end;
   end if;

   Ada.Text_IO.Put_Line
     ("truststores tests: "
      & (if Failures = 0 then "passed" else Failures'Image & " failed"));

   if Failures /= 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Truststores_Tests;
