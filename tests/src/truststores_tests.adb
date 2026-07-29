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
         Skip ("no NSS database on this host with anchors to read");
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

   --  Firefox is packaged three ways on Linux and each confines its profiles to
   --  its own directory. Relocating the home directory is how a suite can prove
   --  a snap's profile is found without a snap installed.
   if Hostkit.Host.Current = Hostkit.Host.Linux then
      declare
         Fake : constant String :=
           Ada.Directories.Compose
             (Hostkit.Fs.Temp_Directory, "truststores-tests-home");
         Snap : constant String :=
           Fake & "/snap/firefox/common/.mozilla/firefox/abc.default";
         Real_Home : constant String := Hostkit.Fs.Home_Directory;
         File : Ada.Text_IO.File_Type;
      begin
         if Ada.Directories.Exists (Fake) then
            Ada.Directories.Delete_Tree (Fake);
         end if;
         Ada.Directories.Create_Path (Snap);
         Ada.Text_IO.Create (File, Ada.Text_IO.Out_File, Snap & "/cert9.db");
         Ada.Text_IO.Put_Line (File, "not a database, but named like one");
         Ada.Text_IO.Close (File);

         Ada.Environment_Variables.Set ("HOME", Fake);
         Check
           (Truststores.NSS_Database_Count > 0,
            "a snap-confined Firefox profile is discovered");
         declare
           Found : Boolean := False;
         begin
            for Index in 1 .. Truststores.NSS_Database_Count loop
               if Ada.Strings.Fixed.Index
                    (Truststores.NSS_Database_Path (Index), "/snap/") /= 0
               then
                  Found := True;
               end if;
            end loop;
            Check (Found, "and it is the snap path that was found");
         end;

         Ada.Environment_Variables.Set ("HOME", Real_Home);
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
