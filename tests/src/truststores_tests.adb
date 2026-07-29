with Ada.Command_Line;
with Ada.Directories;
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
      Check
        (System_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Unsupported,
         "the system store answers a probe: " & System_State'Image);
      Check
        (NSS_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Unsupported,
         "so does NSS: " & NSS_State'Image);
      Check
        (Java_State in Truststores.Available | Truststores.Tool_Missing
           | Truststores.Unsupported,
         "so does Java: " & Java_State'Image);
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

   Ada.Text_IO.Put_Line
     ("truststores tests: "
      & (if Failures = 0 then "passed" else Failures'Image & " failed"));

   if Failures /= 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Truststores_Tests;
