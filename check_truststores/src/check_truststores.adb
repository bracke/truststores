with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;

with Project_Tools.Files;
with Project_Tools.Processes;
with Project_Tools.Text;

--  The release gate for truststores.
--
--  Each rule below is here because something went wrong once. A build tree was
--  committed and nearly published; a store was read on three hosts while the
--  documentation claimed one; the environment variables an application names
--  are a contract that a library must not quietly start reading for itself.
procedure Check_Truststores is
   use Ada.Text_IO;

   Build_Command : constant String := "alr --non-interactive build";
   GNAT_Version_Command : constant String := "alr exec -- gnatls --version";
   Tests_Run_Command : constant String := "./bin/truststores_tests";

   function Root_Directory return String is
      Current : constant String := Ada.Directories.Current_Directory;
   begin
      if Ada.Directories.Exists (Current & "/truststores.gpr") then
         return Current;
      elsif Ada.Directories.Exists (Current & "/../truststores.gpr") then
         return Ada.Directories.Full_Name (Current & "/..");
      else
         Put_Line (Standard_Error, "truststores root not found from " & Current);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      end if;
   end Root_Directory;

   Root   : constant String := Root_Directory;
   Errors : Natural := 0;

   procedure Error (Message : String) is
   begin
      Errors := Errors + 1;
      Put_Line (Standard_Error, "error: " & Message);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Error;

   --  The project_tools requirement helpers report what is wrong and then
   --  raise, which stops at the first one. A gate is more use when it lists
   --  everything and then says so: caught here, counted, and the run carries on
   --  to the end.
   procedure Require_Text
     (Relative_Path : String; Pattern : String; Message : String) is
   begin
      Project_Tools.Files.Require_Contains
        (Root & "/" & Relative_Path, Pattern, Message);
   exception
      when Program_Error =>
         Errors := Errors + 1;
   end Require_Text;

   procedure Require_Files (Paths : Project_Tools.Files.Path_List) is
   begin
      Project_Tools.Files.Require_Files
        (Paths, "required truststores release file missing");
   exception
      when Program_Error =>
         Errors := Errors + 1;
   end Require_Files;

   procedure Require_GNAT_15_Manifest (Relative_Path : String) is
   begin
      Require_Text
        (Relative_Path,
         "gnat_native = ""=15.2.1""",
         Relative_Path & " must pin gnat_native = ""=15.2.1""");
   end Require_GNAT_15_Manifest;

   procedure Require_Alire_GNAT_15 is
      Output : constant String :=
        Project_Tools.Processes.Shell_Output
          ("cd " & Project_Tools.Processes.Shell_Quote (Root)
           & " && " & GNAT_Version_Command);
   begin
      Put_Line ("");
      Put_Line ("==> verify Alire-selected GNAT 15 toolchain");

      if Output = "" then
         Error ("alr exec -- gnatls --version failed");
      elsif not Project_Tools.Text.Contains (Output, "GNATLS 15.") then
         Error ("truststores must build with GNAT 15, got: " & Output);
      end if;
   end Require_Alire_GNAT_15;

   procedure Run_Command (Label : String; Dir : String; Command : String) is
      Status : Integer;
   begin
      Put_Line ("");
      Put_Line ("==> " & Label);
      Status :=
        Project_Tools.Processes.Run_Shell_In_Directory (Dir, Command);
      if Status /= 0 then
         Error (Label & " failed with status" & Status'Image);
      end if;
   end Run_Command;

   --  Nothing generated may be tracked. A build tree was committed here once and
   --  came within one command of being published: obj/, lib/, the Alire lock, the
   --  generated config, and a compiled test binary.
   procedure Require_No_Tracked_Build_Output is
      Output : constant String :=
        Project_Tools.Processes.Shell_Output
          ("cd " & Project_Tools.Processes.Shell_Quote (Root)
           & " && git ls-files");
   begin
      Put_Line ("");
      Put_Line ("==> no generated files are tracked");

      if Output = "" then
         Error ("git ls-files returned nothing; is this a repository?");
         return;
      end if;

      declare
         Generated : constant array (1 .. 5) of Unbounded_String :=
           [To_Unbounded_String ("obj/"),
            To_Unbounded_String ("lib/"),
            To_Unbounded_String ("alire/"),
            To_Unbounded_String ("/config/"),
            To_Unbounded_String ("bin/")];
      begin
         for Pattern of Generated loop
            if Project_Tools.Text.Contains (Output, To_String (Pattern)) then
               Error
                 ("a generated path is tracked: " & To_String (Pattern)
                  & " -- see .gitignore");
            end if;
         end loop;
      end;
   end Require_No_Tracked_Build_Output;

   --  A library must not read its caller's environment. The variables this crate
   --  consults are its own; an application's -- DEVCERT_NSS_DB and the rest --
   --  arrive through Configure, and a source that names one has stopped being a
   --  library.
   procedure Require_No_Application_Variables is
      Output : constant String :=
        Project_Tools.Processes.Shell_Output
          ("cd " & Project_Tools.Processes.Shell_Quote (Root)
           --  A quoted name, which is what a read looks like. The
           --  specification names DEVCERT_NSS_DB in prose as the example of
           --  what an application passes in, and prose is the opposite of the
           --  problem.
           & " && grep -n '""DEVCERT_' src/truststores.adb src/truststores.ads"
           & " | head -3");
   begin
      Put_Line ("");
      Put_Line ("==> no application environment variables in the library");

      if Output /= "" then
         Error
           ("the library names an application's environment variable: " & Output);
      end if;
   end Require_No_Application_Variables;

begin
   Project_Tools.Processes.Require_Command
     ("alr", "alr executable not found on PATH");
   Require_Alire_GNAT_15;

   Require_GNAT_15_Manifest ("alire.toml");
   Require_GNAT_15_Manifest ("tests/alire.toml");
   Require_GNAT_15_Manifest ("check_truststores/alire.toml");

   Require_Files
     ([To_Unbounded_String (Root & "/README.md"),
       To_Unbounded_String (Root & "/LICENSE"),
       To_Unbounded_String (Root & "/.gitignore"),
       To_Unbounded_String (Root & "/truststores.gpr"),
       To_Unbounded_String (Root & "/src/truststores.ads"),
       To_Unbounded_String (Root & "/src/truststores.adb"),
       To_Unbounded_String (Root & "/docs/platform_evidence.md"),
       To_Unbounded_String (Root & "/tests/alire.toml"),
       To_Unbounded_String (Root & "/tests/truststores_tests.gpr"),
       To_Unbounded_String (Root & "/.github/workflows/ci.yml"),
       To_Unbounded_String (Root & "/CLAUDE.md"),
       To_Unbounded_String (Root & "/AGENTS.md"),
       To_Unbounded_String (Root & "/CHANGELOG.md")]);

   --  The README has to carry the contract, not just the crate name.
   Require_Text
     ("README.md", "System_Anchors",
      "README must document the reading side");
   Require_Text
     ("README.md", "Configure",
      "README must document that configuration is passed in, not read");
   Require_Text
     ("README.md", "permission-required",
      "README must document the state a caller can act on");
   Require_Text
     ("README.md", "docs/platform_evidence.md",
      "README must point at the validation record");

   --  The rules an agent or a newcomer would otherwise have to infer from the
   --  code, and which took six never-working features in devcert to learn.
   Require_Text
     ("CLAUDE.md", "Ask the store, not the tool",
      "CLAUDE.md must carry the rule about verifying against the store");
   Require_Text
     ("CLAUDE.md", "does not read its caller's environment",
      "CLAUDE.md must carry the rule about configuration");
   Require_Text
     ("CLAUDE.md", "not the first one found",
      "CLAUDE.md must carry the rule about every store of each kind");

   --  Reading is CI's to prove and mutating is not, so the record has to say
   --  which is which -- and name what nobody has run.
   Require_Text
     ("docs/platform_evidence.md", "## Not Validated",
      "the evidence file must carry a standing list of what is not covered");
   Require_Text
     ("docs/platform_evidence.md", "## Reading, On Every Host",
      "the evidence file must record the reading runs CI makes");

   --  Three hosts, or the matrix is decoration: where a host keeps its anchors
   --  is the whole subject of this crate.
   Require_Text
     (".github/workflows/ci.yml", "macos-15-intel",
      "CI must run on macOS");
   Require_Text
     (".github/workflows/ci.yml", "windows-latest",
      "CI must run on Windows");
   Require_Text
     (".github/workflows/ci.yml", "cannot do is mutate",
      "CI must state what it cannot validate");

   --  Every store this crate claims to know about, named in the specification.
   Require_Text
     ("src/truststores.ads", "NSS_Anchors",
      "the specification must offer the NSS store");
   Require_Text
     ("src/truststores.ads", "Java_Anchors",
      "the specification must offer the Java store");

   Require_No_Tracked_Build_Output;
   Require_No_Application_Variables;

   Run_Command ("build the library", Root, Build_Command);
   Run_Command ("build the tests", Root & "/tests", Build_Command);
   Run_Command ("run the tests", Root & "/tests", Tests_Run_Command);

   Put_Line ("");
   if Errors = 0 then
      Put_Line ("truststores release check passed");
   else
      Put_Line
        (Standard_Error,
         "truststores release check failed:" & Errors'Image & " error(s)");
   end if;
end Check_Truststores;
