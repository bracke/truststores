with Ada.Streams.Stream_IO;
with Ada.Characters.Handling;
with Ada.Environment_Variables;
with Ada.Directories;
with Ada.Text_IO;
with Ada.Strings.Fixed;

with GNAT.OS_Lib;

with CryptoLib.Certificates;

with Hostkit.Fs;
with Hostkit.Process;
with Hostkit.Host;

package body Truststores is
   --  Long enough for a keychain prompt to be answered, short enough that a
   --  tool which has stopped talking does not hold devcert for ever.
   Command_Timeout_Ms : constant := 120_000;

   type Linux_System_Backend is
     (No_Backend,
      Configured_Anchor_Directory,
      Update_CA_Certificates,
      Update_CA_Trust,
      Trust_Anchor);

   function Name (Target : Trust_Target) return String is
   begin
      case Target is
         when Linux =>
            return "linux";
         when NSS =>
            return "nss";
         when Java =>
            return "java";
         when MacOS =>
            return "macos";
         when Windows =>
            return "windows";
      end case;
   end Name;

   function Name (Kind : Trust_Store_Kind) return String is
   begin
      case Kind is
         when System_Store =>
            return "system";
         when NSS_Store =>
            return "nss";
         when Java_Store =>
            return "java";
      end case;
   end Name;

   function State_Image (State : Trust_State) return String is
   begin
      case State is
         when Unsupported =>
            return "unsupported";
         when Available =>
            return "available";
         when Installed =>
            return "installed";
         when Not_Installed =>
            return "not-installed";
         when Tool_Missing =>
            return "tool-missing";
         when Permission_Required =>
            return "permission-required";
         when Partial =>
            return "partial";
         when Error =>
            return "error";
      end case;
   end State_Image;

   function Target_From_Name (Value : String; Target : out Trust_Target) return Boolean is
   begin
      if Value = "system" then
         Target := Detect_Default_Target;
      elsif Value = "linux" then
         Target := Linux;
      elsif Value = "nss" then
         Target := NSS;
      elsif Value = "java" then
         Target := Java;
      elsif Value = "macos" or else Value = "mac" then
         Target := MacOS;
      elsif Value = "windows" or else Value = "win" then
         Target := Windows;
      else
         return False;
      end if;
      return True;
   end Target_From_Name;

   function Kind_From_Name
     (Value : String;
      Kind  : out Trust_Store_Kind) return Boolean
   is
   begin
      if Value = "system"
        or else Value = "linux"
        or else Value = "macos"
        or else Value = "mac"
        or else Value = "windows"
        or else Value = "win"
      then
         Kind := System_Store;
      elsif Value = "nss" then
         Kind := NSS_Store;
      elsif Value = "java" then
         Kind := Java_Store;
      else
         return False;
      end if;
      return True;
   end Kind_From_Name;

   --  The host says which host it is. Sniffing the environment for it read every
   --  macOS as a Linux: OSTYPE is a shell variable, not part of the environment a
   --  spawned process inherits, so devcert reached for update-ca-certificates on a
   --  machine whose trust store is the keychain.
   function Detect_Default_Target return Trust_Target is
      use type Hostkit.Host.Kind;
   begin
      case Hostkit.Host.Current is
         when Hostkit.Host.Windows =>
            return Windows;
         when Hostkit.Host.MacOS =>
            return MacOS;
         when Hostkit.Host.Linux | Hostkit.Host.Unsupported =>
            --  A host with no body of its own is treated as the POSIX case, which is
            --  what the file-based backends assume.
            return Linux;
      end case;
   end Detect_Default_Target;

   function Default_Selection return Store_Selection is
   begin
      return (Count => 1, Items => [1 => System_Store, others => System_Store]);
   end Default_Selection;

   function Contains
     (Selection : Store_Selection;
      Kind      : Trust_Store_Kind) return Boolean
   is
   begin
      for I in 1 .. Selection.Count loop
         if Selection.Items (I) = Kind then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   procedure Append
     (Selection : in out Store_Selection;
      Kind      : Trust_Store_Kind) is
   begin
      if not Contains (Selection, Kind) then
         Selection.Count := Selection.Count + 1;
         Selection.Items (Selection.Count) := Kind;
      end if;
   end Append;

   function Selection_From_Text
     (Value     : String;
      Selection : out Store_Selection) return Boolean
   is
      First : Positive := Value'First;
      Last  : Natural;
      Comma : Natural;
      Kind  : Trust_Store_Kind;
   begin
      Selection := (Count => 0, Items => [others => System_Store]);
      if Value'Length = 0 then
         return False;
      end if;

      while First <= Value'Last loop
         Comma := Ada.Strings.Fixed.Index
           (Value (First .. Value'Last), ",");
         if Comma = 0 then
            Last := Value'Last;
         else
            Last := Comma - 1;
         end if;

         declare
            Part : constant String :=
              Ada.Strings.Fixed.Trim (Value (First .. Last), Ada.Strings.Both);
         begin
            if Part = "" or else not Kind_From_Name (Part, Kind) then
               return False;
            end if;
            Append (Selection, Kind);
         end;

         First := Last + 2;
      end loop;

      return Selection.Count > 0;
   end Selection_From_Text;

   function Target_For (Kind : Trust_Store_Kind) return Trust_Target is
   begin
      case Kind is
         when System_Store =>
            return Detect_Default_Target;
         when NSS_Store =>
            return NSS;
         when Java_Store =>
            return Java;
      end case;
   end Target_For;

   function Plan
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String) return String is
      Verb : constant String := (if Operation = Install then "install" else "remove");
   begin
      case Target is
         when Linux =>
            return Verb & " linux system trust for " & Fingerprint & " using "
              & Certificate;
         when NSS =>
            return Verb & " NSS profiles for " & Fingerprint & " using "
              & Certificate;
         when Java =>
            return Verb & " Java trust stores for " & Fingerprint & " using "
              & Certificate;
         when MacOS =>
            return Verb & " macOS keychain trust for " & Fingerprint & " using "
              & Certificate;
         when Windows =>
            return Verb & " Windows certificate store trust for " & Fingerprint
              & " using " & Certificate;
      end case;
   end Plan;

   function Safe_Fingerprint (Fingerprint : String) return String is
      Result : Unbounded_String;
   begin
      for C of Fingerprint loop
         if C in 'a' .. 'f' or else C in '0' .. '9' then
            Ada.Strings.Unbounded.Append (Result, C);
         end if;
      end loop;
      return Ada.Strings.Unbounded.To_String (Result);
   end Safe_Fingerprint;

   function Fingerprint_Alias (Fingerprint : String) return String is
   begin
      return "devcert-" & Safe_Fingerprint (Fingerprint);
   end Fingerprint_Alias;

   --  Asked of the host: a name resolves through PATHEXT on Windows, where
   --  certutil is certutil.exe, and a resolved path is what the spawn below
   --  needs -- an unresolved name that fails to start is indistinguishable
   --  from a tool that ran and refused.
   function Locate (Name : String) return String is
   begin
      return Hostkit.Process.Locate (Name);
   end Locate;

   function NSS_Database return String;
   function Detect_Linux_Backend return Linux_System_Backend;

   Max_Java_Keystores : constant := 8;
   type Java_Keystore_List is
     array (1 .. Max_Java_Keystores) of Unbounded_String;

   procedure Java_Keystores
     (Keystores : out Java_Keystore_List;
      Count     : out Natural);

   Max_NSS_Databases : constant := 16;
   type NSS_Database_List is
     array (1 .. Max_NSS_Databases) of Unbounded_String;

   procedure Discover_NSS_Databases
     (Databases : out NSS_Database_List;
      Count     : out Natural);

   --  What the caller passed to Configure. Ahead of the environment, because a
   --  caller that names a store is pointing at one deliberately -- a test with
   --  a disposable database, or an application with variables of its own.
   Set_Linux_Directory : Unbounded_String;
   Set_NSS_Database    : Unbounded_String;
   Set_Java_Keystore   : Unbounded_String;

   Linux_Variable : Unbounded_String;
   NSS_Variable   : Unbounded_String;
   Java_Variable  : Unbounded_String;

   procedure Configure
     (Linux_Anchor_Directory : String := "";
      NSS_Database           : String := "";
      Java_Keystore          : String := "";
      Linux_Directory_Variable : String := "";
      NSS_Database_Variable    : String := "";
      Java_Keystore_Variable   : String := "") is
   begin
      Set_Linux_Directory :=
        Ada.Strings.Unbounded.To_Unbounded_String (Linux_Anchor_Directory);
      Set_NSS_Database :=
        Ada.Strings.Unbounded.To_Unbounded_String (NSS_Database);
      Set_Java_Keystore :=
        Ada.Strings.Unbounded.To_Unbounded_String (Java_Keystore);
      Linux_Variable :=
        Ada.Strings.Unbounded.To_Unbounded_String (Linux_Directory_Variable);
      NSS_Variable :=
        Ada.Strings.Unbounded.To_Unbounded_String (NSS_Database_Variable);
      Java_Variable :=
        Ada.Strings.Unbounded.To_Unbounded_String (Java_Keystore_Variable);
   end Configure;

   --  A setting, then the caller's own variable, then this crate's, then
   --  nothing. Read each time rather than once, so a caller that sets a
   --  variable after startup is still heard.
   function Setting
     (Chosen   : Unbounded_String;
      Variable : Unbounded_String;
      Name     : String) return String
   is
      function Env (From : String) return String is
        (if From /= "" and then Ada.Environment_Variables.Exists (From)
         then Ada.Environment_Variables.Value (From)
         else "");

      Named : constant String :=
        Env (Ada.Strings.Unbounded.To_String (Variable));
   begin
      if Ada.Strings.Unbounded.Length (Chosen) > 0 then
         return Ada.Strings.Unbounded.To_String (Chosen);
      elsif Named /= "" then
         return Named;
      else
         return Env (Name);
      end if;
   end Setting;

   function Configured_Linux_Trust_Dir return String is
   begin
      return Setting (Set_Linux_Directory, Linux_Variable, "TRUSTSTORES_LINUX_DIR");
   end Configured_Linux_Trust_Dir;

   function Probe (Kind : Trust_Store_Kind) return Trust_State is
   begin
      case Kind is
         when System_Store =>
            case Detect_Default_Target is
               when Linux =>
                  return
                    (if Detect_Linux_Backend = No_Backend
                     then Tool_Missing
                     else Available);
               when MacOS =>
                  if Locate ("security") /= "" then
                     return Available;
                  else
                     return Tool_Missing;
                  end if;
               when Windows =>
                  if Locate ("certutil") /= "" then
                     return Available;
                  else
                     return Tool_Missing;
                  end if;
               when others =>
                  return Unsupported;
            end case;
         when NSS_Store =>
            if Locate ("certutil") = "" then
               return Tool_Missing;
            elsif NSS_Database_Count = 0 then
               return Not_Installed;
            else
               return Available;
            end if;
         when Java_Store =>
            if Locate ("keytool") = "" then
               return Tool_Missing;
            else
               declare
                  Keystores : Java_Keystore_List;
                  Count     : Natural;
               begin
                  Java_Keystores (Keystores, Count);
                  return (if Count = 0 then Not_Installed else Available);
               end;
            end if;
      end case;
   end Probe;

   --  Run a tool and report how it went.
   --
   --  Through hostkit, which knows what a spawn means on each host and gives
   --  the child somewhere to write. devcert used to do this itself, capturing
   --  into /tmp spelled out -- a directory Windows has not got, so the spawn
   --  could not create the file it was told to capture into and every
   --  trust-store command there reported failure whatever the tool did.
   --
   --  Under a deadline, because a trust tool that never returns used to mean a
   --  devcert that never returns.
   procedure Run
     (Program     : String;
      Args        : GNAT.OS_Lib.Argument_List;
      Success     : out Boolean;
      Exit_Status : out Integer)
   is
      Arguments : Hostkit.String_Vectors.Vector;
      Out_Path  : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-command.out");
      Err_Path  : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-command.err");
      Outcome   : Hostkit.Process.Process_Outcome;
   begin
      for Item of Args loop
         Arguments.Append
           (Ada.Strings.Unbounded.To_Unbounded_String (Item.all));
      end loop;

      Outcome :=
        Hostkit.Process.Run_Captured
          (Program     => Program,
           Arguments   => Arguments,
           Stdout_Path => Out_Path,
           Stderr_Path => Err_Path,
           Timeout_Ms  => Command_Timeout_Ms);

      if Ada.Directories.Exists (Out_Path) then
         Ada.Directories.Delete_File (Out_Path);
      end if;
      if Ada.Directories.Exists (Err_Path) then
         Ada.Directories.Delete_File (Err_Path);
      end if;

      Success := Outcome.Started and then not Outcome.Timed_Out
        and then Outcome.Exit_Status = 0;
      Exit_Status := (if Outcome.Started then Outcome.Exit_Status else -1);
   end Run;

   procedure Run
     (Program : String;
      Args    : GNAT.OS_Lib.Argument_List;
      Success : out Boolean)
   is
      Ignored : Integer;
   begin
      Run (Program, Args, Success, Ignored);
   end Run;

   function Read_Text_File (Path : String) return String is
      File   : Ada.Text_IO.File_Type;
      Result : Unbounded_String;
   begin
      Ada.Text_IO.Open (File, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File) loop
         Ada.Strings.Unbounded.Append (Result, Ada.Text_IO.Get_Line (File));
         Ada.Strings.Unbounded.Append (Result, ASCII.LF);
      end loop;
      Ada.Text_IO.Close (File);
      return Ada.Strings.Unbounded.To_String (Result);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File) then
            Ada.Text_IO.Close (File);
         end if;
         return "";
   end Read_Text_File;

   --  The same, keeping what the tool said. Only stdout: what is read back
   --  from these tools -- a certificate listing, a store dump -- is what they
   --  print there.
   procedure Run_Capture
     (Program : String;
      Args    : GNAT.OS_Lib.Argument_List;
      Success : out Boolean;
      Output  : out Unbounded_String)
   is
      Arguments : Hostkit.String_Vectors.Vector;
      Out_Path  : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-capture.out");
      --  Captured and dropped rather than inherited: a certutil that cannot
      --  find something says so on standard error, and it is this library's
      --  business what to make of that, not the caller's terminal's.
      Err_Path  : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-capture.err");
      Outcome   : Hostkit.Process.Process_Outcome;
   begin
      for Item of Args loop
         Arguments.Append
           (Ada.Strings.Unbounded.To_Unbounded_String (Item.all));
      end loop;

      Outcome :=
        Hostkit.Process.Run_Captured
          (Program     => Program,
           Arguments   => Arguments,
           Stdout_Path => Out_Path,
           Stderr_Path => Err_Path,
           Timeout_Ms  => Command_Timeout_Ms);

      if Ada.Directories.Exists (Err_Path) then
         Ada.Directories.Delete_File (Err_Path);
      end if;

      Output :=
        (if Ada.Directories.Exists (Out_Path)
         then Ada.Strings.Unbounded.To_Unbounded_String
                (Read_Text_File (Out_Path))
         else Ada.Strings.Unbounded.Null_Unbounded_String);

      if Ada.Directories.Exists (Out_Path) then
         Ada.Directories.Delete_File (Out_Path);
      end if;

      Success := Outcome.Started and then not Outcome.Timed_Out
        and then Outcome.Exit_Status = 0;
   end Run_Capture;

   --  Asked of cryptolib, which owns PEM. Comparing scrubbed text here treated
   --  the armour as noise, so a private key and a certificate whose base64
   --  matched would have compared equal -- and this decides whether an anchor
   --  on disk is ours before it is deleted.
   function Same_Certificate (Left : String; Right : String) return Boolean is
   begin
      return CryptoLib.Certificates.Same_Certificate (Left, Right);
   end Same_Certificate;

   function Detect_Linux_Backend return Linux_System_Backend is
   begin
      if Configured_Linux_Trust_Dir /= "" then
         return Configured_Anchor_Directory;
      elsif Locate ("update-ca-certificates") /= "" then
         return Update_CA_Certificates;
      elsif Locate ("update-ca-trust") /= "" then
         return Update_CA_Trust;
      elsif Locate ("trust") /= "" then
         return Trust_Anchor;
      else
         return No_Backend;
      end if;
   end Detect_Linux_Backend;

   function Linux_Target
     (Backend     : Linux_System_Backend;
      Fingerprint : String) return String
   is
      Safe : constant String := Safe_Fingerprint (Fingerprint);
   begin
      case Backend is
         when Configured_Anchor_Directory =>
            return Configured_Linux_Trust_Dir & "/devcert-" & Safe & ".crt";
         when Update_CA_Certificates =>
            return "/usr/local/share/ca-certificates/devcert-" & Safe & ".crt";
         when Update_CA_Trust =>
            --  Same tool, different directory: Fedora and RHEL keep anchors
            --  under /etc/pki/ca-trust, Arch under /etc/ca-certificates. The
            --  Fedora path was hardcoded, so on Arch every install wrote into
            --  a directory that does not exist and reported it as wanting
            --  privileges.
            declare
               Fedora : constant String := "/etc/pki/ca-trust/source/anchors";
               Arch   : constant String :=
                 "/etc/ca-certificates/trust-source/anchors";
            begin
               if Ada.Directories.Exists (Fedora) then
                  return Fedora & "/devcert-" & Safe & ".crt";
               elsif Ada.Directories.Exists (Arch) then
                  return Arch & "/devcert-" & Safe & ".crt";
               end if;
               return Fedora & "/devcert-" & Safe & ".crt";
            end;
         when others =>
            return "";
      end case;
   end Linux_Target;

   procedure Refresh_Linux
     (Backend : Linux_System_Backend;
      Success : out Boolean)
   is
   begin
      case Backend is
         when Configured_Anchor_Directory =>
            Success := True;
         when Update_CA_Certificates =>
            Run
              (Locate ("update-ca-certificates"),
               [1 => new String'("--fresh")],
               Success);
         when Update_CA_Trust =>
            Run
              (Locate ("update-ca-trust"),
               [1 => new String'("extract")],
               Success);
         when others =>
            Success := True;
      end case;
   end Refresh_Linux;

   procedure Apply_Linux
     (Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      Backend : constant Linux_System_Backend := Detect_Linux_Backend;
      Target : constant String :=
        Linux_Target (Backend, Fingerprint);
      Ran : Boolean := False;
      Success : Boolean := False;
   begin
      Success := False;
      State := Error;
      Message := Ada.Strings.Unbounded.Null_Unbounded_String;

      if Backend = No_Backend then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("linux trust backend is not installed");
         return;
      end if;

      case Operation is
         when Install =>
            if Backend = Trust_Anchor then
               Run
                 (Locate ("trust"),
                  [new String'("anchor"), new String'(Certificate)],
                  Ran);

               --  p11-kit stores the anchor and then runs a compat extractor
               --  to rewrite the bundle files. Debian and Ubuntu ship no such
               --  extractor -- no package provides it -- so trust exits 2
               --  having done the work asked of it. Believing that exit code
               --  reports a failed install of a certificate the host now
               --  trusts, which is the worse of the two wrong answers. The
               --  store is the authority, as it is for every other adapter
               --  here.
               if not Ran then
                  Ran := System_Trusts (Read_Text_File (Certificate));
               end if;
            else
               if Backend = Configured_Anchor_Directory then
                  Ada.Directories.Create_Path (Configured_Linux_Trust_Dir);
               end if;
               Ada.Directories.Copy_File (Certificate, Target);
               Refresh_Linux (Backend, Ran);
            end if;
            Success := Ran;
            State := (if Success then Installed else Error);
            if Success then
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   ("installed linux trust anchor for " & Fingerprint);
            else
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   (if Backend = Trust_Anchor
                    then "linux trust anchor failed and the store does not"
                         & " hold the certificate"
                    else "linux trust refresh failed");
            end if;
         when Remove =>
            if Backend = Trust_Anchor then
               declare
                  PEM : constant String := Read_Text_File (Certificate);
               begin
                  --  Asked before the removal rather than after it, because
                  --  afterwards "the store does not hold it" is the same
                  --  answer whether this removed it or it was never there.
                  --  The branch below says that difference out loud for the
                  --  other backends, and it is worth as much here.
                  if not System_Trusts (PEM) then
                     Success := True;
                     State := Installed;
                     Message :=
                       Ada.Strings.Unbounded.To_Unbounded_String
                         ("no linux trust anchor for " & Fingerprint);
                     return;
                  end if;

                  Run
                    (Locate ("trust"),
                     [new String'("anchor"),
                      new String'("--remove"),
                      new String'(Certificate)],
                     Ran);

                  --  The same exit code, for the same reason, on the way out.
                  if not Ran then
                     Ran := not System_Trusts (PEM);
                  end if;
               end;
            elsif Ada.Directories.Exists (Target)
              and then Same_Certificate (Read_Text_File (Target), Read_Text_File (Certificate))
            then
               Ada.Directories.Delete_File (Target);
               Refresh_Linux (Backend, Ran);
            elsif Ada.Directories.Exists (Target) then
               Ran := False;
               State := Error;
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   ("linux trust anchor fingerprint mismatch; refusing removal");
               return;
            else
               --  Nothing of ours to remove. That is a success, but saying
               --  "removed" for it is a claim about work that never happened,
               --  and it read as removal from a store that had refused the
               --  install moments earlier.
               Success := True;
               State := Installed;
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   ("no linux trust anchor for " & Fingerprint);
               return;
            end if;
            Success := Ran;
            State := (if Success then Installed else Error);
            if Success then
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   ("removed linux trust anchor for " & Fingerprint);
            else
               Message :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   ("linux trust removal failed");
            end if;
      end case;
   exception
      when others =>
         --  The copy or the refresh raised. On this backend that is what a
         --  store owned by root looks like from an unprivileged process.
         Success := False;
         State := Permission_Required;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("linux trust store update requires permission for " & Target);
   end Apply_Linux;

   function Java_Contains_Certificate
     (Keytool     : String;
      Keystore    : String;
      Alias       : String;
      Certificate : String) return Boolean
   is
      Ran    : Boolean := False;
      Output : Unbounded_String;
   begin
      if Keystore = "" then
         Run_Capture
           (Keytool,
            [new String'("-list"),
             new String'("-rfc"),
             new String'("-cacerts"),
             new String'("-storepass"),
             new String'("changeit"),
             new String'("-alias"),
             new String'(Alias)],
            Ran,
            Output);
      else
         Run_Capture
           (Keytool,
            [new String'("-list"),
             new String'("-rfc"),
             new String'("-keystore"),
             new String'(Keystore),
             new String'("-storepass"),
             new String'("changeit"),
             new String'("-alias"),
             new String'(Alias)],
            Ran,
            Output);
      end if;
      return Ran
        and then Same_Certificate
          (Ada.Strings.Unbounded.To_String (Output),
           Read_Text_File (Certificate));
   end Java_Contains_Certificate;

   --  The keystore keytool would write, when it was not told one: the JDK's
   --  own. Taken from JAVA_HOME, or from wherever keytool itself lives, since
   --  a JDK keeps them in one shape -- bin/keytool beside lib/security/cacerts.
   function Default_Java_Keystore (Keytool : String) return String is
   begin
      if Ada.Environment_Variables.Exists ("JAVA_HOME") then
         return Ada.Environment_Variables.Value ("JAVA_HOME")
           & "/lib/security/cacerts";
      end if;

      if Keytool = "" then
         return "";
      end if;

      declare
         --  Through the symlinks: a distribution puts keytool on PATH as a link
         --  into its alternatives system, and the directory that link sits in
         --  is not the JDK. /usr/bin/keytool would otherwise give
         --  /usr/lib/security/cacerts, which is nobody's keystore.
         Real : constant String :=
           GNAT.OS_Lib.Normalize_Pathname (Keytool, Resolve_Links => True);
         Bin  : constant String := Ada.Directories.Containing_Directory (Real);
         Home : constant String := Ada.Directories.Containing_Directory (Bin);
      begin
         return Home & "/lib/security/cacerts";
      end;
   exception
      when others =>
         return "";
   end Default_Java_Keystore;

   --  Every Java keystore on this host.
   --
   --  A machine with two JDKs has two stores, and an anchor in one is not in the
   --  other: java-17 does not read java-21's cacerts. Installing into whichever
   --  keytool happens to be first on PATH leaves the rest untrusting, and says
   --  nothing about it.
   --
   --  Deduplicated by resolved path, because a distribution fills that directory
   --  with aliases: default-java and java-1.21.0-openjdk-amd64 are both
   --  java-21-openjdk-amd64, and installing three times into one store would
   --  report three successes for one anchor.
   procedure Java_Keystores
     (Keystores : out Java_Keystore_List;
      Count     : out Natural)
   is
      use type Hostkit.Host.Kind;

      procedure Add (Path : String) is
         Resolved : constant String :=
           (if Path = "" then "" else Hostkit.Fs.Real_Path (Path));
         Final    : constant String := (if Resolved = "" then Path else Resolved);
      begin
         if Final = ""
           or else Count >= Max_Java_Keystores
           or else not Ada.Directories.Exists (Final)
         then
            return;
         end if;

         for Index in 1 .. Count loop
            if Ada.Strings.Unbounded.To_String (Keystores (Index)) = Final then
               return;
            end if;
         end loop;

         Count := Count + 1;
         Keystores (Count) := Ada.Strings.Unbounded.To_Unbounded_String (Final);
      end Add;

      --  Every <root>/*/lib/security/cacerts under a conventional JVM directory.
      procedure Add_Under (Root : String; Suffix : String) is
         Search : Ada.Directories.Search_Type;
         Item   : Ada.Directories.Directory_Entry_Type;
      begin
         if Root = "" or else not Ada.Directories.Exists (Root) then
            return;
         end if;

         Ada.Directories.Start_Search
           (Search,
            Directory => Root,
            Pattern   => "*",
            Filter    =>
              [Ada.Directories.Directory     => True,
               Ada.Directories.Ordinary_File => False,
               Ada.Directories.Special_File  => False]);
         while Ada.Directories.More_Entries (Search) loop
            Ada.Directories.Get_Next_Entry (Search, Item);
            declare
               Name : constant String := Ada.Directories.Simple_Name (Item);
            begin
               if Name /= "." and then Name /= ".." then
                  Add (Ada.Directories.Full_Name (Item) & Suffix);
               end if;
            end;
         end loop;
         Ada.Directories.End_Search (Search);
      exception
         when others =>
            null;
      end Add_Under;

      Chosen : constant String :=
        Setting (Set_Java_Keystore, Java_Variable, "TRUSTSTORES_JAVA_KEYSTORE");
   begin
      Keystores := [others => Ada.Strings.Unbounded.Null_Unbounded_String];
      Count := 0;

      --  A named keystore is the whole answer: a caller pointing at one is not
      --  asking for every JDK on the machine.
      if Chosen /= "" then
         Count := 1;
         Keystores (1) := Ada.Strings.Unbounded.To_Unbounded_String (Chosen);
         return;
      end if;

      Add (Default_Java_Keystore (Locate ("keytool")));

      case Hostkit.Host.Current is
         when Hostkit.Host.MacOS =>
            Add_Under
              ("/Library/Java/JavaVirtualMachines",
               "/Contents/Home/lib/security/cacerts");
         when Hostkit.Host.Windows =>
            Add_Under ("C:\Program Files\Java", "\lib\security\cacerts");
            Add_Under
              ("C:\Program Files\Eclipse Adoptium", "\lib\security\cacerts");
         when others =>
            Add_Under ("/usr/lib/jvm", "/lib/security/cacerts");
            Add_Under ("/usr/java", "/lib/security/cacerts");
      end case;
   end Java_Keystores;

   --  Can this process write that keystore? Asked by opening it, because the
   --  alternative is inferring it from ownership and mode, and a store may be
   --  unwritable for reasons neither of those shows.
   --
   --  A keystore that is not there yet is the ordinary case for a keystore of
   --  one's own -- keytool creates it -- so the question becomes whether its
   --  directory will have us. And a path we could not work out at all answers
   --  True: the caller turns False into "you need permission", which is a claim,
   --  and a claim is not something to make out of not knowing.
   function Keystore_Is_Writable (Path : String) return Boolean is
      File : Ada.Streams.Stream_IO.File_Type;
   begin
      if Path = "" then
         return True;
      end if;

      if Ada.Directories.Exists (Path) then
         Ada.Streams.Stream_IO.Open
           (File, Ada.Streams.Stream_IO.Append_File, Path);
         Ada.Streams.Stream_IO.Close (File);
         return True;
      end if;

      declare
         Directory : constant String :=
           Ada.Directories.Containing_Directory (Path);
         Probe : constant String :=
           Ada.Directories.Compose (Directory, "devcert-keystore-probe");
      begin
         if not Ada.Directories.Exists (Directory) then
            return True;
         end if;

         Ada.Streams.Stream_IO.Create
           (File, Ada.Streams.Stream_IO.Out_File, Probe);
         Ada.Streams.Stream_IO.Close (File);
         Ada.Directories.Delete_File (Probe);
         return True;
      end;
   exception
      when others =>
         return False;
   end Keystore_Is_Writable;

   procedure Apply_Java
     (Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      Keytool   : constant String := Locate ("keytool");
      Alias     : constant String := Fingerprint_Alias (Fingerprint);
      Keystores : Java_Keystore_List;
      Count     : Natural;
      Failures  : Natural := 0;
      Denials   : Natural := 0;
      Combined  : Unbounded_String;

      procedure Note (Text : String) is
      begin
         if Ada.Strings.Unbounded.Length (Combined) > 0 then
            Ada.Strings.Unbounded.Append (Combined, "; ");
         end if;
         Ada.Strings.Unbounded.Append (Combined, Text);
      end Note;

      --  One keystore's worth of work, so the loop below reads as the aggregate
      --  it is.
      procedure Apply_One (Keystore : String) is
         Ran     : Boolean := False;
         Present : constant Boolean :=
           Java_Contains_Certificate (Keytool, Keystore, Alias, Certificate);
      begin
         case Operation is
            when Install =>
               Run
                 (Keytool,
                  [new String'("-importcert"),
                   new String'("-noprompt"),
                   new String'("-trustcacerts"),
                   new String'("-keystore"),
                   new String'(Keystore),
                   new String'("-storepass"),
                   new String'("changeit"),
                   new String'("-alias"),
                   new String'(Alias),
                   new String'("-file"),
                   new String'(Certificate)],
                  Ran);

               --  Asked of the store, not of the tool: keytool has reported
               --  success for an import the store did not keep.
               if Ran
                 and then not Java_Contains_Certificate
                                (Keytool, Keystore, Alias, Certificate)
               then
                  Ran := False;
               end if;

               if Ran then
                  Note ("installed Java trust anchor " & Alias & " in " & Keystore);
               elsif not Keystore_Is_Writable (Keystore) then
                  Denials := Denials + 1;
                  Failures := Failures + 1;
                  Note
                    ("Java trust store update requires permission for " & Keystore);
               else
                  Failures := Failures + 1;
                  Note ("failed to install Java trust anchor " & Alias
                        & " in " & Keystore);
               end if;

            when Remove =>
               if not Present then
                  --  Nothing of ours in this one. Saying "removed" would be a
                  --  claim about work that never happened.
                  Note ("no Java trust anchor " & Alias & " in " & Keystore);
                  return;
               end if;

               Run
                 (Keytool,
                  [new String'("-delete"),
                   new String'("-keystore"),
                   new String'(Keystore),
                   new String'("-storepass"),
                   new String'("changeit"),
                   new String'("-alias"),
                   new String'(Alias)],
                  Ran);

               if Ran then
                  Note ("removed Java trust anchor " & Alias & " from " & Keystore);
               elsif not Keystore_Is_Writable (Keystore) then
                  Denials := Denials + 1;
                  Failures := Failures + 1;
                  Note
                    ("Java trust store update requires permission for " & Keystore);
               else
                  Failures := Failures + 1;
                  Note ("failed to remove Java trust anchor " & Alias
                        & " from " & Keystore);
               end if;
         end case;
      end Apply_One;
   begin
      State := Error;

      if Keytool = "" then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("keytool is not installed");
         return;
      end if;

      Java_Keystores (Keystores, Count);

      if Count = 0 then
         State := Not_Installed;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("no Java keystore on this host");
         return;
      end if;

      --  Every keystore this host has. An anchor in one JDK is not in another,
      --  and a machine with two of them trusts in one and not the other.
      for Index in 1 .. Count loop
         Apply_One (Ada.Strings.Unbounded.To_String (Keystores (Index)));
      end loop;

      Message := Combined;
      State :=
        (if Failures = 0 then Installed
         elsif Denials = Failures then Permission_Required
         else Error);
   end Apply_Java;

   function NSS_Database return String is
   begin
      if Setting (Set_NSS_Database, NSS_Variable, "TRUSTSTORES_NSS_DB") /= "" then
         return Setting (Set_NSS_Database, NSS_Variable, "TRUSTSTORES_NSS_DB");
      elsif Ada.Environment_Variables.Exists ("HOME") then
         return Ada.Environment_Variables.Value ("HOME") & "/.pki/nssdb";
      else
         return "";
      end if;
   end NSS_Database;

   --  Where the host keeps Firefox profiles. Firefox does not read the shared
   --  database under ~/.pki/nssdb -- that one is Chromium's -- and keeps a
   --  cert9.db of its own per profile, so a certificate installed only into the
   --  shared database is trusted by Chromium and by nothing else.
   --  Every place this host might keep Firefox profiles.
   --
   --  One path was not enough. A packaged Firefox does not use the traditional
   --  directory: a snap keeps its profiles under ~/snap/firefox/common, a
   --  flatpak under ~/.var/app/org.mozilla.firefox, and both are confined so
   --  they cannot see the other's. Ubuntu has shipped Firefox as a snap since
   --  22.04, which made ~/.mozilla empty on the commonest desktop there is --
   --  so a program that looked only at it installed its anchor into nothing and
   --  reported success.
   Max_Profile_Roots : constant := 6;
   type Profile_Root_List is
     array (1 .. Max_Profile_Roots) of Unbounded_String;

   procedure Firefox_Profile_Roots
     (Roots : out Profile_Root_List;
      Count : out Natural)
   is
      Data : constant String := Hostkit.Fs.Application_Data_Directory;
      Home : constant String := Hostkit.Fs.Home_Directory;

      procedure Add (Path : String) is
      begin
         if Path /= "" and then Count < Max_Profile_Roots then
            Count := Count + 1;
            Roots (Count) := Ada.Strings.Unbounded.To_Unbounded_String (Path);
         end if;
      end Add;
   begin
      Roots := [others => Ada.Strings.Unbounded.Null_Unbounded_String];
      Count := 0;

      case Hostkit.Host.Current is
         when Hostkit.Host.Windows =>
            if Data /= "" then
               Add (Data & "\Mozilla\Firefox\Profiles");
            end if;

         when Hostkit.Host.MacOS =>
            if Data /= "" then
               Add (Data & "/Firefox/Profiles");
            end if;

         when others =>
            --  Linux keeps Firefox under the home directory rather than under
            --  the data directory, because ~/.mozilla predates the
            --  specification. It is not the only place any more.
            if Home /= "" then
               Add (Home & "/.mozilla/firefox");
               Add (Home & "/snap/firefox/common/.mozilla/firefox");
               Add (Home & "/.var/app/org.mozilla.firefox/.mozilla/firefox");

               --  Where the Flathub Firefox actually puts them. A flatpak
               --  gives the application its own XDG_CONFIG_HOME
               --  (~/.var/app/<id>/config), and Firefox 153 writes profiles
               --  there rather than into the ~/.mozilla the sandbox also
               --  offers it. Checked on this host: profiles.ini and a cert9.db
               --  Firefox itself created sit under config/mozilla/firefox,
               --  and .mozilla/firefox does not exist at all. Guessing which
               --  of the two a build uses is what the earlier list did.
               Add (Home
                    & "/.var/app/org.mozilla.firefox/config/mozilla/firefox");

               --  The same shape for a snap, inferred rather than seen: no
               --  snapd on the host this was found on. Costs a directory that
               --  is not there; missing it costs an anchor installed into
               --  nothing.
               Add (Home & "/snap/firefox/common/.config/mozilla/firefox");
            end if;
      end case;
   end Firefox_Profile_Roots;

   --  The first root this host actually has, for callers that want one name.
   function Firefox_Profile_Root return String is
      Roots : Profile_Root_List;
      Count : Natural;
   begin
      Firefox_Profile_Roots (Roots, Count);
      for Index in 1 .. Count loop
         declare
            Path : constant String :=
              Ada.Strings.Unbounded.To_String (Roots (Index));
         begin
            if Ada.Directories.Exists (Path) then
               return Path;
            end if;
         end;
      end loop;
      return (if Count = 0 then ""
              else Ada.Strings.Unbounded.To_String (Roots (1)));
   end Firefox_Profile_Root;

   procedure Add_Database
     (Databases : in out NSS_Database_List;
      Count     : in out Natural;
      Path      : String) is
   begin
      if Path /= "" and then Count < Max_NSS_Databases
        and then Ada.Directories.Exists (Path)
      then
         Count := Count + 1;
         --  Canonical, so every entry is comparable with every other. A profile
         --  found by enumeration arrives full-named already; leaving the ones
         --  built from environment variables as typed meant two spellings of
         --  the same directory, which only shows up where the separator
         --  differs from the one the caller wrote.
         Databases (Count) :=
           Ada.Strings.Unbounded.To_Unbounded_String
             (Ada.Directories.Full_Name (Path));
      end if;
   end Add_Database;

   procedure Discover_NSS_Databases
     (Databases : out NSS_Database_List;
      Count     : out Natural)
   is
      Roots      : Profile_Root_List;
      Root_Count : Natural;
   begin
      Databases := [others => Ada.Strings.Unbounded.Null_Unbounded_String];
      Count := 0;
      Firefox_Profile_Roots (Roots, Root_Count);

      --  An explicit database is the whole answer: a caller who names one is
      --  pointing at a disposable profile, not asking devcert to go looking.
      if Setting (Set_NSS_Database, NSS_Variable, "TRUSTSTORES_NSS_DB") /= "" then
         Add_Database
           (Databases, Count, Setting (Set_NSS_Database, NSS_Variable, "TRUSTSTORES_NSS_DB"));
         return;
      end if;

      Add_Database (Databases, Count, NSS_Database);

      --  Every root, not the first that exists: a machine can have the
      --  traditional directory and a snap, and each confines Firefox to its
      --  own. Installing into one leaves the other untrusted.
      for Index in 1 .. Root_Count loop
         declare
            Root : constant String :=
              Ada.Strings.Unbounded.To_String (Roots (Index));
         begin
            if Root /= "" and then Ada.Directories.Exists (Root) then
               declare
                  Search : Ada.Directories.Search_Type;
                  Item   : Ada.Directories.Directory_Entry_Type;
               begin
                  Ada.Directories.Start_Search
                    (Search,
                     Directory => Root,
                     Pattern   => "*",
                     Filter    =>
                       [Ada.Directories.Directory     => True,
                        Ada.Directories.Ordinary_File => False,
                        Ada.Directories.Special_File  => False]);
                  while Ada.Directories.More_Entries (Search) loop
                     Ada.Directories.Get_Next_Entry (Search, Item);
                     declare
                        Name : constant String :=
                          Ada.Directories.Simple_Name (Item);
                        Path : constant String :=
                          Ada.Directories.Full_Name (Item);
                     begin
                        --  A profile is a directory holding cert9.db; anything
                        --  else in there is not a database and must not be
                        --  handed to certutil.
                        if Name /= "." and then Name /= ".."
                          and then Ada.Directories.Exists (Path & "/cert9.db")
                        then
                           Add_Database (Databases, Count, Path);
                        end if;
                     end;
                  end loop;
                  Ada.Directories.End_Search (Search);
               exception
                  when others =>
                     null;
               end;
            end if;
         end;
      end loop;
   end Discover_NSS_Databases;

   function NSS_Database_Count return Natural is
      Databases : NSS_Database_List;
      Count     : Natural;
   begin
      Discover_NSS_Databases (Databases, Count);
      return Count;
   end NSS_Database_Count;

   function NSS_Database_Path (Index : Positive) return String is
      Databases : NSS_Database_List;
      Count     : Natural;
   begin
      Discover_NSS_Databases (Databases, Count);
      if Index > Count then
         return "";
      end if;
      return Ada.Strings.Unbounded.To_String (Databases (Index));
   end NSS_Database_Path;

   procedure Apply_NSS
     (Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      Certutil  : constant String := Locate ("certutil");
      Alias     : constant String := Fingerprint_Alias (Fingerprint);
      Databases : NSS_Database_List;
      Found     : Natural;
      Failures  : Natural := 0;
      Combined  : Unbounded_String;

      DB  : Unbounded_String;
      Ran : Boolean := False;

      function Database return String is
        (Ada.Strings.Unbounded.To_String (DB));

      --  Absent and present-but-different are not the same answer: an anchor
      --  missing from one profile is nothing to remove there, while one whose
      --  stored certificate differs is somebody else's and must be left alone.
      function Alias_Present return Boolean is
         Output : Unbounded_String;
         Listed : Boolean := False;
      begin
         Run_Capture
           (Certutil,
            [new String'("-L"),
             new String'("-d"),
             new String'("sql:" & Database),
             new String'("-n"),
             new String'(Alias),
             new String'("-a")],
            Listed,
            Output);
         return Listed;
      end Alias_Present;

      function NSS_Contains_Certificate return Boolean is
         Output : Unbounded_String;
         Listed : Boolean := False;
      begin
         Run_Capture
           (Certutil,
            [new String'("-L"),
             new String'("-d"),
             new String'("sql:" & Database),
             new String'("-n"),
             new String'(Alias),
             new String'("-a")],
            Listed,
            Output);
         return Listed
           and then Same_Certificate
             (Ada.Strings.Unbounded.To_String (Output),
              Read_Text_File (Certificate));
      end NSS_Contains_Certificate;
      procedure Note (Text : String) is
      begin
         if Ada.Strings.Unbounded.Length (Combined) > 0 then
            Ada.Strings.Unbounded.Append (Combined, "; ");
         end if;
         Ada.Strings.Unbounded.Append (Combined, Text);
      end Note;
   begin
      State := Error;
      Discover_NSS_Databases (Databases, Found);

      if Certutil = "" then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("certutil is not installed");
         return;
      elsif Found = 0 then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("NSS database is missing");
         return;
      end if;

      --  Every database the host has: the shared one Chromium reads, and one
      --  per Firefox profile, which reads nothing else.
      for Index in 1 .. Found loop
         DB := Databases (Index);
         Ran := False;

         case Operation is
            when Install =>
               Run
                 (Certutil,
                  [new String'("-A"),
                   new String'("-d"),
                   new String'("sql:" & Database),
                   new String'("-n"),
                   new String'(Alias),
                   new String'("-t"),
                   new String'("C,,"),
                   new String'("-i"),
                   new String'(Certificate)],
                  Ran);
               if Ran and then not NSS_Contains_Certificate then
                  Ran := False;
               end if;
               if not Ran then
                  Failures := Failures + 1;
               end if;
               Note
                 ((if Ran then "installed" else "failed to install")
                  & " NSS trust anchor " & Alias & " in " & Database);

            when Remove =>
               if not Alias_Present then
                  Note ("no NSS trust anchor " & Alias & " in " & Database);
               elsif not NSS_Contains_Certificate then
                  Failures := Failures + 1;
                  Note
                    ("NSS trust anchor fingerprint mismatch in " & Database
                     & "; refusing removal");
               else
                  Run
                    (Certutil,
                     [new String'("-D"),
                      new String'("-d"),
                      new String'("sql:" & Database),
                      new String'("-n"),
                      new String'(Alias)],
                     Ran);
                  if not Ran then
                     Failures := Failures + 1;
                  end if;
                  Note
                    ((if Ran then "removed" else "failed to remove")
                     & " NSS trust anchor " & Alias & " in " & Database);
               end if;
         end case;
      end loop;

      State := (if Failures = 0 then Installed else Error);
      Message := Combined;
   end Apply_NSS;

   procedure Apply_MacOS
     (Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      Security : constant String := Locate ("security");
      Ran      : Boolean := False;
      Status   : Integer := -1;
   begin
      State := Error;
      if Security = "" then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("security is not installed");
         return;
      end if;

      case Operation is
         when Install =>
            Run
              (Security,
               [new String'("add-trusted-cert"),
                new String'("-d"),
                new String'("-r"),
                new String'("trustRoot"),
                new String'("-k"),
                new String'("/Library/Keychains/System.keychain"),
                new String'(Certificate)],
               Ran,
               Status);
         when Remove =>
            Run
              (Security,
               [new String'("delete-certificate"),
                new String'("-Z"),
                new String'(Safe_Fingerprint (Fingerprint)),
                new String'("/Library/Keychains/System.keychain")],
               Ran,
               Status);
      end case;
      --  A denial is not a broken store, and on macOS it is the ordinary case:
      --  the system keychain belongs to root. Reported as an error, the only
      --  thing wrong -- that this has to run under sudo -- was the one thing
      --  the message did not say. The privilege is asked about only once the
      --  attempt has failed: whether a keychain will have us is the keychain's
      --  answer to give, not ours to predict.
      if Ran then
         State := Installed;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("updated macOS trust store");
      elsif not Hostkit.Host.Is_Elevated then
         State := Permission_Required;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("macOS trust store update requires permission for "
              & "/Library/Keychains/System.keychain");
      else
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("failed to update macOS trust store (security exit"
              & Status'Image & ")");
      end if;
   end Apply_MacOS;

   procedure Apply_Windows
     (Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      --  Windows is the one store that will not be told which certificate to
      --  remove in devcert's own terms: it indexes by SHA-1, and that is
      --  computed from the certificate below rather than taken from here.
      pragma Unreferenced (Fingerprint);

      Certutil : constant String := Locate ("certutil");
      Ran      : Boolean := False;
      --  What certutil made of it. The message used to say only that the store
      --  was not updated, which is the least useful half of what was known.
      Status   : Integer := -1;
   begin
      State := Error;
      if Certutil = "" then
         State := Tool_Missing;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("certutil is not installed");
         return;
      end if;

      case Operation is
         when Install =>
            Run
              (Certutil,
               [new String'("-addstore"),
                new String'("Root"),
                new String'(Certificate)],
               Ran,
               Status);
         when Remove =>
            declare
               --  The hash the store indexes by. Handed the SHA-256 devcert
               --  identifies certificates with, certutil exits zero having
               --  deleted nothing -- so uninstall reported a removal that had
               --  not happened, which is the one lie a trust tool must not
               --  tell.
               Hash : constant String :=
                 CryptoLib.Certificates.SHA1_Fingerprint
                   (Read_Text_File (Certificate));
               Listing : Unbounded_String;
               Listed  : Boolean := False;
            begin
               if Hash = "" then
                  State := Error;
                  Message :=
                    Ada.Strings.Unbounded.To_Unbounded_String
                      ("cannot identify the certificate to remove from the "
                       & "Windows trust store");
                  return;
               end if;

               Run
                 (Certutil,
                  [new String'("-delstore"),
                   new String'("Root"),
                   new String'(Hash)],
                  Ran,
                  Status);

               --  And then look, because the exit status has already been
               --  wrong about this once.
               if Ran then
                  Run_Capture
                    (Certutil,
                     [new String'("-store"), new String'("Root")],
                     Listed,
                     Listing);

                  if Listed
                    and then Ada.Strings.Fixed.Index
                               (Ada.Characters.Handling.To_Lower
                                  (Ada.Strings.Unbounded.To_String (Listing)),
                                Hash) /= 0
                  then
                     State := Error;
                     Message :=
                       Ada.Strings.Unbounded.To_Unbounded_String
                         ("certutil reported a removal but the certificate is "
                          & "still in the Windows trust store");
                     return;
                  end if;
               end if;
            end;
      end case;
      --  The machine Root store is the administrator's, the same way the system
      --  keychain is root's; see the note in Apply_MacOS.
      if Ran then
         State := Installed;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String ("updated Windows trust store");
      elsif not Hostkit.Host.Is_Elevated then
         State := Permission_Required;
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("Windows trust store update requires permission for "
              & "the machine Root certificate store");
      else
         Message :=
           Ada.Strings.Unbounded.To_Unbounded_String
             ("failed to update Windows trust store (certutil exit"
              & Status'Image & ")");
      end if;
   end Apply_Windows;

   procedure Apply
     (Target      : Trust_Target;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String) is
   begin
      case Target is
         when Linux =>
            Apply_Linux (Operation, Certificate, Fingerprint, State, Message);
         when NSS =>
            Apply_NSS (Operation, Certificate, Fingerprint, State, Message);
         when Java =>
            Apply_Java (Operation, Certificate, Fingerprint, State, Message);
         when MacOS =>
            Apply_MacOS (Operation, Certificate, Fingerprint, State, Message);
         when Windows =>
            Apply_Windows (Operation, Certificate, Fingerprint, State, Message);
      end case;
   end Apply;

   procedure Apply
     (Selection   : Store_Selection;
      Operation   : Action;
      Certificate : String;
      Fingerprint : String;
      State       : out Trust_State;
      Message     : out Unbounded_String)
   is
      Success_Count : Natural := 0;
      Failure_Count : Natural := 0;
      --  Of the failures, how many were the store asking for privileges. Kept
      --  apart because that is the one failure the caller can act on, and the
      --  aggregate used to flatten it into Error along with everything else.
      Denied_Count  : Natural := 0;
      Combined      : Unbounded_String;
   begin
      Message := Ada.Strings.Unbounded.Null_Unbounded_String;
      if Selection.Count = 0 then
         State := Unsupported;
         Message := Ada.Strings.Unbounded.To_Unbounded_String
           ("no trust stores selected");
         return;
      end if;

      for I in 1 .. Selection.Count loop
         declare
            Kind          : constant Trust_Store_Kind := Selection.Items (I);
            Target        : constant Trust_Target := Target_For (Kind);
            Item_Success  : Boolean := False;
            Item_Message  : Unbounded_String;
            Item_State    : Trust_State;
         begin
            --  Each store says what happened to it. This used to be read back
            --  out of the message the store had just written -- a search for
            --  "requires permission" and "not installed" -- so the exit code a
            --  caller acts on depended on the wording of an English sentence,
            --  and translating one would have turned a denial into a plain
            --  error without anything failing.
            Apply
              (Target, Operation, Certificate, Fingerprint, Item_State,
               Item_Message);
            Item_Success := Item_State = Installed;

            if I > 1 then
               Ada.Strings.Unbounded.Append (Combined, "; ");
            end if;
            --  A removal that worked is reported as removed, not installed.
            --  The state is one success either way, but "uninstall" answering
            --  "system=installed" reads as the opposite of what happened, and
            --  this is a tool people run to be sure a root is gone.
            Ada.Strings.Unbounded.Append
              (Combined,
               Name (Kind)
               & "="
               & (if Operation = Remove and then Item_State = Installed
                  then "removed"
                  else State_Image (Item_State))
               & ": "
               & Ada.Strings.Unbounded.To_String (Item_Message));

            if Item_Success then
               Success_Count := Success_Count + 1;
            else
               Failure_Count := Failure_Count + 1;
               if Item_State = Permission_Required then
                  Denied_Count := Denied_Count + 1;
               end if;
            end if;
         end;
      end loop;

      Message := Combined;
      if Success_Count > 0 and then Failure_Count > 0 then
         State := Partial;
      elsif Success_Count > 0 then
         State := Installed;
      elsif Denied_Count = Failure_Count then
         --  Every store that failed did so for want of privileges, so the whole
         --  operation has one answer and it is actionable.
         State := Permission_Required;
      else
         State := Error;
      end if;
   end Apply;
   ---------------------------------------------------------------------------
   --  Reading
   ---------------------------------------------------------------------------

   --  The bundle a Linux host assembles its anchors into. Distributions do not
   --  agree, and a program that hard-codes one of these finds nothing on the
   --  others -- so they are tried in turn and the first that exists wins.
   function Linux_Anchor_Bundle return String is
      type Path_List is array (Positive range <>) of Unbounded_String;
      Candidates : constant Path_List :=
        [Ada.Strings.Unbounded.To_Unbounded_String
           ("/etc/ssl/certs/ca-certificates.crt"),          --  Debian, Ubuntu
         Ada.Strings.Unbounded.To_Unbounded_String
           ("/etc/pki/tls/certs/ca-bundle.crt"),            --  Fedora, RHEL
         Ada.Strings.Unbounded.To_Unbounded_String
           ("/etc/ssl/ca-bundle.pem"),                      --  SUSE
         Ada.Strings.Unbounded.To_Unbounded_String
           ("/etc/ca-certificates/extracted/tls-ca-bundle.pem"),  --  Arch
         Ada.Strings.Unbounded.To_Unbounded_String
           ("/etc/ssl/cert.pem")];                          --  Alpine, others
   begin
      for Candidate of Candidates loop
         declare
            Path : constant String :=
              Ada.Strings.Unbounded.To_String (Candidate);
         begin
            if Ada.Directories.Exists (Path) then
               return Path;
            end if;
         end;
      end loop;
      return "";
   end Linux_Anchor_Bundle;

   --  The anchors p11-kit holds, asked of p11-kit.
   --
   --  A host with p11-kit and no ca-certificates has no bundle file to read.
   --  That is not an exotic configuration: it is the one where
   --  Detect_Linux_Backend picks Trust_Anchor, so it is exactly the host whose
   --  anchors this library most needs to be able to name. Extraction works
   --  there even though the compat extractor that writes the bundle files is
   --  the missing piece that sent us down this path.
   function P11_Kit_Anchors return String is
      Trust : constant String := Locate ("trust");
      Path  : constant String :=
        Ada.Directories.Compose
          (Hostkit.Fs.Temp_Directory, "truststores-p11-anchors.pem");
      Ran   : Boolean := False;
   begin
      if Trust = "" then
         return "";
      end if;

      Run
        (Trust,
         [new String'("extract"),
          new String'("--format=pem-bundle"),
          new String'("--filter=ca-anchors"),
          --  Named rather than left to p11-kit, which warns on standard error
          --  and then picks this itself. A warning is not an answer.
          new String'("--purpose=server-auth"),
          new String'("--overwrite"),
          new String'(Path)],
         Ran);

      if not Ran or else not Ada.Directories.Exists (Path) then
         return "";
      end if;

      declare
         Text : constant String := Read_Text_File (Path);
      begin
         begin
            Ada.Directories.Delete_File (Path);
         exception
            when others =>
               null;
         end;
         return Text;
      end;
   end P11_Kit_Anchors;

   function System_Anchors return Unbounded_String is
      use type Hostkit.Host.Kind;
      Ran    : Boolean := False;
      Output : Unbounded_String;
   begin
      case Hostkit.Host.Current is
         when Hostkit.Host.Linux =>
            --  Read, not run: the bundle is a file the host maintains, and
            --  reading it needs no tool and no privileges.
            declare
               Bundle : constant String := Linux_Anchor_Bundle;
               Text   : constant String :=
                 (if Bundle = "" then "" else Read_Text_File (Bundle));
            begin
               --  An empty bundle is not an answer, and it is what a host with
               --  p11-kit and no ca-certificates has: Ubuntu ships
               --  /etc/ssl/certs/ca-certificates.crt as a zero-length file and
               --  nothing fills it, because the extractor that would is the
               --  piece that package does not carry. Testing the path rather
               --  than the contents reads that host as trusting nothing at
               --  all. Where there are no bytes, ask p11-kit.
               return Ada.Strings.Unbounded.To_Unbounded_String
                        (if Text = "" then P11_Kit_Anchors else Text);
            end;

         when Hostkit.Host.MacOS =>
            --  The keychain is a database, and security is what reads it. Both
            --  keychains: the roots Apple ships and the ones this machine added.
            declare
               Security : constant String := Locate ("security");
               System_Roots : Unbounded_String;
            begin
               if Security = "" then
                  return Ada.Strings.Unbounded.Null_Unbounded_String;
               end if;

               Run_Capture
                 (Security,
                  [new String'("find-certificate"),
                   new String'("-a"),
                   new String'("-p"),
                   new String'
                     ("/System/Library/Keychains/SystemRootCertificates.keychain")],
                  Ran,
                  System_Roots);
               Run_Capture
                 (Security,
                  [new String'("find-certificate"),
                   new String'("-a"),
                   new String'("-p"),
                   new String'("/Library/Keychains/System.keychain")],
                  Ran,
                  Output);
               return Ada.Strings.Unbounded."&" (System_Roots, Output);
            end;

         when Hostkit.Host.Windows =>
            --  certutil describes certificates rather than exporting them, and
            --  there is no switch that dumps the store as PEM. PowerShell can
            --  hand back the bytes, which is what this asks it for.
            declare
               Shell : constant String := Locate ("powershell");
            begin
               if Shell = "" then
                  return Ada.Strings.Unbounded.Null_Unbounded_String;
               end if;

               Run_Capture
                 (Shell,
                  [new String'("-NoProfile"),
                   new String'("-Command"),
                   new String'
                     ("Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object { "
                      & "'-----BEGIN CERTIFICATE-----'; "
                      & "[Convert]::ToBase64String($_.RawData, "
                      & "'InsertLineBreaks'); "
                      & "'-----END CERTIFICATE-----' }")],
                  Ran,
                  Output);
               return Output;
            end;

         when others =>
            return Ada.Strings.Unbounded.Null_Unbounded_String;
      end case;
   exception
      when others =>
         return Ada.Strings.Unbounded.Null_Unbounded_String;
   end System_Anchors;

   --  Whether a PEM text holds this certificate, one armoured block at a time.
   --  Comparing the whole text would answer about the first block and nothing
   --  after it.
   function Text_Holds
     (Anchors : String; Certificate_PEM : String) return Boolean
   is
      Mark  : constant String := "-----END CERTIFICATE-----";
      From  : Positive := Anchors'First;
      Start : Positive := Anchors'First;
   begin
      if Anchors = "" or else Certificate_PEM = "" then
         return False;
      end if;

      loop
         declare
            Stop : constant Natural :=
              Ada.Strings.Fixed.Index (Anchors (From .. Anchors'Last), Mark);
         begin
            exit when Stop = 0;
            if Same_Certificate
                 (Anchors (Start .. Stop + Mark'Length - 1), Certificate_PEM)
            then
               return True;
            end if;
            exit when Stop + Mark'Length >= Anchors'Last;
            From := Stop + Mark'Length;
            Start := From;
         end;
      end loop;
      return False;
   end Text_Holds;

   function NSS_Anchors return Unbounded_String is
      Certutil  : constant String := Locate ("certutil");
      Databases : NSS_Database_List;
      Count     : Natural;
      Result    : Unbounded_String;
      Ran       : Boolean := False;
   begin
      if Certutil = "" then
         return Ada.Strings.Unbounded.Null_Unbounded_String;
      end if;

      Discover_NSS_Databases (Databases, Count);

      for Index in 1 .. Count loop
         declare
            Database : constant String :=
              Ada.Strings.Unbounded.To_String (Databases (Index));
            Listing  : Unbounded_String;
         begin
            --  The nicknames first: certutil exports by name, and there is no
            --  switch that dumps a database whole.
            Run_Capture
              (Certutil,
               [new String'("-L"),
                new String'("-d"),
                new String'("sql:" & Database)],
               Ran,
               Listing);

            if Ran then
               declare
                  Text : constant String :=
                    Ada.Strings.Unbounded.To_String (Listing);
                  From : Positive := Text'First;
               begin
                  while From <= Text'Last loop
                     declare
                        Stop : constant Natural :=
                          Ada.Strings.Fixed.Index
                            (Text (From .. Text'Last), "" & ASCII.LF);
                        Line : constant String :=
                          (if Stop = 0 then Text (From .. Text'Last)
                           else Text (From .. Stop - 1));
                        --  Each row is "nickname <trust,flags>", and neither
                        --  end is fixed: a nickname carries spaces and commas
                        --  of its own -- "... - Mozilla Corporation" -- and the
                        --  flags may be separated by one space and followed by
                        --  several. So: drop the trailing spaces, take the last
                        --  token as the flags, and accept it only if it looks
                        --  like flags. That rejects the header and the
                        --  SSL,S/MIME,JAR/XPI legend beneath it, which an
                        --  earlier reading turned into a certificate called SSL
                        --  and asked certutil for by name.
                        Body_Text : constant String :=
                          Ada.Strings.Fixed.Trim (Line, Ada.Strings.Right);
                        Break : constant Natural :=
                          (if Body_Text = "" then 0
                           else Ada.Strings.Fixed.Index
                                  (Body_Text, " ", Ada.Strings.Backward));

                        function Looks_Like_Flags (Value : String) return Boolean is
                        begin
                           if Value = ""
                             or else Value'Length > 12
                             or else Ada.Strings.Fixed.Index (Value, ",") = 0
                           then
                              return False;
                           end if;
                           for Item of Value loop
                              if Item /= ','
                                and then Item not in 'a' .. 'z'
                                and then Item not in 'A' .. 'Z'
                              then
                                 return False;
                              end if;
                           end loop;
                           return True;
                        end Looks_Like_Flags;
                     begin
                        if Break > Body_Text'First then
                           declare
                              Nickname : constant String :=
                                Ada.Strings.Fixed.Trim
                                  (Body_Text (Body_Text'First .. Break - 1),
                                   Ada.Strings.Both);
                              Flags : constant String :=
                                Body_Text (Break + 1 .. Body_Text'Last);
                              Exported : Unbounded_String;
                              Got      : Boolean := False;
                           begin
                              if Nickname /= ""
                                and then Looks_Like_Flags (Flags)
                                and then Ada.Strings.Fixed.Index
                                           (Nickname, "Certificate Nickname") = 0
                              then
                                 Run_Capture
                                   (Certutil,
                                    [new String'("-L"),
                                     new String'("-d"),
                                     new String'("sql:" & Database),
                                     new String'("-n"),
                                     new String'(Nickname),
                                     new String'("-a")],
                                    Got,
                                    Exported);
                                 if Got then
                                    Ada.Strings.Unbounded.Append
                                      (Result, Exported);
                                 end if;
                              end if;
                           end;
                        end if;

                        exit when Stop = 0;
                        From := Stop + 1;
                     end;
                  end loop;
               end;
            end if;
         end;
      end loop;

      return Result;
   exception
      when others =>
         return Ada.Strings.Unbounded.Null_Unbounded_String;
   end NSS_Anchors;

   function Java_Anchors return Unbounded_String is
      Keytool   : constant String := Locate ("keytool");
      Keystores : Java_Keystore_List;
      Count     : Natural;
      Result    : Unbounded_String;
   begin
      if Keytool = "" then
         return Ada.Strings.Unbounded.Null_Unbounded_String;
      end if;

      Java_Keystores (Keystores, Count);

      --  Every keystore, because "does this host trust it" is a question about
      --  the host and not about whichever JDK is first on PATH.
      for Index in 1 .. Count loop
         declare
            Keystore : constant String :=
              Ada.Strings.Unbounded.To_String (Keystores (Index));
            Output   : Unbounded_String;
            Ran      : Boolean := False;
         begin
            --  keytool dumps a keystore whole, which certutil will not: one
            --  spawn each rather than one per anchor.
            Run_Capture
              (Keytool,
               [new String'("-list"),
                new String'("-rfc"),
                new String'("-keystore"),
                new String'(Keystore),
                new String'("-storepass"),
                new String'("changeit")],
               Ran,
               Output);
            if Ran then
               Ada.Strings.Unbounded.Append (Result, Output);
            end if;
         end;
      end loop;

      return Result;
   exception
      when others =>
         return Ada.Strings.Unbounded.Null_Unbounded_String;
   end Java_Anchors;

   function NSS_Trusts (Certificate_PEM : String) return Boolean is
   begin
      return Text_Holds
        (Ada.Strings.Unbounded.To_String (NSS_Anchors), Certificate_PEM);
   end NSS_Trusts;

   function Java_Trusts (Certificate_PEM : String) return Boolean is
   begin
      return Text_Holds
        (Ada.Strings.Unbounded.To_String (Java_Anchors), Certificate_PEM);
   end Java_Trusts;

   function System_Anchor_Count return Natural is
      Text  : constant String :=
        Ada.Strings.Unbounded.To_String (System_Anchors);
      Mark  : constant String := "-----BEGIN CERTIFICATE-----";
      Count : Natural := 0;
      From  : Positive := Text'First;
   begin
      if Text = "" then
         return 0;
      end if;

      loop
         declare
            Found : constant Natural :=
              Ada.Strings.Fixed.Index (Text (From .. Text'Last), Mark);
         begin
            exit when Found = 0;
            Count := Count + 1;
            exit when Found + Mark'Length > Text'Last;
            From := Found + Mark'Length;
         end;
      end loop;
      return Count;
   end System_Anchor_Count;

   function System_Trusts (Certificate_PEM : String) return Boolean is
   begin
      return Text_Holds
        (Ada.Strings.Unbounded.To_String (System_Anchors), Certificate_PEM);
   end System_Trusts;

end Truststores;
