using System.Text.Json;
using OTS.Firewall79X.Core;

var results=new List<object>();int failed=0;
void Test(string name,Action action){try{action();Console.WriteLine("PASS "+name);results.Add(new{name,status="PASS"});}catch(Exception e){failed++;Console.WriteLine("FAIL "+name+": "+e.Message);results.Add(new{name,status="FAIL",error=e.Message});}}
void Assert(bool b,string message="Assertion failed"){if(!b)throw new Exception(message);}
void Throws<T>(Action a)where T:Exception{try{a();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
string Temp()=>Path.Combine(Path.GetTempPath(),"OTS-tests-"+Guid.NewGuid().ToString("N"),"journal.json");

Test("Section E optional RDP restrictions require strong nonexistent-user evidence",()=>{
    var monitor=new AuthenticationFailureMonitor();var now=DateTimeOffset.UtcNow;
    AuthenticationFailureMonitor.Finding finding=new(false,false,0,"","");
    for(int i=0;i<31;i++)
        finding=monitor.Observe("8.8.8.8","10",now.AddSeconds(i),"0xC0000064","absent"+(i%5));
    Assert(!finding.RestrictionCandidate,"31 is below the block threshold");
    finding=monitor.Observe("8.8.8.8","10",now.AddSeconds(31),"0xC0000064","absent0");
    Assert(finding.RestrictionCandidate,"32 missing-user attempts across five identities must qualify");
    Assert(!finding.Alert,"32-failure restriction can occur during 8-failure alert cooldown; handler must evaluate separately");
    Assert(!monitor.Observe("8.8.8.8","10",now.AddSeconds(32),"0xC0000064","absent1").RestrictionCandidate,"Cooldown must reject immediate repeat");
    var validAccount=new AuthenticationFailureMonitor();
    for(int i=0;i<60;i++)finding=validAccount.Observe("1.1.1.1","10",now.AddSeconds(i),"0xC000006A","realuser");
    Assert(!finding.RestrictionCandidate,"Bad passwords for an existing user must never cause a source block");
    var networkLogon=new AuthenticationFailureMonitor();
    for(int i=0;i<60;i++)finding=networkLogon.Observe("9.9.9.9","3",now.AddSeconds(i),"0xC0000064","absent"+i);
    Assert(!finding.RestrictionCandidate,"SMB/network logon type 3 must not create an RDP restriction");
    var sameName=new AuthenticationFailureMonitor();
    for(int i=0;i<60;i++)finding=sameName.Observe("8.8.4.4","10",now.AddSeconds(i),"0xC0000064","absent");
    Assert(!finding.RestrictionCandidate,"One typo'd username must never trigger the guard");
});
Test("Section E local identity policy recognizes weaknesses without changing settings",()=>{
    Assert(IdentityPasswordPolicy.Assess(8,0,uint.MaxValue,0).Risks.Count==4);
    Assert(IdentityPasswordPolicy.Assess(14,10,90u*24u*3600u,10).Risks.Count==0);
    Assert(IdentityPasswordPolicy.Assess(12,5,30u*24u*3600u,1).Risks.Count==0);
});
Test("OTS RDP rule ownership rejects spoofed or broadened rules",()=>{
    var addr="8.8.8.8";
    var name=OwnedFirewallRule.AuthenticationPrefix+addr;
    Assert(OwnedFirewallRule.HasReservedName(name));
    Assert(OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,1,0,6,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,1,0,6,int.MaxValue,true,"3388"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,1,0,6,int.MaxValue,true,"0-65535"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,1,0,256,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(name,"spoofed",addr,1,0,6,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,"8.8.4.4",1,0,6,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,2,0,6,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(name,OwnedFirewallRule.AuthenticationDescription,addr,1,1,6,int.MaxValue,true,"3389"));
    Assert(!OwnedFirewallRule.Matches(OwnedFirewallRule.AuthenticationPrefix+"192.168.1.2",OwnedFirewallRule.AuthenticationDescription,"192.168.1.2",1,0,6,int.MaxValue,true,"3389"));
});
Test("Catalog contains exactly 79 unique ordered requirements",()=>Assert(Catalog.All.Select(l=>l.Id).SequenceEqual(Enumerable.Range(1,79))));
Test("OFF score is zero regardless of reported layers",()=>Assert(Posture.Calculate([new(1,LayerMode.Enforcing,true,"test")],false).Score==0));
Test("Unavailable core layers reduce score",()=>Assert(Posture.Calculate([new(1,LayerMode.Unavailable,false,"missing"),new(2,LayerMode.Monitoring,true,"observed")],true).Score==25));
Test("Idle layers cannot inflate score",()=>Assert(Posture.Calculate([new(1,LayerMode.Idle,true,"not started")],true).Score==0));
Test("Not-applicable layers excluded without free points",()=>Assert(Posture.Calculate([new(1,LayerMode.NotApplicable,false,"none")],true).Score==0));
Test("Journal restores exact original value",()=>{var s=new FakeStore("original");var j=new ChangeJournal(Temp(),s);j.Apply("setting","ours");Assert(s.Value=="ours");Assert(j.Restore().Count==0&&s.Value=="original");});
Test("Journal preserves newer external changes",()=>{var s=new FakeStore("original");var j=new ChangeJournal(Temp(),s);j.Apply("setting","ours");s.Value="third-party";Assert(j.Restore().SequenceEqual(new[]{"setting"}));Assert(s.Value=="third-party");});
Test("Journal records durable intent before failed write",()=>{var p=Temp();var s=new FakeStore("old"){Fail=true};var j=new ChangeJournal(p,s);Throws<IOException>(()=>j.Apply("setting","new"));Assert(File.ReadAllText(p).Contains("prepared"));s.Fail=false;Assert(new ChangeJournal(p,s).Restore().Count==0&&s.Value=="old");});
Test("Journal recovers crash after write before commit",()=>{var p=Temp();Directory.CreateDirectory(Path.GetDirectoryName(p)!);File.WriteAllText(p,JsonSerializer.Serialize(new[]{new Change("setting","old","new","prepared")},Wire.Json));var s=new FakeStore("new");new ChangeJournal(p,s).Restore();Assert(s.Value=="old");});
Test("Journal restore is idempotent",()=>{var s=new FakeStore(null);var j=new ChangeJournal(Temp(),s);j.Apply("setting","new");j.Restore();j.Restore();Assert(s.Value==null);});
Test("Invalid journal rejected",()=>{var p=Temp();Directory.CreateDirectory(Path.GetDirectoryName(p)!);File.WriteAllText(p,"{corrupt}");Throws<JsonException>(()=>new ChangeJournal(p,new FakeStore(null)));});
Test("Duplicate owned setting rejected",()=>{var j=new ChangeJournal(Temp(),new FakeStore("old"));j.Apply("setting","new");Throws<InvalidOperationException>(()=>j.Apply("setting","newer"));});
Test("Status is the only nonadministrative command",()=>Assert(Wire.Commands.Where(c=>!Wire.RequiresAdmin(c)).SequenceEqual(new[]{"status"})));
Test("Oversize frame rejected before allocation",()=>{using var m=new MemoryStream(BitConverter.GetBytes(int.MaxValue));Throws<InvalidDataException>(()=>Wire.ReadAsync<Request>(m,1024,default).GetAwaiter().GetResult());});
Test("Truncated frame rejected",()=>{using var m=new MemoryStream([8,0,0,0,1]);Throws<EndOfStreamException>(()=>Wire.ReadAsync<Request>(m,1024,default).GetAwaiter().GetResult());});
Test("Framing round trip",()=>{using var m=new MemoryStream();Wire.WriteAsync(m,new Request("status"),default).GetAwaiter().GetResult();m.Position=0;Assert(Wire.ReadAsync<Request>(m,1024,default).GetAwaiter().GetResult().Command=="status");});
Test("Deterministic malformed-frame corpus",()=>{var rng=new Random(79);for(int i=0;i<1000;i++){var b=new byte[rng.Next(0,80)];rng.NextBytes(b);using var m=new MemoryStream(b);try{Wire.ReadAsync<Request>(m,1024,default).GetAwaiter().GetResult();throw new Exception("Unexpected valid random frame");}catch(Exception ex)when(ex is InvalidDataException or EndOfStreamException or JsonException){}}});
Test("Text sanitization bounds hostile log values",()=>Assert(Wire.Clean("a\0\n\r"+new string('x',5000),20).Length==20&&!Wire.Clean("a\0").Contains('\0')));
Test("Private addresses cannot qualify for public-IP bans",()=>{foreach(var ip in new[]{"127.0.0.1","10.0.0.1","172.16.0.1","192.168.1.1","169.254.1.1","::1","fc00::1","fe80::1","::ffff:192.168.1.1","100.64.0.1"})Assert(!Detections.IsPublicAddress(ip),ip);});
Test("Port scan requires diverse ports",()=>{Assert(!Detections.Scan(Enumerable.Repeat(443,200)));Assert(Detections.Scan(Enumerable.Range(1,12)));});
Test("Beacon regularity requires enough observations",()=>{var now=DateTimeOffset.UtcNow;Assert(!Detections.IsBeacon([now,now.AddMinutes(1)]));Assert(Detections.IsBeacon(Enumerable.Range(0,10).Select(i=>now.AddMinutes(i)).ToArray()));Assert(!Detections.IsBeacon(Enumerable.Range(0,10).Select(i=>now.AddMinutes(i*i)).ToArray()));});
Test("File burst ignores older events",()=>{var now=DateTimeOffset.UtcNow;Assert(!Detections.FileBurst(Enumerable.Repeat(now.AddMinutes(-1),100),now));Assert(Detections.FileBurst(Enumerable.Repeat(now,40),now));});
Test("Execution detector does not flag ordinary shell invocation",()=>{Assert(Detections.ExecutionIndicator("powershell.exe","Get-Date")==null);Assert(Detections.ExecutionIndicator("powershell.exe","-EncodedCommand AAAA")!=null);});
Test("Secrets scanner categorizes without retaining raw secret",()=>{
    var token="ghp_"+new string('A',36);
    var aws="AKIA"+new string('A',16);
    var detected=Detections.SecretKinds("token="+token+"\nAWS="+aws+"\n-----BEGIN OPENSSH PRIVATE KEY-----");
    Assert(detected.Count>=3&&detected.Any(x=>x.Contains("GitHub"))&&detected.Any(x=>x.Contains("AWS"))&&detected.Contains("Private key"));
    Assert(!string.Join("|",detected).Contains(token)&&!string.Join("|",detected).Contains(aws));
});
Test("Secrets scanner rejects binary data and misleading placeholders",()=>{
    Assert(Detections.SecretKinds("binary\0ghp_"+new string('A',36)).Count==0);
    Assert(Detections.SecretKinds("password=REDACTED\nclient_secret=example").Count==0);
    Throws<ArgumentOutOfRangeException>(()=>Detections.SecretKinds(new string('x',1024*1024+1)));
});
Test("Four-setting journal restores unchanged settings and preserves later edits",()=>{
    var values=new Dictionary<string,string?>{{"autorun","0"},{"command",null},{"autoplay","0"},{"smartscreen",null}};
    var store=new DictionaryStore(values);var j=new ChangeJournal(Temp(),store);
    j.Apply("autorun","255");j.Apply("command","1");j.Apply("autoplay","1");j.Apply("smartscreen","1");
    values["autoplay"]="third-party";
    Assert(j.Restore().SequenceEqual(new[]{"autoplay"}));
    Assert(values["autorun"]=="0"&&values["command"]==null&&values["autoplay"]=="third-party"&&values["smartscreen"]==null);
});
Test("Browser manifest flags high impact debugger, wildcard and proxy permissions",()=>{
    using var debugger=JsonDocument.Parse("{\"permissions\":[\"debugger\"]}");
    using var proxy=JsonDocument.Parse("{\"optional_permissions\":[\"proxy\"]}");
    using var hosts=JsonDocument.Parse("{\"host_permissions\":[\"<all_urls>\"]}");
    Assert(Detections.BrowserManifestHasHighImpactPermissions(debugger.RootElement));
    Assert(Detections.BrowserManifestHasHighImpactPermissions(proxy.RootElement));
    Assert(Detections.BrowserManifestHasHighImpactPermissions(hosts.RootElement));
});
Test("Browser manifest avoids false malware verdict on ordinary permissions",()=>{
    using var ordinary=JsonDocument.Parse("{\"permissions\":[\"storage\",\"alarms\"],\"host_permissions\":[\"https://example.com/*\"]}");
    using var wrongType=JsonDocument.Parse("{\"permissions\":\"debugger\"}");
    using var array=JsonDocument.Parse("[\"debugger\"]");
    Assert(!Detections.BrowserManifestHasHighImpactPermissions(ordinary.RootElement));
    Assert(!Detections.BrowserManifestHasHighImpactPermissions(wrongType.RootElement));
    Assert(!Detections.BrowserManifestHasHighImpactPermissions(array.RootElement));
});
Test("NuGet lockfile produces exact validated versions, deduplicated across target frameworks",()=>{
    const string json="""{"version":1,"dependencies":{"net10.0":{"Example.Package":{"type":"Direct","resolved":"1.2.3"},"Other.Lib":{"type":"Transitive","resolved":"4.5.6-beta.2"}},"net10.0-windows":{"Example.Package":{"type":"Direct","resolved":"1.2.3"}}}}""";
    var packages=NuGetLockParser.Parse(json);
    Assert(packages.Count==2);
    Assert(packages.Any(p=>p.Name=="Example.Package"&&p.Version=="1.2.3"));
    Assert(packages.Any(p=>p.Name=="Other.Lib"&&p.Version=="4.5.6-beta.2"));
});
Test("NuGet lockfile refuses malformed, unversioned or invalid package identifiers",()=>{
    Throws<InvalidDataException>(()=>NuGetLockParser.Parse("{}"));
    Throws<InvalidDataException>(()=>NuGetLockParser.Parse("""{"dependencies":{"net10.0":{"Library":{"type":"Project"}}}}"""));
    Throws<InvalidDataException>(()=>NuGetLockParser.Parse("""{"dependencies":{"net10.0":{"bad/package":{"resolved":"1.2.3"}}}}"""));
    Throws<InvalidDataException>(()=>NuGetLockParser.Parse("""{"dependencies":{"net10.0":{"name":{"resolved":"../secret"}}}}"""));
    Throws<InvalidDataException>(()=>NuGetLockParser.Parse(new string('a',1024*1024+1)));
});
Test("OSV batch parser correctly attributes exact NuGet package advisory IDs",()=>{
    NuGetLockParser.Package[] packages=[new("Package.A","1.2.3"),new("Package.B","2.0.0")];
    var parsed=OsvBatchValidator.Parse("""{"results":[{"vulns":[{"id":"GHSA-abcd-1234-5678"},{"id":"CVE-2025-12345"}]},{}]}""",packages);
    Assert(parsed.Queried==2&&parsed.PackagesAffected==1&&parsed.AdvisoryCount==2&&parsed.Complete);
    Assert(parsed.Findings.Single().Name=="Package.A");
});
Test("OSV parser refuses mismatched, malformed or unbounded untrusted results",()=>{
    NuGetLockParser.Package[] packages=[new("Package.A","1.2.3")];
    Throws<InvalidDataException>(()=>OsvBatchValidator.Parse("""{"results":[]}""",packages));
    Throws<InvalidDataException>(()=>OsvBatchValidator.Parse("""{"results":[{"vulns":"not an array"}]}""",packages));
    Throws<InvalidDataException>(()=>OsvBatchValidator.Parse("""{"results":[{"vulns":[{"id":"../../bad"}]}]}""",packages));
    Throws<InvalidDataException>(()=>OsvBatchValidator.Parse(new string('x',1024*1024+1),packages));
});
Test("OSV result pagination is incomplete, never certified as fully checked",()=>{
    NuGetLockParser.Package[] packages=[new("Package.A","1.2.3")];
    var parsed=OsvBatchValidator.Parse("""{"results":[{"next_page_token":"future","vulns":[]}]}""",packages);
    Assert(!parsed.Complete&&parsed.Findings.Single().NeedsAnotherPage&&parsed.AdvisoryCount==0);
});
Test("OSV continuation is assigned to its original query subset",()=>{
    NuGetLockParser.Package[] packages=[new("First","1.0"),new("Second","2.0"),new("Third","3.0")];
    var first=OsvBatchValidator.ParsePage("""
        {"results":[
            {"vulns":[{"id":"GHSA-one"}],"next_page_token":"next-first"},
            {"vulns":[{"id":"CVE-2026-1234"}]},
            {"next_page_token":"next-third"}]}
        """,3);
    Assert(first.Results[0].NextPageToken=="next-first");
    Assert(first.Results[1].NextPageToken==null);
    Assert(first.Results[2].NextPageToken=="next-third");
    var followup=OsvBatchValidator.ParsePage("""
        {"results":[
            {"vulns":[{"id":"GHSA-two"},{"id":"GHSA-one"}]},
            {"vulns":[{"id":"GHSA-third"}]}]}
        """,2);
    Assert(followup.Results[0].AdvisoryIds.Count==2);
    Assert(followup.Results[1].AdvisoryIds.Single()=="GHSA-third");
    Assert(followup.Results.All(x=>x.NextPageToken==null));
    Assert(packages.Length==3);
});
Test("OSV strict pagination parsing rejects malicious tokens and response types",()=>{
    Throws<InvalidDataException>(()=>OsvBatchValidator.ParsePage("""{"results":[{"next_page_token":5}]}""",1));
    Throws<InvalidDataException>(()=>OsvBatchValidator.ParsePage("""{"results":[{"next_page_token":"line\\nbreak"}]}""",1));
    Throws<InvalidDataException>(()=>OsvBatchValidator.ParsePage("""{"results":[{"next_page_token":"t"}]}""",2));
    Throws<InvalidDataException>(()=>OsvBatchValidator.ParsePage("""{"results":[{"vulns":null}]}""",1));
    Throws<InvalidDataException>(()=>OsvBatchValidator.ParsePage("""{"results":[{"vulns":[{"id":"../escape"}]}]}""",1));
});
Test("Secrets scanner emits indicator type only",()=>{Assert(Detections.SecretKind("ordinary text")==null);Assert(Detections.SecretKind("-----BEGIN PRIVATE KEY-----\nsecret") == "Private key");});
Test("Report includes all layers and literal limitations",()=>{var layers=Catalog.All.Select(l=>new LayerResult(l.Id,LayerMode.Unavailable,false,"Not implemented","A | B")).ToList();var d=new Dashboard(false,"Not Protected",0,0,DateTimeOffset.UtcNow,null,layers,[],[],0,0,0,null,"none");var report=Reports.Generate(d);Assert(report.Contains("| 79 |")&&report.Contains("A \\| B"));});
Test("Encrypted archive roundtrip and wrong-password rejection",()=>{var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);SecureArchive.Encrypt(path,"private report"u8.ToArray(),"twelve-chars-or-more");Assert(SecureArchive.Decrypt(path,"twelve-chars-or-more").AsSpan().SequenceEqual("private report"u8));Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(()=>SecureArchive.Decrypt(path,"wrong-password-here"));});
Test("Encrypted archive preserves caller bytes and rejects oversized or truncated files",()=>{
    var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    byte[] source=System.Text.Encoding.UTF8.GetBytes("sensitive archive evidence");
    var expected=(byte[])source.Clone();
    SecureArchive.Encrypt(path,source,"twelve-chars-or-more");
    Assert(source.AsSpan().SequenceEqual(expected),"Archive encryption unexpectedly mutated caller-owned bytes");
    var roundtrip=SecureArchive.Decrypt(path,"twelve-chars-or-more");
    Assert(roundtrip.AsSpan().SequenceEqual(expected));
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(roundtrip);
    var original=File.ReadAllBytes(path);
    File.WriteAllBytes(path,original.AsSpan(0,40).ToArray());
    Throws<InvalidDataException>(()=>SecureArchive.Decrypt(path,"twelve-chars-or-more"));
});
Test("Encrypted archive rejects modified ciphertext",()=>{var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);SecureArchive.Encrypt(path,"private report"u8.ToArray(),"twelve-chars-or-more");var bytes=File.ReadAllBytes(path);bytes[^1]^=1;File.WriteAllBytes(path,bytes);Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(()=>SecureArchive.Decrypt(path,"twelve-chars-or-more"));});
Test("Encrypted archive rejects short password and invalid format",()=>{Throws<ArgumentException>(()=>SecureArchive.Encrypt(Temp(),[1],"short"));var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllText(path,"bad");Throws<InvalidDataException>(()=>SecureArchive.Decrypt(path,"twelve-chars-or-more"));});
Test("Folder backup roundtrip preserves files without overwriting",()=>{var parent=Path.GetDirectoryName(Temp())!;var source=Path.Combine(parent,"source");Directory.CreateDirectory(Path.Combine(source,"nested"));File.WriteAllText(Path.Combine(source,"nested","file.txt"),"test content");var archive=Path.Combine(parent,"backup.otsfolder");var summary=FolderBackup.Create(source,archive,"twelve-chars-or-more");Assert(summary.Files==1);var target=Path.Combine(parent,"restored");FolderBackup.Restore(archive,target,"twelve-chars-or-more");Assert(File.ReadAllText(Path.Combine(target,"nested","file.txt"))=="test content");Throws<IOException>(()=>FolderBackup.Restore(archive,target,"twelve-chars-or-more"));Throws<IOException>(()=>FolderBackup.Create(source,archive,"twelve-chars-or-more"));});
Test("Encrypted folder backup preserves empty nested directories and remains non-overwriting",()=>{
    var root=Path.GetDirectoryName(Temp())!;
    var src=Path.Combine(root,"selected");Directory.CreateDirectory(src);
    Directory.CreateDirectory(Path.Combine(src,"empty","deep"));
    Directory.CreateDirectory(Path.Combine(src,"has-file"));
    File.WriteAllText(Path.Combine(src,"has-file","document.txt"),"content preserved");
    var archive=Path.Combine(root,"folder.otsfolder");
    var summary=FolderBackup.Create(src,archive,"twelve-chars-or-more");
    Assert(summary.Files==1);
    Assert(FolderBackup.Verify(archive,"twelve-chars-or-more").Files==1);
    var restore=Path.Combine(root,"restored");
    FolderBackup.Restore(archive,restore,"twelve-chars-or-more");
    Assert(Directory.Exists(Path.Combine(restore,"empty","deep")),"Empty nested directory was not restored");
    Assert(File.ReadAllText(Path.Combine(restore,"has-file","document.txt"))=="content preserved");
    Throws<IOException>(()=>FolderBackup.Restore(archive,restore,"twelve-chars-or-more"));
});
Test("Legacy file-only encrypted backup restores with the expanded directory schema",()=>{
    var root=Path.GetDirectoryName(Temp())!;
    Directory.CreateDirectory(root);
    var data=System.Text.Encoding.UTF8.GetBytes("legacy archive contents");
    byte[] zipBytes;
    using(var buffer=new MemoryStream())
    {
        using(var zip=new System.IO.Compression.ZipArchive(buffer,System.IO.Compression.ZipArchiveMode.Create,true))
        {
            using(var file=zip.CreateEntry("files/legacy.txt").Open())file.Write(data);
            var manifestData=JsonSerializer.Serialize(new[]{
                new {Path="legacy.txt",Length=(long)data.Length,
                    Sha256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)),
                    LastWriteUtcTicks=(long?)null}});
            using(var writer=new StreamWriter(zip.CreateEntry("manifest.json").Open()))
                writer.Write(manifestData);
        }
        zipBytes=buffer.ToArray();
    }
    var archive=Path.Combine(root,"legacy.otsfolder");
    SecureArchive.Encrypt(archive,zipBytes,"twelve-chars-or-more");
    var restored=Path.Combine(root,"legacy-restored");
    var summary=FolderBackup.Restore(archive,restored,"twelve-chars-or-more");
    Assert(summary.Files==1&&summary.Bytes==data.Length);
    Assert(File.ReadAllText(Path.Combine(restored,"legacy.txt"))=="legacy archive contents");
});
Test("Encrypted backup directory markers reject path traversal",()=>{
    var root=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(root);
    byte[] zipBytes;
    using(var buffer=new MemoryStream())
    {
        using(var zip=new System.IO.Compression.ZipArchive(buffer,System.IO.Compression.ZipArchiveMode.Create,true))
        {
            zip.CreateEntry("directories/../escape/");
            var digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>()));
            var manifestData=JsonSerializer.Serialize(new[]{
                new {Path="../escape",Length=0L,Sha256=digest,
                    LastWriteUtcTicks=(long?)null,IsDirectory=true}});
            using(var writer=new StreamWriter(zip.CreateEntry("manifest.json").Open()))
                writer.Write(manifestData);
        }
        zipBytes=buffer.ToArray();
    }
    var archive=Path.Combine(root,"hostile.otsfolder");
    SecureArchive.Encrypt(archive,zipBytes,"twelve-chars-or-more");
    Throws<InvalidDataException>(()=>FolderBackup.Verify(archive,"twelve-chars-or-more"));
});
Test("Folder backup rejects destination inside source",()=>{var source=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(source);Throws<IOException>(()=>FolderBackup.Create(source,Path.Combine(source,"self.otsfolder"),"twelve-chars-or-more"));});
Test("Folder backup rejects path traversal before writing outside restore",()=>{var parent=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(parent);using var bytes=new MemoryStream();using(var zip=new System.IO.Compression.ZipArchive(bytes,System.IO.Compression.ZipArchiveMode.Create,true)){using(var writer=new StreamWriter(zip.CreateEntry("manifest.json").Open()))writer.Write("[{\"Path\":\"../outside.txt\",\"Length\":0,\"Sha256\":\"x\"}]");zip.CreateEntry("files/../outside.txt");}var archive=Path.Combine(parent,"bad.otsfolder");SecureArchive.Encrypt(archive,bytes.ToArray(),"twelve-chars-or-more");Throws<InvalidDataException>(()=>FolderBackup.Restore(archive,Path.Combine(parent,"restored"),"twelve-chars-or-more"));Assert(!File.Exists(Path.Combine(parent,"outside.txt")));Assert(!Directory.Exists(Path.Combine(parent,"restored")));});
Test("Repeated protection cycles retain bounded recoverable journal",()=>{var path=Temp();var store=new FakeStore("original");var journal=new ChangeJournal(path,store);for(int i=0;i<300;i++){journal.Apply("setting","ours");journal.Restore();}Assert(journal.Entries.Count<=256);var reopened=new ChangeJournal(path,store);reopened.Apply("setting","ours");reopened.Restore();Assert(store.Value=="original");});
Test("Unknown transaction states are rejected",()=>{var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllText(path,JsonSerializer.Serialize(new[]{new Change("setting","old","ours","invented")},Wire.Json));Throws<InvalidDataException>(()=>new ChangeJournal(path,new FakeStore("ours")));});
Test("Stored event integrity authenticates entries and survives linked restarts",()=>{
    var key=System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    var previous=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    var lines=new List<string>();
    foreach(var data in new[]{"alpha","beta","gamma"})
    {
        var digest=Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(key,System.Text.Encoding.UTF8.GetBytes(previous+data)));
        lines.Add(JsonSerializer.Serialize(new EventIntegrity.Record(previous,data,digest),Wire.Json));previous=digest;
    }
    var ok=EventIntegrity.Verify(lines,key);Assert(ok.Verified==3&&ok.ChainGaps==0&&ok.LastHmac==previous);
    var changed=JsonSerializer.Deserialize<EventIntegrity.Record>(lines[1],Wire.Json)! with {Data="tampered"};
    var tampered=lines.ToArray();tampered[1]=JsonSerializer.Serialize(changed,Wire.Json);
    Throws<InvalidDataException>(()=>EventIntegrity.Verify(tampered,key));
    var gap=lines.Where((_,i)=>i!=1).ToArray();Assert(EventIntegrity.Verify(gap,key).ChainGaps==1);
    Throws<InvalidDataException>(()=>EventIntegrity.Verify(new[]{"{bad json"},key));
});
Test("Feodo parser validates trusted-format dated public IPv4 indicators",()=>{
    var now=DateTimeOffset.UtcNow;
    var header="# Feodo C2\n# Last updated: "+now.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss",System.Globalization.CultureInfo.InvariantCulture)+" UTC\n";
    var parsed=FeodoFeedParser.Parse(header+"8.8.8.8\n1.1.1.1\n8.8.8.8\n");
    Assert(parsed.Addresses.Count==2&&FeodoFeedParser.IsFresh(parsed,now));
    Throws<InvalidDataException>(()=>FeodoFeedParser.Parse(header+"127.0.0.1\n"));
    Throws<InvalidDataException>(()=>FeodoFeedParser.Parse(header+"10.0.0.2\n"));
    Throws<InvalidDataException>(()=>FeodoFeedParser.Parse(header+"8.8.8.8\nnot-an-ip\n"));
    Throws<InvalidDataException>(()=>FeodoFeedParser.Parse("8.8.8.8\n"));
    Throws<InvalidDataException>(()=>FeodoFeedParser.Parse(header+"8.8.8.8/32\n"));
    var old=parsed with {UpdatedUtc=now.AddDays(-2)};
    Assert(!FeodoFeedParser.IsFresh(old,now)&&!FeodoFeedParser.IsFresh(parsed with{UpdatedUtc=now.AddHours(2)},now));
});
Test("Read-audit analyzer recognizes genuine Windows 4663 access mask and browser paths",()=>{
    Assert(AuditedFileAccess.IsReadAccess("0x1")&&AuditedFileAccess.IsReadAccess("0x120089")&&!AuditedFileAccess.IsReadAccess("0x2"));
    Assert(!AuditedFileAccess.IsReadAccess("nonsense"));
    var sensitive=@"C:\Users\Public\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    Assert(AuditedFileAccess.IsBrowserCredentialPath(sensitive));
    Assert(!AuditedFileAccess.IsBrowserCredentialPath(@"C:\Temp\Login Data"));
    var now=DateTimeOffset.UtcNow;var monitor=new AuditedFileAccess();
    Assert(!monitor.Observe("Key",sensitive,@"C:\malware.exe","0x1",now).AuditedRead);
    Assert(!monitor.Observe("File",sensitive,@"C:\malware.exe","0x2",now).AuditedRead);
    var ordinary=monitor.Observe("File",sensitive,@"C:\Program Files\Google\Chrome\chrome.exe","0x1",now);
    Assert(ordinary.AuditedRead&&ordinary.BrowserCredentialRead&&!ordinary.UnexpectedCredentialReader);
    var suspicious=monitor.Observe("File",sensitive,@"C:\Temp\unknown.exe","0x1",now);
    Assert(suspicious.UnexpectedCredentialReader);
    Assert(!monitor.Observe("File",sensitive,@"C:\Temp\unknown.exe","0x1",now.AddSeconds(3)).UnexpectedCredentialReader);
    var later=monitor.Observe("File",sensitive,@"C:\Temp\unknown.exe","0x1",now.AddMinutes(6));
    Assert(later.UnexpectedCredentialReader);
});
Test("Per-process audited bulk reads require 64 distinct file paths in one minute",()=>{
    var m=new AuditedFileAccess();var now=DateTimeOffset.UtcNow;int alerts=0;
    for(int i=0;i<80;i++){
        var found=m.Observe("File",$@"C:\Data\item-{i}.txt",@"C:\Tools\copy.exe","0x1",now.AddMilliseconds(i*50));
        if(found.BulkRead)alerts++;
    }
    Assert(alerts==1);
    Assert(m.Observe("File",@"C:\Data\item-20.txt",@"C:\Tools\copy.exe","0x1",now.AddSeconds(20)).DistinctFiles==80);
    Assert(m.Observe("File",@"C:\Data\other.txt",@"C:\Tools\copy.exe","0x1",now.AddMinutes(2)).DistinctFiles==1);
});
Test("DNS-rebinding observation warns only after validated public to private transition",()=>{
    var now=DateTimeOffset.UtcNow;
    var d=new DnsRebindingDetector();
    Assert(DnsRebindingDetector.IsLocal(System.Net.IPAddress.Parse("192.168.1.12")));
    Assert(!DnsRebindingDetector.IsLocal(System.Net.IPAddress.Parse("1.1.1.1")));
    var first=d.Observe("example.com","::ffff:8.8.8.8;","0",now);
    Assert(first.ParsedAddressAnswer&&!first.SuspiciousTransition);
    Assert(!d.Observe("unrelated.example.com","10.1.2.3;","0",now.AddSeconds(2)).SuspiciousTransition);
    var second=d.Observe("example.com","192.168.2.20;","0",now.AddSeconds(3));
    Assert(second.ParsedAddressAnswer&&second.SuspiciousTransition);
    Assert(!d.Observe("example.com","192.168.2.21;","0",now.AddSeconds(4)).SuspiciousTransition);
    Assert(!d.Observe("example.com","192.168.2.22;","9003",now.AddSeconds(5)).SuspiciousTransition);
    Assert(!d.Observe("router.local","8.8.8.8;","0",now).ParsedAddressAnswer);
    var stale=new DnsRebindingDetector();
    stale.Observe("site.example.org","8.8.8.8;","0",now);
    Assert(!stale.Observe("site.example.org","10.0.0.1;","0",now.AddMinutes(11)).SuspiciousTransition);
    Assert(!new DnsRebindingDetector().Observe("example.com","some.cname.example;","0",now).ParsedAddressAnswer);
});
Test("SSH configuration audits global first-match directives without assuming Match or Include safety",()=>{
    var strict=OpenSshPolicyAudit.Parse("PasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\n");
    Assert(strict.ExplicitlyHardened&&!strict.RequiresEffectiveVerification);
    Assert(OpenSshPolicyAudit.Parse("PasswordAuthentication yes\nPasswordAuthentication no\n").ExplicitWeakness);
    Assert(!OpenSshPolicyAudit.Parse("PasswordAuthentication no\n").ExplicitlyHardened);
    var conditional=OpenSshPolicyAudit.Parse("PasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nMatch User admin\nPasswordAuthentication yes\n");
    Assert(!conditional.ExplicitlyHardened&&conditional.RequiresEffectiveVerification&&!conditional.ExplicitWeakness);
    Assert(!OpenSshPolicyAudit.Parse("Include C:/somefile\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\n").ExplicitlyHardened);
    Assert(OpenSshPolicyAudit.Parse("PasswordAuthentication yes # prior setting\n").ExplicitWeakness);
    Throws<InvalidDataException>(()=>OpenSshPolicyAudit.Parse(new string('X',300000)));
});
Test("Container management API exposure distinguishes wildcard IPv4/IPv6 from local-only TCP",()=>{
    var x=ContainerManagementAudit.Analyze(new[]{"[0.0.0.0]:2375","[::]:2375","[127.0.0.1]:2375","[::1]:2376","[192.168.1.10]:2376"},true);
    Assert(x.PlaintextCandidates==3&&x.RemotePlaintextCandidates==2&&x.TlsCandidates==2);
    Assert(x.RequiresAttention);
    Assert(ContainerManagementAudit.ParseListeningAddress("malformed")==null);
    Assert(ContainerManagementAudit.ParseListeningAddress("[::]:443")==null);
    Assert(ContainerManagementAudit.Analyze(new[]{"[127.0.0.1]:2376"},true).PlaintextCandidates==0);
});
Test("TPM and BitLocker unknown-state handling",()=>{
    Assert(SecurityDeviceStates.TpmEnabled("True","True")==true);
    Assert(SecurityDeviceStates.TpmEnabled("True","False")==false);
    Assert(SecurityDeviceStates.TpmEnabled("False","True")==false);
    Assert(SecurityDeviceStates.TpmEnabled(null,"True")==null);
    Assert(SecurityDeviceStates.VolumeProtected("1")==true);
    Assert(SecurityDeviceStates.VolumeProtected("0")==false);
    Assert(SecurityDeviceStates.VolumeProtected("2")==null);
});

Test("Section G: strict IPC request schema rejects property injection and duplicate keys",()=>{
    void Bad(string json)
    {
        using var m=new MemoryStream();
        Wire.WriteAsync(m,new Request("status"),default).GetAwaiter().GetResult();
        var bytes=System.Text.Encoding.UTF8.GetBytes(json);
        m.SetLength(0);m.Write(BitConverter.GetBytes(bytes.Length));m.Write(bytes);m.Position=0;
        Throws<InvalidDataException>(()=>Wire.ReadAsync<Request>(m,1024,default).GetAwaiter().GetResult());
    }
    Bad("{\"Command\":\"off\",\"Unknown\":\"ignored\"}");
    Bad("{\"Command\":\"status\",\"Command\":\"off\"}");
    Bad("{\"Command\":\"status\",\"Layer\":1}");
    Bad("{\"Command\":\"status\",\"Enabled\":true}");
    // Unknown command names are well-formed requests, but the server explicitly denies them.
    Assert(!Wire.ValidRequest(new Request("other")));
    Bad("{\"Command\":null}");
    Bad("[]");
    Bad("{\"command\":\"status\"}");
    Assert(Wire.ValidRequest(new Request("status")));
    Assert(!Wire.ValidRequest(new Request("off",1)));
});
Test("Section G: restart throttling prevents rapid loops and resets after one hour",()=>{
    var policy=new RestartBudget();var t=DateTimeOffset.UtcNow;
    Assert(policy.TryAcquire(t));
    Assert(!policy.TryAcquire(t.AddSeconds(2)));
    Assert(policy.TryAcquire(t.AddMinutes(2)));
    Assert(policy.TryAcquire(t.AddMinutes(4)));
    Assert(!policy.TryAcquire(t.AddMinutes(6)));
    Assert(policy.TryAcquire(t.AddHours(2)));
    Assert(!policy.TryAcquire(t.AddHours(1)));
});
Test("Section G: independent watchdog heartbeat policy",()=>{
    var now=DateTimeOffset.UtcNow;
    Assert(!HeartbeatPolicy.IsStale(now.AddMinutes(-5),now,TimeSpan.FromMinutes(8)));
    Assert(HeartbeatPolicy.IsStale(now.AddMinutes(-9),now,TimeSpan.FromMinutes(8)));
    Assert(HeartbeatPolicy.IsStale(now.AddMinutes(6),now,TimeSpan.FromMinutes(8)));
    Assert(!HeartbeatPolicy.IsStale(now,now,TimeSpan.Zero));
});
Test("Section G: resource budget honors battery, CPU, memory and low disk",()=>{
    var ac=ResourceBudget.Evaluate(false,0,50,10L*1024*1024*1024,100L*1024*1024*1024);
    Assert(ac.CycleInterval==TimeSpan.FromSeconds(30)&&!ac.DeferNonessentialDiskWork);
    Assert(ResourceBudget.Evaluate(true,0,50,long.MaxValue,0).CycleInterval==TimeSpan.FromSeconds(90));
    Assert(ResourceBudget.Evaluate(false,12,50,long.MaxValue,0).CycleInterval==TimeSpan.FromSeconds(60));
    Assert(ResourceBudget.Evaluate(true,0,300,long.MaxValue,0).CycleInterval==TimeSpan.FromSeconds(180));
    var disk=ResourceBudget.Evaluate(false,0,50,200L*1024*1024,100L*1024*1024*1024);
    Assert(disk.DeferNonessentialDiskWork&&disk.CycleInterval>=TimeSpan.FromSeconds(180));
    Throws<ArgumentOutOfRangeException>(()=>ResourceBudget.Evaluate(false,double.NaN,0,1,2));
});
Test("Section G: trusted signed update rejects tampering, downgrade, expiry, and untrusted publisher",()=>{
    using var publisher=System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    using var impostor=System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    var key=publisher.ExportSubjectPublicKeyInfo();var now=DateTimeOffset.UtcNow;
    var folder=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(folder);
    var file=Path.Combine(folder,"update.bin");File.WriteAllText(file,"verified bytes");
    var digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file)));
    var manifest=new TrustedArtifacts.Manifest("OTS Firewall79X","2.0.0",now.AddMinutes(-1),now.AddHours(6),
        "software",[new TrustedArtifacts.Artifact("update.bin",new FileInfo(file).Length,digest)]);
    string Signed(TrustedArtifacts.Manifest data,System.Security.Cryptography.ECDsa signer)
    {
        var payload=JsonSerializer.SerializeToUtf8Bytes(data,Wire.Json);
        var sig=signer.SignData(payload,System.Security.Cryptography.HashAlgorithmName.SHA256);
        return JsonSerializer.Serialize(new TrustedArtifacts.Envelope(
            Convert.ToBase64String(payload),Convert.ToBase64String(sig)),Wire.Json);
    }
    var envelope=Signed(manifest,publisher);
    Assert(TrustedArtifacts.Verify(envelope,key,folder,new Version(1,0),now).Version=="2.0.0");
    Throws<System.Security.Cryptography.CryptographicException>(()=>
        TrustedArtifacts.Verify(Signed(manifest,impostor),key,folder,new Version(1,0),now));
    Throws<InvalidDataException>(()=>
        TrustedArtifacts.Verify(envelope,key,folder,new Version(3,0),now));
    Throws<InvalidDataException>(()=>
        TrustedArtifacts.Verify(Signed(manifest with{ExpiresUtc=now.AddSeconds(-1)},publisher),
            key,folder,new Version(1,0),now));
    Throws<InvalidDataException>(()=>
        TrustedArtifacts.Verify(Signed(manifest with{Files=[new TrustedArtifacts.Artifact("../update.bin",1,digest)]},publisher),
            key,folder,new Version(1,0),now));
    File.WriteAllText(file,"tampered bytes");
    Throws<System.Security.Cryptography.CryptographicException>(()=>
        TrustedArtifacts.Verify(envelope,key,folder,new Version(1,0),now));
    Throws<InvalidDataException>(()=>
        TrustedArtifacts.Verify(envelope,[],folder,new Version(1,0),now));
});
Test("Threat feed publication floor accepts only fresh, monotonic UTC timestamps across instances",()=>{
    var directory=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(directory);
    var path=Path.Combine(directory,"publication-floor.txt");
    var now=DateTimeOffset.UtcNow;
    var first=now.AddMinutes(-30);
    ThreatFeedPublicationFloor.Accept(path,first,now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5));
    Assert(File.Exists(path));
    // A second instance must reject rollback even when the older feed is still fresh.
    Throws<InvalidDataException>(()=>ThreatFeedPublicationFloor.Accept(path,first.AddSeconds(-1),
        now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5)));
    var next=now.AddMinutes(-10);
    ThreatFeedPublicationFloor.Accept(path,next,now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5));
    ThreatFeedPublicationFloor.Accept(path,next,now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5));
    Throws<InvalidDataException>(()=>ThreatFeedPublicationFloor.Accept(path,
        now.AddHours(-25),now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5)));
    Throws<InvalidDataException>(()=>ThreatFeedPublicationFloor.Accept(path,
        now.AddMinutes(6),now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5)));
    File.WriteAllText(path,"corrupt publication floor");
    Throws<InvalidDataException>(()=>ThreatFeedPublicationFloor.Accept(path,
        now,now,TimeSpan.FromHours(24),TimeSpan.FromMinutes(5)));
});
Test("Signed update staging rejects injected payloads and noncanonical Windows paths",()=>{
    using var publisher=System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    var key=publisher.ExportSubjectPublicKeyInfo();var now=DateTimeOffset.UtcNow;
    var folder=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(folder);
    var file=Path.Combine(folder,"update.bin");File.WriteAllText(file,"trusted contents");
    var digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file)));
    var entry=new TrustedArtifacts.Artifact("update.bin",new FileInfo(file).Length,digest);
    var manifest=new TrustedArtifacts.Manifest("OTS Firewall79X","3.0.0",now.AddMinutes(-1),now.AddHours(1),
        "software",[entry]);
    string Signed(TrustedArtifacts.Manifest info)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(info,Wire.Json);
        return JsonSerializer.Serialize(new TrustedArtifacts.Envelope(Convert.ToBase64String(bytes),
            Convert.ToBase64String(publisher.SignData(bytes,System.Security.Cryptography.HashAlgorithmName.SHA256))),Wire.Json);
    }
    Assert(TrustedArtifacts.Verify(Signed(manifest),key,folder,new Version(1,0),now).Files.Count==1);
    File.WriteAllText(Path.Combine(folder,"unexpected.ps1"),"not signed by the manifest");
    Throws<InvalidDataException>(()=>TrustedArtifacts.Verify(Signed(manifest),key,folder,new Version(1,0),now));
    File.Delete(Path.Combine(folder,"unexpected.ps1"));
    Directory.CreateDirectory(Path.Combine(folder,"nested"));
    Throws<InvalidDataException>(()=>TrustedArtifacts.Verify(Signed(manifest),key,folder,new Version(1,0),now));
    Directory.Delete(Path.Combine(folder,"nested"));
    foreach(var filename in new[]{"CON.txt","AUX.exe","COM1.dll","update.bin.","update.bin ","evil:stream","a|b.dll"})
    {
        var malformed=manifest with{Files=[entry with{Name=filename}]};
        Throws<InvalidDataException>(()=>TrustedArtifacts.Verify(Signed(malformed),key,folder,new Version(1,0),now));
    }
});
Test("Network restrictions reject outbound, private, mapped and documentation sources",()=>{
    var now=DateTimeOffset.UtcNow;var detector=new NetworkAbuseWindow();
    foreach(var ip in new[]{"127.0.0.1","10.0.2.8","192.0.2.9","198.51.100.20","203.0.113.24","::1","fc00::123","2001:db8::1","::ffff:8.8.8.8"})
    {
        Assert(!NetworkAbuseWindow.EligiblePublicSource(ip),ip);
        for(int i=0;i<50;i++)Assert(!detector.Observe(ip,"%%14592",1000+i,now).Restrict,ip);
    }
    Assert(!detector.Observe("8.8.8.8","%%14593",80,now).Eligible);
    Assert(!detector.Observe("8.8.8.8","Inbound",80,now).Eligible);
    Assert(!detector.Observe("8.8.8.8","%%14592",0,now).Eligible);
    Assert(!NetworkAbuseWindow.EligiblePublicSource("8.8.8.8",new[]{"8.8.8.8"}));
    Assert(NetworkAbuseWindow.EligiblePublicSource("8.8.8.8"));
    Assert(NetworkAbuseWindow.EligiblePublicSource("2606:4700:4700::1111"));
});
Test("Inbound scan escalates only after 20 distinct ports and cools down",()=>{
    var detector=new NetworkAbuseWindow();var now=DateTimeOffset.UtcNow;
    for(int i=1;i<=19;i++)
    {
        var f=detector.Observe("8.8.4.4","%%14592",i,now.AddMilliseconds(i));
        Assert(f.Eligible && !f.Restrict);
        if(i==12)Assert(f.Scan);
    }
    Assert(detector.Observe("8.8.4.4","%%14592",20,now.AddSeconds(1)).Restrict);
    Assert(!detector.Observe("8.8.4.4","%%14592",21,now.AddSeconds(2)).Restrict);
    Assert(detector.Observe("8.8.4.4","%%14592",22,now.AddMinutes(21)).Eligible);
});
Test("Flood threshold does not treat a single repetitive service as a ban",()=>{
    var detector=new NetworkAbuseWindow();var now=DateTimeOffset.UtcNow;
    for(int i=0;i<200;i++)Assert(!detector.Observe("1.1.1.1","%%14592",443,now.AddMilliseconds(i)).Restrict);
    var other=new NetworkAbuseWindow();bool restricted=false;
    for(int i=0;i<150;i++)restricted|=other.Observe("1.0.0.1","%%14592",1000+i%4,now.AddMilliseconds(i)).Restrict;
    Assert(restricted);
});
Test("Layer 41 aggregates only verified public-source remote Windows logons, with cooldown",()=>{
    var auth=new AuthenticationFailureMonitor();var now=DateTimeOffset.UtcNow;AuthenticationFailureMonitor.Finding finding=new(false,false,0,"","");
    Assert(!auth.Observe("203.0.113.5","2",now).ValidRemoteSource);
    Assert(!auth.Observe("127.0.0.1","10",now).ValidRemoteSource);
    Assert(!auth.Observe("192.168.1.15","3",now).ValidRemoteSource);
    Assert(!auth.Observe("-","10",now).ValidRemoteSource);
    for(int i=0;i<8;i++)finding=auth.Observe("8.8.8.8","10",now.AddSeconds(i));
    Assert(finding.ValidRemoteSource&&finding.Alert&&finding.Count==8);
    Assert(!auth.Observe("8.8.8.8","10",now.AddSeconds(9)).Alert);
    Assert(!auth.Observe("8.8.8.8","10",now.AddMinutes(3)).Alert);
    for(int i=0;i<8;i++)finding=auth.Observe("8.8.8.8","3",now.AddMinutes(6).AddSeconds(i));
    Assert(finding.Alert);
});
Test("Layer 41 handles IPv6 and large source pools within a bounded detector",()=>{
    var auth=new AuthenticationFailureMonitor();var now=DateTimeOffset.UtcNow;
    Assert(auth.Observe("2606:4700:4700::1111","3",now).ValidRemoteSource);
    Assert(!auth.Observe("fe80::1","3",now).ValidRemoteSource);
    for(int i=0;i<2500;i++)auth.Observe($"8.{i/256}.{i%256}.1","3",now);
    Assert(auth.Observe("9.9.9.9","10",now).ValidRemoteSource);
});
Test("Layer 43 hashes only the requested password and validates padded breach range",()=>{
    var password=System.Text.Encoding.UTF8.GetBytes("correct horse battery staple");
    var range=PasswordBreachRange.ComputeRange(password);
    Assert(range.Prefix.Length==5&&range.Suffix.Length==35);
    var response=range.Suffix+":42\r\n"+new string('F',35)+":0\r\n";
    Assert(PasswordBreachRange.ParseCount(range.Suffix,response)==42);
    Assert(PasswordBreachRange.ParseCount(new string('A',35),response)==0);
    Throws<InvalidDataException>(()=>PasswordBreachRange.ParseCount(range.Suffix,"not-a-range-response"));
    Throws<InvalidDataException>(()=>PasswordBreachRange.ParseCount(range.Suffix,response+response));
    Throws<InvalidDataException>(()=>PasswordBreachRange.ParseCount(range.Suffix,new string('A',1024*1024+1)));
    Throws<ArgumentException>(()=>PasswordBreachRange.ParseCount("invalid",response));
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
});
Test("Layer 42 parses effective SSH policy without trusting defaults",()=>{
    var hardened=EffectiveSshPolicy.Parse("passwordauthentication no\npubkeyauthentication yes\npermitemptypasswords no\npermitrootlogin prohibit-password\nstrictmodes yes\nallowtcpforwarding no\nx11forwarding no\n");
    Assert(hardened.Complete&&hardened.Hardened&&!hardened.Weak);
    var weak=EffectiveSshPolicy.Parse("passwordauthentication yes\npubkeyauthentication no\npermitemptypasswords yes\npermitrootlogin yes\nstrictmodes no");
    Assert(weak.Weak&&!weak.Hardened);
    Assert(!EffectiveSshPolicy.Parse("passwordauthentication no").Hardened);
    Throws<InvalidDataException>(()=>EffectiveSshPolicy.Parse(new string('x',256*1024+1)));
});
Test("Section D parses genuine Security 4663 decimal/hex PIDs only",()=>{
    Assert(EndpointSignals.AuditProcessId("0x3e8")==1000);
    Assert(EndpointSignals.AuditProcessId("1000")==1000);
    Assert(EndpointSignals.AuditProcessId("0")==null);
    Assert(EndpointSignals.AuditProcessId("0xffffffff")==null);
    Assert(EndpointSignals.AuditProcessId("not a pid")==null);
});
Test("Section D transfer correlation is PID/public address/state constrained",()=>{
    var c=new Connection(42,"copy","[127.0.0.1]:1","[8.8.8.8]:443","Established");
    Assert(EndpointSignals.PublicTcpForProcess(42,[c]));
    Assert(!EndpointSignals.PublicTcpForProcess(41,[c]));
    Assert(!EndpointSignals.PublicTcpForProcess(42,[c with{Remote="[192.168.1.1]:443"}]));
    Assert(!EndpointSignals.PublicTcpForProcess(42,[c with{State="Listening"}]));
});
Test("Section D miner alerts require CPU persistence plus corroboration",()=>{
    Assert(!EndpointSignals.MiningIndicator("chrome.exe",20,false));
    Assert(!EndpointSignals.MiningIndicator("xmrig.exe",1,true));
    Assert(EndpointSignals.MiningIndicator("xmrig.exe",3,false));
    Assert(EndpointSignals.MiningIndicator("xmrig",3,false));
    Assert(EndpointSignals.MiningIndicator("ordinary.exe",4,true));
    Assert(!EndpointSignals.MiningIndicator("ordinary.exe",3,true));
    Assert(EndpointSignals.PoolPortSeen(42,[new Connection(42,"example","[::]:1","[8.8.8.8]:3333","Established")]));
});
Test("Section D Defender indicators do not claim arbitrary input-hook detection",()=>{
    Assert(EndpointSignals.DefenderKeyloggerIndicator("Trojan:Win32/Keylogger.A"));
    Assert(EndpointSignals.DefenderKeyloggerIndicator("captures keystrokes"));
    Assert(!EndpointSignals.DefenderKeyloggerIndicator("ordinary service update"));
    Assert(!EndpointSignals.DefenderKeyloggerIndicator(new string('X',400)));
});
Test("Section D BCD parser flags only explicit weakening values",()=>{
    Assert(BootPolicyAudit.Parse("testsigning Yes\n").WeakeningDetected);
    Assert(BootPolicyAudit.Parse("nointegritychecks on\n").WeakeningDetected);
    Assert(!BootPolicyAudit.Parse("testsigning No\n").WeakeningDetected);
    Assert(!BootPolicyAudit.Parse("").Parsed);
    Assert(!BootPolicyAudit.Parse("unrelated text").Parsed);
});
Test("Section D Docker audit distinguishes unverified TCP from verified setting",()=>{
    Assert(DockerDaemonAudit.Parse("{\"hosts\":[\"tcp://0.0.0.0:2375\"]}").UnverifiedTcpHost);
    Assert(!DockerDaemonAudit.Parse("{\"hosts\":[\"tcp://0.0.0.0:2376\"],\"tlsverify\":true}").UnverifiedTcpHost);
    Assert(!DockerDaemonAudit.Parse("{\"hosts\":[\"npipe:////./pipe/docker_engine\"]}").UnverifiedTcpHost);
    Assert(!DockerDaemonAudit.Parse("{invalid}").Parsed);
});
Test("Section D execution indicators require suspicious command or parent lineage",()=>{
    Assert(Detections.ExecutionIndicator("powershell.exe","Get-Date","winword.exe")!=null);
    Assert(Detections.ExecutionIndicator("powershell.exe","Get-Date","explorer.exe")==null);
    Assert(Detections.ExecutionIndicator("wscript.exe","https://example.com/a.vbs")!=null);
    Assert(Detections.ExecutionIndicator("rundll32.exe","javascript:alert(1)")!=null);
});
Test("Canary DNS comparison requires exact generated name and ignores DNS case/trailing dot",()=>{
    const string expected="ots-0123456789abcdef0123456789abcdef.invalid";
    Assert(DeceptionRules.IsGeneratedCanaryDnsName(expected));
    Assert(DeceptionRules.IsCanaryDnsQuery(expected.ToUpperInvariant()+".",expected));
    Assert(!DeceptionRules.IsCanaryDnsQuery("other."+expected,expected));
    Assert(!DeceptionRules.IsCanaryDnsQuery("not-a-canary.invalid",expected));
    Assert(!DeceptionRules.IsGeneratedCanaryDnsName("ots-not-random.invalid"));
});
Test("HTTP canary requires exact GET or HEAD path with bounded single-line syntax",()=>{
    var path="/canary/0123456789abcdef0123456789abcdef";
    Assert(DeceptionRules.IsCanaryHttpRequest("GET "+path+" HTTP/1.1",path));
    Assert(DeceptionRules.IsCanaryHttpRequest("HEAD "+path+" HTTP/1.0",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("POST "+path+" HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("GET "+path+"/extra HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("GET http://remote.test"+path+" HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest(new string('X',1000),path));
});
Test("Audited canary file access requires exact 4663 object identity and rights",()=>{
    const string file=@"C:\ProgramData\OTS\canaries\decoy.txt";
    var read=DeceptionRules.ClassifyFileAudit("File",file,file,"0x1");
    Assert(read.Read&&!read.Changed);
    Assert(DeceptionRules.ClassifyFileAudit("File",file,file,"0x2").Changed);
    Assert(DeceptionRules.ClassifyFileAudit("File",file,file,"0x10000").Changed);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file+"-other",file,"0x1").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("Key",file,file,"0x1").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file,file,"bad").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file,file,"0x80").Read);
});
Test("URLhaus domain parser validates header, exact names and source freshness",()=>{
    var now=DateTimeOffset.UtcNow;
    var header="# abuse.ch URLhaus Host file #\n# Last updated: "+now.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss",System.Globalization.CultureInfo.InvariantCulture)+" (UTC) #\n";
    var feed=MaliciousDomainIntelligence.Parse(header+"127.0.0.1 evil-domain.example.net\n127.0.0.1 malicious-mirror.example.org\n127.0.0.1 evil-domain.example.net\n");
    Assert(feed.Domains.Count==2&&MaliciousDomainIntelligence.IsFresh(feed,now));
    Assert(!MaliciousDomainIntelligence.IsFresh(feed,now.AddDays(3)));
    Assert(!MaliciousDomainIntelligence.IsFresh(feed,now.AddHours(13)));
    var online="# Title: Online Malicious Hosts Blocklist\n# Updated: "+now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ",System.Globalization.CultureInfo.InvariantCulture)+"\n# Expires: 12 hours (update frequency)\n# Source: https://urlhaus.abuse.ch/api/\n0.0.0.0 a.test-malicious.example.net\n0.0.0.0 b.test-malicious.example.org\n";
    Assert(MaliciousDomainIntelligence.Parse(online).Domains.Count==2);
    Assert(ManagedHostsSection.Remove("# other\n1.2.3.4 example.internal\r\n")=="# other\n1.2.3.4 example.internal\r\n");
    Assert(!MaliciousDomainIntelligence.ValidDomain("microsoft.com")&&!MaliciousDomainIntelligence.ValidDomain("x.github.com"));
    Assert(!MaliciousDomainIntelligence.ValidDomain("abc..org")&&!MaliciousDomainIntelligence.ValidDomain("127.0.0.1"));
    Assert(MaliciousDomainIntelligence.ValidDomain("evil-domain.example.net"));
    Throws<InvalidDataException>(()=>MaliciousDomainIntelligence.Parse("127.0.0.1 evil-domain.example.net"));
    Throws<InvalidDataException>(()=>MaliciousDomainIntelligence.Parse(header+"not-an-ip malformed.bad\n"));
    Throws<InvalidDataException>(()=>MaliciousDomainIntelligence.Parse(header+"127.0.0.1 google.com\n"));
});
Test("Managed hosts changes preserve external lines and rollback exact owned region",()=>{
    var original="# keep this line\r\n192.168.1.5 intranet.corp\r\n";
    var applied=ManagedHostsSection.Apply(original,["a.bad-domain.example.net","b.bad-domain.example.net","google.com"],["b.bad-domain.example.net"]);
    Assert(applied.Contains("0.0.0.0 a.bad-domain.example.net")&&!applied.Contains("b.bad-domain.example.net"));
    Assert(applied.Contains("192.168.1.5 intranet.corp"));
    Assert(ManagedHostsSection.Remove(applied)==original);
    Assert(ManagedHostsSection.Remove(ManagedHostsSection.Remove(applied))==original);
    var external=applied+"1.2.3.4 external.intranet\r\n";
    Assert(ManagedHostsSection.Remove(external).Contains("external.intranet"));
    Throws<InvalidDataException>(()=>ManagedHostsSection.Remove(applied.Replace("0.0.0.0 a.bad-domain.example.net","5.6.7.8 a.bad-domain.example.net")));
    Throws<InvalidDataException>(()=>ManagedHostsSection.Apply(original,["evil-domain.example.net"],["invalid..entry"]));
});
Test("Ransomware burst requires destructive distinct changes, ignores repeated notifications",()=>{
    var tracker=new RansomwareActivity();var now=DateTimeOffset.UtcNow;
    for(int i=0;i<50;i++)Assert(!tracker.Observe("C:/data/"+i+".txt",WatcherChangeTypes.Changed,now.AddMilliseconds(i*30)));
    bool alarm=false;
    for(int i=0;i<60;i++)alarm|=tracker.Observe("C:/other/"+i+".locked",WatcherChangeTypes.Renamed,now.AddSeconds(2).AddMilliseconds(i*50));
    Assert(alarm);
    Assert(!tracker.Observe("C:/other/60.locked",WatcherChangeTypes.Renamed,now.AddSeconds(5)));
    var duplicate=new RansomwareActivity();
    for(int i=0;i<100;i++)Assert(!duplicate.Observe("C:/same.file",WatcherChangeTypes.Deleted,now.AddMilliseconds(i*40)));
});
Test("Ransomware heuristic resets stale event windows after clock rollback",()=>{
    var activity=new RansomwareActivity();
    var now=DateTimeOffset.UtcNow;
    bool alert=false;
    for (int i=0;i<40;i++)
        alert |= activity.Observe("pre-"+i,WatcherChangeTypes.Deleted,now.AddMilliseconds(i*20));
    Assert(alert,"An actual destructive file burst should be observed");
    var earlier=now.AddHours(-1);
    Assert(!activity.Observe("rollback",WatcherChangeTypes.Deleted,earlier),
        "Clock rollback must not preserve the previous destructive burst");
    for(int i=0;i<40;i++)
        Assert(!activity.Observe("within-cooldown-"+i,WatcherChangeTypes.Deleted,earlier.AddMilliseconds(i*20)),
            "A backward clock jump must not bypass alert cooldown");
    bool later=false;
    for(int i=0;i<40;i++)
        later |= activity.Observe("after-cooldown-"+i,WatcherChangeTypes.Deleted,
            earlier.AddMinutes(3).AddMilliseconds(i*20));
    Assert(later,"Ransomware heuristic should recover after bounded cooldown");
});
Test("Beacon detector demands sufficient regularity and suppresses expected background tasks",()=>{
    var now=DateTimeOffset.UtcNow;
    var periodic=Enumerable.Range(0,14).Select(i=>now.AddSeconds(i*60)).ToArray();
    Assert(BeaconAnalysis.Suspicious("unknown-app",periodic));
    Assert(!BeaconAnalysis.Suspicious("chrome",periodic));
    Assert(!BeaconAnalysis.Suspicious("unknown-app",periodic.Take(5).ToArray()));
    Assert(!BeaconAnalysis.Suspicious("unknown-app",Enumerable.Range(0,14).Select(i=>now.AddSeconds(i*i*65)).ToArray()));
    Assert(!BeaconAnalysis.Suspicious("unknown-app",Enumerable.Range(0,14).Select(i=>now.AddSeconds(i*10)).ToArray()));
});
Test("Section G: exact owned-rule identities never delete drifted or lookalike policies",()=>{
    const string prefix=OwnedFirewallRule.InboundPrefix;
    const string intel=OwnedFirewallRule.IntelligencePrefix;
    bool Mine(string name,string description,string remote,int direction=1,int action=0,int protocol=256,
        int profiles=int.MaxValue,bool enabled=true)=>
        OwnedFirewallRule.Matches(name,description,remote,direction,action,protocol,profiles,enabled);
    Assert(Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8"));
    Assert(Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8/255.255.255.255"));
    Assert(Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8/32"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8/255.255.255.0"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8/16","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8/0","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8/33","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8-8.8.8.9","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8;1.1.1.1","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("8.8.8.8 ","8.8.8.8"));
    Assert(!OwnedFirewallRule.ExactHostAddress("*","8.8.8.8"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8/24"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8,1.1.1.1"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.4.4/255.255.255.255"));
    Assert(Mine(intel+"1.1.1.1",OwnedFirewallRule.IntelligenceDescription,"1.1.1.1/255.255.255.255",2));
    Assert(OwnedFirewallRule.ExactHostAddress("2606:4700:4700::1111/128","2606:4700:4700::1111"));
    Assert(!OwnedFirewallRule.ExactHostAddress("2606:4700:4700::1111/64","2606:4700:4700::1111"));
    Assert(Mine(intel+"1.1.1.1",OwnedFirewallRule.IntelligenceDescription,"1.1.1.1",2));
    Assert(!Mine(prefix+"8.8.8.8","modified by third party","8.8.8.8"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.4.4"));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",2));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",1,1));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",1,0,6));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",1,0,256,1));
    Assert(!Mine(prefix+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",1,0,256,int.MaxValue,false));
    Assert(!Mine(intel+"8.8.8.8",OwnedFirewallRule.InboundDescription,"8.8.8.8",2));
    Assert(!Mine(intel+"2606:4700:4700::1111",OwnedFirewallRule.IntelligenceDescription,"2606:4700:4700::1111",2));
    foreach(var address in new[]{"127.0.0.1","10.0.0.1","192.0.2.10","::1","not-an-ip","8.8.8.8,1.1.1.1","8.8.8.8/32"})
        Assert(!Mine(prefix+address,OwnedFirewallRule.InboundDescription,address));
    var random=new Random(79);
    for(int i=0;i<3000;i++)
    {
        var chars=new char[random.Next(0,95)];
        for(int j=0;j<chars.Length;j++)chars[j]=(char)random.Next(1,128);
        string name=prefix+new string(chars);
        // Unknown name/address must never be treated as an OTS-created rule.
        if(!name.Equals(prefix+"8.8.8.8",StringComparison.Ordinal))
            Assert(!Mine(name,OwnedFirewallRule.InboundDescription,"8.8.8.8"));
    }
});
Test("Canary DNS comparison requires exact generated name and ignores DNS case/trailing dot",()=>{
    const string expected="ots-0123456789abcdef0123456789abcdef.invalid";
    Assert(DeceptionRules.IsGeneratedCanaryDnsName(expected));
    Assert(DeceptionRules.IsCanaryDnsQuery(expected.ToUpperInvariant()+".",expected));
    Assert(!DeceptionRules.IsCanaryDnsQuery("other."+expected,expected));
    Assert(!DeceptionRules.IsCanaryDnsQuery("not-a-canary.invalid",expected));
    Assert(!DeceptionRules.IsGeneratedCanaryDnsName("ots-not-random.invalid"));
});
Test("HTTP canary requires exact GET or HEAD path with bounded single-line syntax",()=>{
    var path="/canary/0123456789abcdef0123456789abcdef";
    Assert(DeceptionRules.IsCanaryHttpRequest("GET "+path+" HTTP/1.1",path));
    Assert(DeceptionRules.IsCanaryHttpRequest("HEAD "+path+" HTTP/1.0",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("POST "+path+" HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("GET "+path+"/extra HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest("GET http://remote.test"+path+" HTTP/1.1",path));
    Assert(!DeceptionRules.IsCanaryHttpRequest(new string('X',1000),path));
});
Test("Audited canary file access requires exact 4663 object identity and rights",()=>{
    const string file=@"C:\ProgramData\OTS\canaries\decoy.txt";
    var read=DeceptionRules.ClassifyFileAudit("File",file,file,"0x1");
    Assert(read.Read&&!read.Changed);
    Assert(DeceptionRules.ClassifyFileAudit("File",file,file,"0x2").Changed);
    Assert(DeceptionRules.ClassifyFileAudit("File",file,file,"0x10000").Changed);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file+"-other",file,"0x1").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("Key",file,file,"0x1").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file,file,"bad").Read);
    Assert(!DeceptionRules.ClassifyFileAudit("File",file,file,"0x80").Read);
});
Test("Section G: event log key rotation preserves linked authenticated history",()=>{
    var key0=System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    var key1=System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    var previous=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    var h0=EventIntegrity.Compute(0,key0,previous,"legacy");
    var h1=EventIntegrity.Compute(1,key1,h0,"rotated");
    var lines=new[]{
        JsonSerializer.Serialize(new EventIntegrity.Record(previous,"legacy",h0),Wire.Json),
        JsonSerializer.Serialize(new EventIntegrity.Record(h0,"rotated",h1,1),Wire.Json)
    };
    var ring=new Dictionary<int,byte[]>{{0,key0},{1,key1}};
    var verification=EventIntegrity.Verify(lines,ring);
    Assert(verification.Verified==2 && verification.ChainGaps==0 && verification.LastHmac==h1);
    Throws<InvalidDataException>(()=>EventIntegrity.Verify(lines,key0));
    var compromised=JsonSerializer.Deserialize<EventIntegrity.Record>(lines[1],Wire.Json)! with{KeyId=0};
    Throws<InvalidDataException>(()=>EventIntegrity.Verify(
        new[]{lines[0],JsonSerializer.Serialize(compromised,Wire.Json)},ring));
    Throws<InvalidDataException>(()=>EventIntegrity.Verify(
        new[]{lines[0],lines[1].Replace("rotated","tampered",StringComparison.Ordinal)},ring));
});

Test("Section G: malformed DNS, feed and retained-log corpus remains bounded",()=>{
    var rng=new Random(56065);
    var detector=new DnsRebindingDetector();
    var now=DateTimeOffset.UtcNow;
    var key=System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    for(int i=0;i<2500;i++)
    {
        var chars=new char[rng.Next(0,180)];
        for(int j=0;j<chars.Length;j++)chars[j]=(char)rng.Next(1,127);
        var raw=new string(chars);
        var finding=detector.Observe(raw,raw,"0",now);
        Assert(finding.AddressCount<=64);
        try
        {
            _ = EventIntegrity.Verify(new[]{raw},key);
            Assert(string.IsNullOrWhiteSpace(raw));
        }
        catch(InvalidDataException){/* A malformed log must fail closed. */}
        try{_ = FeodoFeedParser.Parse(raw);}
        catch(InvalidDataException){/* Unsupported/corrupted input rejected. */}
    }
    Assert(!detector.Observe(new string('A',8192),"8.8.8.8","0",now).ParsedAddressAnswer);
    Assert(!detector.Observe("external.example",new string('A',8192),"0",now).ParsedAddressAnswer);
});
Test("Section C endpoint parser rejects malformed and parses scoped IPv6",()=>{
    var ip4=TrafficRules.ParseEndpoint("[192.168.1.10]:587");
    Assert(ip4?.Port==587&&ip4.Address.ToString()=="192.168.1.10");
    Assert(TrafficRules.ParseEndpoint("[2001:db8::1]:443")?.Port==443);
    foreach(var bad in new[]{"1.2.3.4:80","[1.1.1.1]:-1","[1.1.1.1]:99999","[nope]:80","[::1]:NaN",new string('x',101)})
        Assert(TrafficRules.ParseEndpoint(bad)==null,bad);
    Assert(TrafficRules.NonLoopbackBind("[0.0.0.0]:8080"));
    Assert(!TrafficRules.NonLoopbackBind("[::1]:8080"));
});
Test("Section C SMTP correlation covers common explicit submission ports",()=>{
    foreach(var p in new[]{25,465,587,2525})Assert(TrafficRules.SmtpPort(p));
    Assert(!TrafficRules.SmtpPort(443));
    Assert(TrafficRules.SuspiciousMailClient("powershell",587));
    Assert(TrafficRules.SuspiciousMailClient("unknown",25));
    Assert(!TrafficRules.SuspiciousMailClient("thunderbird.exe",587));
    Assert(!TrafficRules.SuspiciousMailClient("outlook",465));
});
Test("Section C neighbor alerts need two matching observations",()=>{
    var tracker=new NeighborChangeTracker();
    var old=new Dictionary<string,string>{{"3:192.168.1.1","001122334455"}};
    var newer=new Dictionary<string,string>{{"3:192.168.1.1","AABBCCDDEEFF"}};
    var gateway=new HashSet<string>{"192.168.1.1"};
    Assert(tracker.Update(old,gateway).Count==0);
    Assert(tracker.Update(newer,gateway).Count==0);
    Assert(tracker.Update(old,gateway).Count==0);
    Assert(tracker.Update(newer,gateway).Count==0);
    var confirmed=tracker.Update(newer,gateway);
    Assert(confirmed.Count==1&&confirmed[0].Gateway);
    Assert(tracker.Update(newer,gateway).Count==0);
    Assert(!TrafficRules.IsMac("000000000000"));
    Assert(TrafficRules.IsMac("00-11-22-33-44-55"));
});
Test("Section C monotonic clock checks ignore ordinary passage of time",()=>{
    var t=DateTimeOffset.Parse("2026-10-27T10:00:00+00:00");
    Assert(!TrafficRules.ClockStep(t,10000,t.AddSeconds(30),40000,TimeSpan.FromSeconds(90)));
    Assert(TrafficRules.ClockStep(t,10000,t.AddMinutes(4),40000,TimeSpan.FromSeconds(90)));
    Assert(!TrafficRules.ClockStep(t,40000,t.AddMinutes(4),10000,TimeSpan.FromSeconds(90)));
    Assert(!TrafficRules.RemoteClockDrift(t,t.AddSeconds(30),TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(120)));
    Assert(TrafficRules.RemoteClockDrift(t,t.AddMinutes(3),TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(120)));
    Assert(!TrafficRules.RemoteClockDrift(t,t.AddMinutes(3),TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(120)));
});
Test("Section C MITRE mapping is limited to justified signals",()=>{
    Assert(TrafficRules.MitreTechnique("repeated-logon-failures")!.Contains("T1110"));
    Assert(TrafficRules.MitreTechnique("remote-rdp-logon")!.Contains("T1021.001"));
    Assert(TrafficRules.MitreTechnique("script-powershell")!.Contains("T1059.001"));
    Assert(TrafficRules.MitreTechnique("arbitrary-network-traffic")==null);
});
Test("Section H forensic snapshot roundtrip, corruption rejection and unique versions",()=>{
    var root=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(root);
    var dashboard=new Dashboard(true,"Partially Protected",12,30,DateTimeOffset.UtcNow,null,
        Catalog.All.Select(c=>new LayerResult(c.Id,LayerMode.Unavailable,false,"Not assessed")).ToList(),[],[],2,0,0,null,"unavailable");
    var first=ForensicSnapshots.Capture(root,dashboard,2);
    var second=ForensicSnapshots.Capture(root,dashboard,2);
    Assert(first!=second&&ForensicSnapshots.Verify(first).Data.Layers.Count==79);
    var json=File.ReadAllText(first).Replace("Partially Protected","Fully Protected");
    File.WriteAllText(first,json);
    Throws<InvalidDataException>(()=>ForensicSnapshots.Verify(first));
    var third=ForensicSnapshots.Capture(root,dashboard,2);
    Assert(File.Exists(first),"Damaged evidence must be preserved");
    Assert(File.Exists(third)&&File.Exists(second));
});
Test("Section H dossier contains 79 operational states and missing-data guidance",()=>{
    var rows=Catalog.All.Select(l=>new LayerResult(l.Id,LayerMode.Unavailable,false,"No evidence","Test limitation")).ToList();
    var d=new Dashboard(true,"Partially Protected",0,0,DateTimeOffset.UtcNow,null,rows,[],[],0,0,0,null,"");
    var doc=SecurityDossier.Generate(d);
    Assert(doc.Contains("| 79 |")&&doc.Contains("Layer 57")&&doc.Contains("unavailable",StringComparison.OrdinalIgnoreCase));
    Assert(PostureAdvice.Recommend(rows).Count>0);
});
Test("Section H quarter history survives restart and catches up without fabricated days",()=>{
    var root=Path.GetDirectoryName(Temp())!;Directory.CreateDirectory(root);
    var history=Path.Combine(root,"history.json");var reports=Path.Combine(root,"reports");
    var t=new DateTimeOffset(2025,12,31,12,0,0,TimeSpan.Zero);
    var d=new Dashboard(true,"Partially Protected",38,52,t,null,[],[],[],12,0,0,null,"");
    QuarterlyHistory.Observe(history,d);QuarterlyHistory.Observe(history,d with{Score=45});
    Assert(QuarterlyHistory.Load(history).Count==1,"Only one daily sample should survive");
    Assert(QuarterlyHistory.CreateDue(history,reports,t).Count==0);
    var created=QuarterlyHistory.CreateDue(history,reports,t.AddDays(1));
    Assert(created.Count==1&&File.ReadAllText(created[0]).Contains("45"));
    Assert(QuarterlyHistory.CreateDue(history,reports,t.AddDays(2)).Count==0,"Report must be idempotent");
    File.WriteAllText(history,"{bad json");
    Throws<System.Text.Json.JsonException>(()=>QuarterlyHistory.Load(history));
});
Test("Section H range audit recognizes IPv4, IPv6 and port overlaps but not unknown keywords",()=>{
    Assert(FirewallOverlap.PortsOverlap("80-100","90,443"));
    Assert(!FirewallOverlap.PortsOverlap("80-90","443"));
    Assert(!FirewallOverlap.PortsOverlap("RPC Dynamic Ports","443"));
    Assert(FirewallOverlap.AddressesOverlap("192.168.1.0/24","192.168.1.2"));
    Assert(!FirewallOverlap.AddressesOverlap("192.168.1.0/24","10.0.0.1/32"));
    Assert(FirewallOverlap.AddressesOverlap("2001:db8::/32","2001:db8::2"));
    Assert(!FirewallOverlap.AddressesOverlap("LocalSubnet","192.168.1.2"));
    var baseRule=new FirewallRuleView("allow","1","1","6","80-90","192.168.1.0/24","7","",true);
    var match=baseRule with{Name="block",Action="0",LocalPorts="85",RemoteAddresses="192.168.1.11"};
    var report=FirewallOverlap.Analyze(new[]{baseRule,match});
    Assert(report.PotentialOverlaps>0&&report.Examined==2);
    Assert(FirewallOverlap.Analyze(new[]{baseRule,match with{Profiles="0"}}).PotentialOverlaps==0);
});
Test("Firewall overlap recognizes contiguous Windows dotted IPv4 masks",()=>{
    Assert(FirewallOverlap.AddressesOverlap("10.24.1.8/255.255.255.0","10.24.1.42/32"));
    Assert(!FirewallOverlap.AddressesOverlap("10.24.1.8/255.255.255.0","10.24.2.42/32"));
    Assert(FirewallOverlap.AddressesOverlap("10.24.1.8/255.255.255.255","10.24.1.8"));
    Assert(!FirewallOverlap.AddressesOverlap("10.24.1.8/255.0.255.0","10.24.1.8"));
    Assert(!FirewallOverlap.AddressesOverlap("2001:db8::1/255.255.255.0","2001:db8::1"));
});
Test("Section H encrypted export queue verifies data and preserves retry on failures",()=>{
    var root=Path.GetDirectoryName(Temp())!;var queue=Path.Combine(root,"queue");var receiver=Path.Combine(root,"receiver");
    Directory.CreateDirectory(root);Directory.CreateDirectory(receiver);
    var source=Path.Combine(root,"source.jsonl");File.WriteAllText(source,"security log data");
    var archive=OffDeviceLogExport.Enqueue(queue,source,"twelve-chars-or-more");
    Assert(!OffDeviceLogExport.IsOffDeviceDestination(receiver),"Local hard disk must not count as off-device");
    Throws<IOException>(()=>OffDeviceLogExport.Ship(archive,receiver));
    var copy=OffDeviceLogExport.CopyAndVerify(archive,receiver);
    Assert(File.Exists(archive)&&File.Exists(copy),"Do not delete queued evidence before successful remote receipt");
    Assert(SecureArchive.Decrypt(copy,"twelve-chars-or-more").AsSpan().SequenceEqual(System.Text.Encoding.UTF8.GetBytes("security log data")));
    Assert(OffDeviceLogExport.CopyAndVerify(archive,receiver)==copy,
        "Byte-identical delivery receipt should be safe to retry after interrupted queue deletion");
    var data=File.ReadAllBytes(copy);data[^1]^=1;File.WriteAllBytes(copy,data);
    Throws<IOException>(()=>OffDeviceLogExport.CopyAndVerify(archive,receiver));
    Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(()=>SecureArchive.Decrypt(copy,"twelve-chars-or-more"));
});
Test("Section H restored encrypted backup retains last-modified timestamp",()=>{
    var root=Path.GetDirectoryName(Temp())!;var source=Path.Combine(root,"src");Directory.CreateDirectory(source);
    var file=Path.Combine(source,"time.txt");File.WriteAllText(file,"important");
    var timestamp=new DateTime(2022,2,3,4,5,6,DateTimeKind.Utc);File.SetLastWriteTimeUtc(file,timestamp);
    var encrypted=Path.Combine(root,"time.otsfolder");
    FolderBackup.Create(source,encrypted,"twelve-chars-or-more");
    var restored=Path.Combine(root,"restored");FolderBackup.Restore(encrypted,restored,"twelve-chars-or-more");
    Assert(Math.Abs((File.GetLastWriteTimeUtc(Path.Combine(restored,"time.txt"))-timestamp).TotalSeconds)<2);
});

Test("Section H generated offline kit preserves verified owned configuration exports",()=>{
    var baseDir=Path.GetDirectoryName(Temp())!;var install=Path.Combine(baseDir,"install");var data=Path.Combine(baseDir,"data");var kit=Path.Combine(baseDir,"kit");
    Directory.CreateDirectory(install);Directory.CreateDirectory(data);
    File.WriteAllText(Path.Combine(data,"changes.json"),"[]");
    File.WriteAllText(Path.Combine(install,"OTS.Firewall79X.Recovery.exe"),"fixture");
    var result=RecoveryKit.Create(kit,install,data);
    Assert(result.IncludesRecoveryExecutable && result.ConfigurationFiles==1);
    Assert(File.ReadAllText(result.ManifestPath).Contains(Convert.ToHexString(
        System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("[]")))));
    Assert(File.ReadAllText(Path.Combine(kit,"RECOVERY_INSTRUCTIONS.md")).Contains("NOT a bootable"));
    Assert(File.ReadAllText(Path.Combine(kit,"RESTORE_OWNED_SETTINGS.ps1")).Contains("--restore"));
});
Test("Section H configured-only resilience actions remain administrator-only",()=>{
    foreach(var command in new[]{"configure-backup","configure-export","disable-backup","disable-export"})
    {
        Assert(Wire.Commands.Contains(command));
        Assert(Wire.RequiresAdmin(command));
    }
    var request=new Request("configure-export",Destination:@"Z:\\OTS-logs",Secret:"NeverLogThisPassword");
    using var stream=new MemoryStream();
    Wire.WriteAsync(stream,request,default).GetAwaiter().GetResult();
    stream.Position=0;
    var parsed=Wire.ReadAsync<Request>(stream,1024,default).GetAwaiter().GetResult();
    Assert(parsed.Command==request.Command&&parsed.Secret==request.Secret&&parsed.Destination==request.Destination);
});
Test("Section H strict IPC denies secret injection into ordinary commands",()=>{
    Assert(!Wire.ValidRequest(new Request("status",Secret:"NeverLogThisPassword")));
    Assert(!Wire.ValidRequest(new Request("configure-export",Destination:"X")));
    Assert(Wire.ValidRequest(new Request("configure-export",Destination:"X",Secret:"NeverLogThisPassword")));
    foreach(var json in new[]{
        """{"Command":"status","Secret":"unauthorized"}""",
        """{"Command":"configure-export","Destination":"X"}""",
        """{"Command":"configure-export","Destination":"X","Secret":"twelve chars okay","secret":"duplicated"}"""})
    {
        using var frame=new MemoryStream();
        var bytes=System.Text.Encoding.UTF8.GetBytes(json);
        frame.Write(BitConverter.GetBytes(bytes.Length));frame.Write(bytes);frame.Position=0;
        Throws<InvalidDataException>(()=>Wire.ReadAsync<Request>(frame,8192,default).GetAwaiter().GetResult());
    }
});
Test("WFP 5157 endpoint roles use remote DestAddress and local SourcePort",()=>{
    Assert(BlockedConnectionEvent.TryParseInboundTcp("%%14592","192.168.1.10","445","8.8.8.8","50420","6",out var evt));
    Assert(evt!=null&&evt.RemoteAddress=="8.8.8.8"&&evt.LocalPort==445&&evt.RemotePort==50420);
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14593","192.168.1.10","445","8.8.8.8","50420","6",out _));
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14592","192.168.1.10","445","8.8.8.8","50420","17",out _));
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14592","192.168.1.10","0","8.8.8.8","50420","6",out _));
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14592","192.168.1.10","445","127.0.0.1","50420","6",out _));
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14592","0.0.0.0","445","8.8.8.8","50420","6",out _));
    Assert(!BlockedConnectionEvent.TryParseInboundTcp("%%14592","192.168.1.10","445","203.0.113.7","50420","6",out _));
    Assert(BlockedConnectionEvent.TryParseInboundTcp("%%14592","2001:db8::10","3389","2606:4700:4700::1111","52880","6",out var v6)&&v6?.LocalPort==3389);
});
Test("IPv4/IPv6 packet parser fails closed on malformed headers, not truncated captures",()=>{
    byte[] ipv4=new byte[40];
    ipv4[0]=0x45;ipv4[2]=0;ipv4[3]=40;ipv4[8]=64;ipv4[9]=6;
    ipv4[12]=192;ipv4[13]=0;ipv4[14]=2;ipv4[15]=1;
    ipv4[16]=198;ipv4[17]=51;ipv4[18]=100;ipv4[19]=1;
    ipv4[32]=0x50;
    uint sum=0;for(int i=0;i<20;i+=2)sum+=(uint)((ipv4[i]<<8)|ipv4[i+1]);
    while((sum>>16)!=0)sum=(sum&65535)+(sum>>16);
    ushort checksum=(ushort)~sum;ipv4[10]=(byte)(checksum>>8);ipv4[11]=(byte)checksum;
    Assert(IpPacketValidator.Inspect(ipv4).Status==IpPacketValidator.Verdict.Valid);
    var truncated=ipv4.AsSpan(0,28).ToArray();
    Assert(IpPacketValidator.Inspect(truncated).Status==IpPacketValidator.Verdict.Unsupported);
    var broken=(byte[])ipv4.Clone();broken[8]=63;
    Assert(IpPacketValidator.Inspect(broken).Status==IpPacketValidator.Verdict.Malformed);
    broken=(byte[])ipv4.Clone();broken[6]=0xE0;
    Assert(IpPacketValidator.Inspect(broken).Status==IpPacketValidator.Verdict.Malformed);
    byte[] ipv6=new byte[48];ipv6[0]=0x60;ipv6[4]=0;ipv6[5]=8;ipv6[6]=17;ipv6[7]=64;ipv6[44]=0;ipv6[45]=8;
    Assert(IpPacketValidator.Inspect(ipv6).Status==IpPacketValidator.Verdict.Valid);
    ipv6[45]=9;Assert(IpPacketValidator.Inspect(ipv6).Status==IpPacketValidator.Verdict.Malformed);
    ipv6[45]=8;ipv6[6]=50;Assert(IpPacketValidator.Inspect(ipv6).Status==IpPacketValidator.Verdict.Unsupported);
    byte[] fragmented=new byte[48];fragmented[0]=0x60;fragmented[5]=8;fragmented[6]=44;fragmented[40]=59;
    Assert(IpPacketValidator.Inspect(fragmented).Status==IpPacketValidator.Verdict.Valid);
    fragmented[42]=0;fragmented[43]=2;
    Assert(IpPacketValidator.Inspect(fragmented).Status==IpPacketValidator.Verdict.Malformed);
});
Test("DNS rebinding recognizes mixed answers and special-use destinations",()=>{
    var now=DateTimeOffset.UtcNow;
    var d=new DnsRebindingDetector();
    Assert(DnsRebindingDetector.IsLocal(System.Net.IPAddress.Parse("100.64.1.2")));
    Assert(DnsRebindingDetector.IsLocal(System.Net.IPAddress.Parse("2001:db8::1")));
    Assert(!DnsRebindingDetector.IsLocal(System.Net.IPAddress.Parse("8.8.8.8")));
    Assert(!d.Observe("mixed.example.org","8.8.8.8;10.0.0.1","0",now).SuspiciousTransition);
    Assert(!d.Observe("mixed.example.org","10.0.0.1","0",now.AddSeconds(1)).SuspiciousTransition,
        "An initial mixed response must not create a public-only baseline");
    d.Observe("mixed.example.org","8.8.8.8","0",now.AddSeconds(2));
    Assert(d.Observe("mixed.example.org","8.8.8.8;10.0.0.1","0",now.AddSeconds(3)).SuspiciousTransition);
    Assert(!d.Observe("mixed.example.org","8.8.8.8;10.0.0.1","0",now.AddSeconds(4)).SuspiciousTransition,
        "Repeated mixed results must honor alert cooldown");
    var special=new DnsRebindingDetector();
    special.Observe("special.example.org","9.9.9.9","0",now);
    Assert(special.Observe("special.example.org","100.64.0.1","0",now.AddSeconds(1)).SuspiciousTransition);
    Assert(!special.Observe("bad_name.example.org","9.9.9.9","0",now).ParsedAddressAnswer);
    Assert(!special.Observe("many.example.org",string.Join(';',Enumerable.Repeat("8.8.8.8",65)),"0",now).ParsedAddressAnswer,
        "More than 64 answers must not be silently truncated");
});
Test("Encrypted evidence exporter refuses linked destination paths and receipts",()=>{
    var root=Path.GetDirectoryName(Temp())!;
    var queue=Path.Combine(root,"queue");
    var receiver=Path.Combine(root,"receiver");
    Directory.CreateDirectory(receiver);
    var log=Path.Combine(root,"events.jsonl");
    File.WriteAllText(log,"encrypted evidence fixture");
    var encrypted=OffDeviceLogExport.Enqueue(queue,log,"recovery-passphrase-test");
    var link=Path.Combine(root,"receiver-link");
    try
    {
        Directory.CreateSymbolicLink(link,receiver);
    }
    catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
    {
        return; // Windows without symlink privilege; ordinary copy/receipt tests still run.
    }
    Throws<IOException>(()=>OffDeviceLogExport.CopyAndVerify(encrypted,link));
    var receipt=Path.Combine(receiver,Path.GetFileName(encrypted));
    File.CreateSymbolicLink(receipt,encrypted);
    Throws<IOException>(()=>OffDeviceLogExport.CopyAndVerify(encrypted,receiver));
    Assert(File.Exists(encrypted),"Rejecting a linked receipt must never discard queued evidence");
});
Test("Inbound abuse history recovers from saturated stale public sources",()=>{
    var monitor=new NetworkAbuseWindow();
    var now=DateTimeOffset.UtcNow;
    for(int i=0;i<1024;i++)
    {
        string ip=$"8.{i/256}.{i%256}.1";
        var item=monitor.Observe(ip,"%%14592",445,now);
        Assert(item.Eligible,"Known public source unexpectedly refused while filling bounded monitor: "+ip);
    }
    var stale=monitor.Observe("9.9.9.9","%%14592",445,now.AddMinutes(3));
    Assert(stale.Eligible,"A full table of stale sources must be reclaimed before refusing a new source");
    Assert(!stale.Restrict,"The new source must never be blocked without independently satisfying the restriction threshold");
});
Test("Layer 4 IP parser checks TCP header length and complete first-fragment headers",()=>{
    byte[] ipv4=new byte[40];
    ipv4[0]=0x45; ipv4[3]=40; ipv4[8]=64; ipv4[9]=6;
    ipv4[32]=0x40; // TCP data offset claims 16 bytes, below the 20-byte minimum.
    uint checksum=0;
    for(int i=0;i<20;i+=2)checksum+=(uint)((ipv4[i]<<8)|ipv4[i+1]);
    while((checksum>>16)!=0)checksum=(checksum&0xffff)+(checksum>>16);
    ushort headerChecksum=(ushort)~checksum;
    ipv4[10]=(byte)(headerChecksum>>8); ipv4[11]=(byte)headerChecksum;
    Assert(IpPacketValidator.Inspect(ipv4).Status==IpPacketValidator.Verdict.Malformed);
    ipv4[32]=0x50;
    Assert(IpPacketValidator.Inspect(ipv4).Status==IpPacketValidator.Verdict.Valid);
    Assert(IpPacketValidator.Inspect(ipv4.AsSpan(0,16)).Status==IpPacketValidator.Verdict.Unsupported);
    byte[] firstFragment=new byte[68];
    firstFragment[0]=0x60; firstFragment[5]=28; firstFragment[6]=44;
    firstFragment[40]=6; // Fragment header -> TCP, offset zero (first fragment).
    firstFragment[60]=0x40;
    Assert(IpPacketValidator.Inspect(firstFragment).Status==IpPacketValidator.Verdict.Malformed);
    firstFragment[60]=0x50;
    Assert(IpPacketValidator.Inspect(firstFragment).Status==IpPacketValidator.Verdict.Valid);
    firstFragment[42]=0; firstFragment[43]=8; // Noninitial fragment: no TCP header assumption.
    Assert(IpPacketValidator.Inspect(firstFragment).Status==IpPacketValidator.Verdict.Valid);
});
Directory.CreateDirectory("artifacts");File.WriteAllText("artifacts/core-test-results.json",JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine($"{results.Count-failed}/{results.Count} tests passed");return failed==0?0:1;
sealed class FakeStore(string? value):ISettingStore{public string? Value=value;public bool Fail;public string? Read(string key)=>Value;public void Write(string key,string? value){if(Fail)throw new IOException("Injected storage failure");Value=value;}}

sealed class DictionaryStore(Dictionary<string,string?> values):ISettingStore
{
    public string? Read(string key)=>values.GetValueOrDefault(key);
    public void Write(string key,string? value)=>values[key]=value;
}
