using System.Text.Json;
using OTS.Firewall79X.Core;

var results=new List<object>();int failed=0;
void Test(string name,Action action){try{action();Console.WriteLine("PASS "+name);results.Add(new{name,status="PASS"});}catch(Exception e){failed++;Console.WriteLine("FAIL "+name+": "+e.Message);results.Add(new{name,status="FAIL",error=e.Message});}}
void Assert(bool b,string message="Assertion failed"){if(!b)throw new Exception(message);}
void Throws<T>(Action a)where T:Exception{try{a();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
string Temp()=>Path.Combine(Path.GetTempPath(),"OTS-tests-"+Guid.NewGuid().ToString("N"),"journal.json");
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
Test("Secrets scanner emits indicator type only",()=>{Assert(Detections.SecretKind("ordinary text")==null);Assert(Detections.SecretKind("-----BEGIN PRIVATE KEY-----\nsecret") == "Private key");});
Test("Report includes all layers and literal limitations",()=>{var layers=Catalog.All.Select(l=>new LayerResult(l.Id,LayerMode.Unavailable,false,"Not implemented","A | B")).ToList();var d=new Dashboard(false,"Not Protected",0,0,DateTimeOffset.UtcNow,null,layers,[],[],0,0,0,null,"none");var report=Reports.Generate(d);Assert(report.Contains("| 79 |")&&report.Contains("A \\| B"));});
Test("Encrypted archive roundtrip and wrong-password rejection",()=>{var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);SecureArchive.Encrypt(path,"private report"u8.ToArray(),"twelve-chars-or-more");Assert(SecureArchive.Decrypt(path,"twelve-chars-or-more").AsSpan().SequenceEqual("private report"u8));Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(()=>SecureArchive.Decrypt(path,"wrong-password-here"));});
Test("Encrypted archive rejects modified ciphertext",()=>{var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);SecureArchive.Encrypt(path,"private report"u8.ToArray(),"twelve-chars-or-more");var bytes=File.ReadAllBytes(path);bytes[^1]^=1;File.WriteAllBytes(path,bytes);Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(()=>SecureArchive.Decrypt(path,"twelve-chars-or-more"));});
Test("Encrypted archive rejects short password and invalid format",()=>{Throws<ArgumentException>(()=>SecureArchive.Encrypt(Temp(),[1],"short"));var path=Temp();Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllText(path,"bad");Throws<InvalidDataException>(()=>SecureArchive.Decrypt(path,"twelve-chars-or-more"));});
Test("Folder backup roundtrip preserves files without overwriting",()=>{var parent=Path.GetDirectoryName(Temp())!;var source=Path.Combine(parent,"source");Directory.CreateDirectory(Path.Combine(source,"nested"));File.WriteAllText(Path.Combine(source,"nested","file.txt"),"test content");var archive=Path.Combine(parent,"backup.otsfolder");var summary=FolderBackup.Create(source,archive,"twelve-chars-or-more");Assert(summary.Files==1);var target=Path.Combine(parent,"restored");FolderBackup.Restore(archive,target,"twelve-chars-or-more");Assert(File.ReadAllText(Path.Combine(target,"nested","file.txt"))=="test content");Throws<IOException>(()=>FolderBackup.Restore(archive,target,"twelve-chars-or-more"));Throws<IOException>(()=>FolderBackup.Create(source,archive,"twelve-chars-or-more"));});
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
Test("Temporary firewall ownership requires exact structured fields, not name prefix alone",()=>{
    const string src="8.8.4.4";
    var name=TemporaryRuleIdentity.InboundPrefix+src;
    Assert(TemporaryRuleIdentity.IsOwned(name,TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,src,1,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned(name,"someone else's rule",TemporaryRuleIdentity.Group,src,1,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned(name,TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,"*",1,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned(name,TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,src,2,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned(TemporaryRuleIdentity.InboundPrefix+"192.168.1.1",TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,"192.168.1.1",1,0,256));
    Assert(TemporaryRuleIdentity.IsOwned(TemporaryRuleIdentity.OutboundPrefix+src,TemporaryRuleIdentity.Marker+"intelligence",TemporaryRuleIdentity.Group,src,2,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned(TemporaryRuleIdentity.OutboundPrefix+src,TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,src,2,0,256));
    Assert(!TemporaryRuleIdentity.IsOwned("Unrelated firewall rule",TemporaryRuleIdentity.Marker+"inbound",TemporaryRuleIdentity.Group,src,1,0,256));
});
Directory.CreateDirectory("artifacts");File.WriteAllText("artifacts/core-test-results.json",JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine($"{results.Count-failed}/{results.Count} tests passed");return failed==0?0:1;
sealed class FakeStore(string? value):ISettingStore{public string? Value=value;public bool Fail;public string? Read(string key)=>Value;public void Write(string key,string? value){if(Fail)throw new IOException("Injected storage failure");Value=value;}}
