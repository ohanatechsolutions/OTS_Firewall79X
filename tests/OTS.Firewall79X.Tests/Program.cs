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
Directory.CreateDirectory("artifacts");File.WriteAllText("artifacts/core-test-results.json",JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine($"{results.Count-failed}/{results.Count} tests passed");return failed==0?0:1;
sealed class FakeStore(string? value):ISettingStore{public string? Value=value;public bool Fail;public string? Read(string key)=>Value;public void Write(string key,string? value){if(Fail)throw new IOException("Injected storage failure");Value=value;}}
