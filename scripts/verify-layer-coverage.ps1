param([switch]$RequireCertified)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# A full catalog and passing compilation do not establish the requested
# 79-layer security behavior. Validate the three independent inventory
# representations before creating a distributable or claiming coverage.
$catalog=@(Get-Content 'src/OTS.Firewall79X.Core/catalog.json' -Raw | ConvertFrom-Json)
$coverage=Get-Content 'LAYER_COVERAGE.md'
$spec=Get-Content 'docs/BUILD_SPECIFICATION.md'
if($catalog.Count -ne 79) { throw "Catalog has $($catalog.Count) layers; expected exactly 79" }

$specNames=@{}
foreach($line in $spec) {
    $match=[regex]::Match($line,'^\*\*(\d{1,2})\.\s+([^*]+)\*\*$')
    if(-not $match.Success) { continue }
    $id=[int]$match.Groups[1].Value
    if($specNames.ContainsKey($id)) { throw "Duplicate specification layer $id" }
    $specNames[$id]=$match.Groups[2].Value.Trim()
}
if($specNames.Count -ne 79) { throw "Original specification defines $($specNames.Count), not 79 layer headings" }

$rows=@{}
foreach($line in $coverage) {
    if($line -notmatch '^\|\s*\d{1,2}\s*\|') { continue }
    # A literal escaped Markdown pipe belongs to a cell, not a column boundary.
    $parts=@([regex]::Split($line,'(?<!\\)\|') | ForEach-Object { $_.Trim() })
    if($parts.Count -lt 9) { throw 'Layer coverage row is missing required fields' }
    $id=[int]$parts[1]
    if($rows.ContainsKey($id)) { throw "Duplicate coverage layer $id" }
    if(@($parts[2],$parts[3],$parts[4],$parts[5],$parts[6],$parts[7]) |
       Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }) {
        throw "Missing evidence field on layer $id"
    }
    $rows[$id]=@{Name=$parts[2];Status=$parts[5];Tests=$parts[6];Limitations=$parts[7]}
}
if($rows.Count -ne 79) { throw "Coverage matrix has $($rows.Count), not 79 layer rows" }

$certified=0
foreach($entry in $catalog) {
    $id=[int]$entry.Id
    if($id -lt 1 -or $id -gt 79 -or -not $specNames.ContainsKey($id) -or -not $rows.ContainsKey($id)) {
        throw "Missing or out-of-range layer $id"
    }
    if($entry.Name -cne $specNames[$id] -or $entry.Name -cne $rows[$id].Name) {
        throw "Original specification/catalog/coverage disagree about layer $id"
    }
    if($rows[$id].Status -ceq 'Certified — full specification implemented and independently validated') {
        $certified++
    }
}
if($RequireCertified -and $certified -ne 79) {
    throw "PRODUCTION BLOCKED: only $certified of 79 layers have complete certified acceptance evidence"
}
Write-Host "PASS: original specification, catalog and coverage matrix agree on 79 layers; $certified individually certified"
