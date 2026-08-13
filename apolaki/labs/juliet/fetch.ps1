param(
    [Parameter(Mandatory = $true)]
    [string]$Destination
)

$ErrorActionPreference = "Stop"
$url = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip"
$expectedBytes = 76798417
$expectedSha256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"

$parent = Split-Path -Parent $Destination
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
Invoke-WebRequest -Uri $url -OutFile $Destination

$item = Get-Item -LiteralPath $Destination
$actualSha256 = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
if ($item.Length -ne $expectedBytes -or $actualSha256 -ne $expectedSha256) {
    throw "Juliet archive verification failed: bytes=$($item.Length), sha256=$actualSha256"
}

[pscustomobject]@{
    Path = $item.FullName
    Bytes = $item.Length
    Sha256 = $actualSha256
}
