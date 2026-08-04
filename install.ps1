$ErrorActionPreference = 'Stop'

# The installer has no production options or mirrors. The fixture harness may
# suppress only the final installer invocation.
$script:Repository = 'context-engine-app/context-engine-mcp'
$script:MinimumVersion = [Version]'0.2.0'
$script:LatestReleaseUrl = 'https://github.com/context-engine-app/context-engine-mcp/releases/latest'
$script:ReleaseRoot = 'https://github.com/context-engine-app/context-engine-mcp/releases/download'
$script:TestOnly = $env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY -eq '1'

function Fail([string]$Message) {
    throw "Context Engine installer: $Message"
}

function Get-InstallRoot {
    if (-not $env:LOCALAPPDATA) { Fail 'LOCALAPPDATA is not available' }
    return [IO.Path]::Combine($env:LOCALAPPDATA, 'Context Engine')
}

function Get-HttpClient {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('context-engine-installer/0.2.0')
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/json')
    return $client
}

function Get-RequestRemaining([DateTimeOffset]$Deadline) {
    $remaining = $Deadline - [DateTimeOffset]::UtcNow
    if ($remaining -le [TimeSpan]::Zero) { Fail 'HTTP request deadline exceeded' }
    $milliseconds = [Math]::Ceiling($remaining.TotalMilliseconds)
    if ($milliseconds -lt 1) { $milliseconds = 1 }
    return [TimeSpan]::FromMilliseconds($milliseconds)
}

function Invoke-HttpGet([System.Net.Http.HttpClient]$Client, [string]$Url, [DateTimeOffset]$Deadline) {
    $current = New-Object System.Uri($Url)
    $logicalTimeout = New-Object System.Threading.CancellationTokenSource
    try {
        $logicalTimeout.CancelAfter((Get-RequestRemaining $Deadline))
        for ($redirect = 0; $redirect -le 10; $redirect++) {
            if ($current.Scheme -ne 'https') { Fail 'HTTP redirect left HTTPS' }
            $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $current)
            $hopTimeout = New-Object System.Threading.CancellationTokenSource
            $linkedTimeout = $null
            try {
                $remaining = Get-RequestRemaining $Deadline
                $hopBudget = [TimeSpan]::FromSeconds(60)
                if ($remaining -lt $hopBudget) { $hopBudget = $remaining }
                $hopTimeout.CancelAfter($hopBudget)
                $linkedTimeout = [Threading.CancellationTokenSource]::CreateLinkedTokenSource($logicalTimeout.Token, $hopTimeout.Token)
                $response = $Client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $linkedTimeout.Token).GetAwaiter().GetResult()
            }
            finally {
                if ($linkedTimeout) { $linkedTimeout.Dispose() }; $hopTimeout.Dispose(); $request.Dispose()
            }
            if ($response.StatusCode -ge 300 -and $response.StatusCode -lt 400) {
                if (-not $response.Headers.Location) { $response.Dispose(); Fail 'redirect did not include a Location header' }
                $next = New-Object System.Uri($current, $response.Headers.Location)
                $response.Dispose(); $current = $next; continue
            }
            if (-not $response.IsSuccessStatusCode) {
                $status = [int]$response.StatusCode
                $response.Dispose(); Fail "HTTP request failed with status $status"
            }
            return @{ Response = $response; Url = $current.AbsoluteUri }
        }
        Fail 'HTTP redirect limit exceeded'
    }
    finally { $logicalTimeout.Dispose() }
}

function Read-ResponseFile([hashtable]$Http, [string]$Destination, [Int64]$ExpectedSize, [Int64]$MaximumSize, [DateTimeOffset]$Deadline) {
    $response = $Http.Response; $stream = $null; $file = $null; $written = [Int64]0
    if ($Deadline -eq [DateTimeOffset]::MinValue) {
        if ($ExpectedSize -ge 0) { $Deadline = [DateTimeOffset]::UtcNow.AddMinutes(10) } else { $Deadline = [DateTimeOffset]::UtcNow.AddSeconds(60) }
    }
    $overallTimeout = New-Object System.Threading.CancellationTokenSource
    try {
        $overallTimeout.CancelAfter((Get-RequestRemaining $Deadline))
        $declared = $response.Content.Headers.ContentLength
        if ($null -ne $declared -and $ExpectedSize -ge 0 -and [Int64]$declared -ne $ExpectedSize) { Fail 'response Content-Length does not match the manifest size' }
        $streamTask = $response.Content.ReadAsStreamAsync()
        $remainingMilliseconds = [Math]::Ceiling((Get-RequestRemaining $Deadline).TotalMilliseconds)
        if ($remainingMilliseconds -gt [Int32]::MaxValue) { $remainingMilliseconds = [Int32]::MaxValue }
        try {
            if (-not $streamTask.Wait([Int32]$remainingMilliseconds)) {
                $overallTimeout.Cancel()
                Fail 'response stream acquisition deadline exceeded'
            }
            $stream = $streamTask.GetAwaiter().GetResult()
        }
        catch [AggregateException] {
            throw $_.Exception.InnerException
        }
        $file = New-Object System.IO.FileStream($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        while ($true) {
            $readTimeout = New-Object System.Threading.CancellationTokenSource
            $readTimeout.CancelAfter([TimeSpan]::FromSeconds(30))
            $linkedTimeout = [Threading.CancellationTokenSource]::CreateLinkedTokenSource($overallTimeout.Token, $readTimeout.Token)
            try {
                try { $read = $stream.ReadAsync($buffer, 0, $buffer.Length, $linkedTimeout.Token).GetAwaiter().GetResult() }
                catch [OperationCanceledException] { Fail 'response read deadline exceeded' }
                catch [AggregateException] { Fail 'response read deadline exceeded' }
            }
            finally { $linkedTimeout.Dispose(); $readTimeout.Dispose() }
            if ($read -eq 0) { break }
            $written += [Int64]$read
            if (($ExpectedSize -ge 0 -and $written -gt $ExpectedSize) -or ($MaximumSize -ge 0 -and $written -gt $MaximumSize)) { Fail 'download exceeds its exact manifest size' }
            $file.Write($buffer, 0, $read)
        }
    }
    finally {
        if ($file) { $file.Dispose() }; if ($stream) { $stream.Dispose() }; $overallTimeout.Dispose(); $response.Dispose()
    }
    if ($ExpectedSize -ge 0 -and $written -ne $ExpectedSize) { Fail 'download ended before its exact manifest size' }
    return $written
}

function Save-RemoteFile([System.Net.Http.HttpClient]$Client, [string]$Url, [string]$Destination, [Int64]$ExpectedSize, [Int64]$MaximumSize) {
    if ($ExpectedSize -ge 0) { $deadline = [DateTimeOffset]::UtcNow.AddMinutes(10) } else { $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60) }
    $http = Invoke-HttpGet -Client $Client -Url $Url -Deadline $deadline
    Read-ResponseFile -Http $http -Destination $Destination -ExpectedSize $ExpectedSize -MaximumSize $MaximumSize -Deadline $deadline | Out-Null
}

function Get-ExactInt64($Value, [string]$Name) {
    $text = [string]$Value
    if ($text -notmatch '^[1-9][0-9]*$') { Fail "$Name is not a positive canonical decimal integer" }
    try { return [Int64]::Parse($text, [Globalization.CultureInfo]::InvariantCulture) } catch { Fail "$Name is outside the signed 64-bit range" }
}

function Get-Sha256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Get-Target {
    $architecture = [string]$env:PROCESSOR_ARCHITECTURE
    if ($architecture -ieq 'AMD64') { return 'x86_64-pc-windows-msvc' }
    Fail "unsupported Windows architecture: $architecture"
}

function Get-LatestTag([System.Net.Http.HttpClient]$Client, [string]$Url) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    $http = Invoke-HttpGet -Client $Client -Url $Url -Deadline $deadline
    $effective = [string]$http.Url; $http.Response.Dispose()
    if ($effective -notmatch '^https://github\.com/context-engine-app/context-engine-mcp/releases/tag/(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$') {
        Fail 'latest release did not resolve to the public stable product tag'
    }
    if ($effective -match '/(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$') { return $Matches[1] }
    Fail 'latest release tag is malformed'
}

function Get-ExactPropertyValue($Object, [string]$Name, [string]$Context) {
    if ($null -eq $Object) { Fail "$Context is missing" }
    $propertyMatches = @($Object.PSObject.Properties | Where-Object { [string]::Equals($_.Name, $Name, [StringComparison]::Ordinal) })
    if ($propertyMatches.Count -ne 1) { Fail "$Context has an invalid $Name property" }
    Write-Output -NoEnumerate -InputObject $propertyMatches[0].Value
}

function Get-ExactArray($Object, [string]$Name, [string]$Context) {
    $value = Get-ExactPropertyValue -Object $Object -Name $Name -Context $Context
    if ($value -isnot [Collections.IList]) { Fail "$Context $Name must be a JSON array" }
    return $value
}

function Get-ManifestString($Object, [string]$Name, [string]$Context) {
    $value = Get-ExactPropertyValue -Object $Object -Name $Name -Context $Context
    if ($value -isnot [string]) { Fail "$Context $Name must be a JSON string" }
    return [string]$value
}

function Get-SelectedManifest($Manifest, [string]$Target, [string]$Tag, [string]$Version) {
    $repository = Get-ManifestString -Object $Manifest -Name 'distribution_repository' -Context 'manifest'
    $manifestTag = Get-ManifestString -Object $Manifest -Name 'tag' -Context 'manifest'
    $manifestVersion = Get-ManifestString -Object $Manifest -Name 'version' -Context 'manifest'
    if (-not [string]::Equals($repository, $script:Repository, [StringComparison]::Ordinal) -or -not [string]::Equals($manifestTag, $Tag, [StringComparison]::Ordinal) -or -not [string]::Equals($manifestVersion, $Version, [StringComparison]::Ordinal)) { Fail 'manifest release identity mismatch' }
    $artifactRecords = Get-ExactArray -Object $Manifest -Name 'artifacts' -Context 'manifest'
    $archives = @()
    foreach ($candidate in @($artifactRecords)) {
        $kind = Get-ManifestString -Object $candidate -Name 'kind' -Context 'manifest artifact'
        $candidateTarget = Get-ManifestString -Object $candidate -Name 'target' -Context 'manifest artifact'
        if ([string]::Equals($kind, 'archive', [StringComparison]::Ordinal) -and [string]::Equals($candidateTarget, $Target, [StringComparison]::Ordinal)) { $archives += $candidate }
    }
    if ($archives.Count -ne 1) { Fail 'manifest archive target is missing or ambiguous' }
    $archive = $archives[0]
    $archivePayloadId = Get-ManifestString -Object $archive -Name 'payload_id' -Context 'manifest archive'
    [void](Get-ManifestString -Object $archive -Name 'filename' -Context 'manifest archive')
    [void](Get-ManifestString -Object $archive -Name 'target' -Context 'manifest archive')
    [void](Get-ManifestString -Object $archive -Name 'url' -Context 'manifest archive')
    [void](Get-ManifestString -Object $archive -Name 'sha256' -Context 'manifest archive')
    $archiveSizeText = Get-ManifestString -Object $archive -Name 'size' -Context 'manifest archive'
    $payloadRecords = Get-ExactArray -Object $Manifest -Name 'payloads' -Context 'manifest'
    $payloads = @()
    foreach ($candidate in @($payloadRecords)) {
        $candidateId = Get-ManifestString -Object $candidate -Name 'id' -Context 'manifest payload'
        $candidateTarget = Get-ManifestString -Object $candidate -Name 'target' -Context 'manifest payload'
        if ([string]::Equals($candidateId, $archivePayloadId, [StringComparison]::Ordinal) -and [string]::Equals($candidateTarget, $Target, [StringComparison]::Ordinal)) { $payloads += $candidate }
    }
    if ($payloads.Count -ne 1) { Fail 'manifest payload linkage is missing or ambiguous' }
    $payload = $payloads[0]
    [void](Get-ManifestString -Object $payload -Name 'filename' -Context 'manifest payload')
    [void](Get-ManifestString -Object $payload -Name 'sha256' -Context 'manifest payload')
    $payloadSizeText = Get-ManifestString -Object $payload -Name 'size' -Context 'manifest payload'
    [void](Get-ManifestString -Object $payload -Name 'license_mode' -Context 'manifest payload')
    [void](Get-ManifestString -Object $payload -Name 'executable_mode' -Context 'manifest payload')
    [void](Get-ManifestString -Object $payload -Name 'version_output' -Context 'manifest payload')
    if ($archiveSizeText -isnot [string] -or $payloadSizeText -isnot [string]) { Fail 'manifest sizes must be JSON strings' }
    $archiveSize = Get-ExactInt64 -Value $archiveSizeText -Name 'archive size'
    $payloadSize = Get-ExactInt64 -Value $payloadSizeText -Name 'payload size'
    if (-not [string]::Equals($archive.filename, "context-engine-$Target.zip", [StringComparison]::Ordinal) -or -not [string]::Equals($payload.filename, 'context-engine.exe', [StringComparison]::Ordinal)) { Fail 'manifest filenames do not match the Windows target' }
    if (-not [string]::Equals($archive.url, "$script:ReleaseRoot/$Tag/$($archive.filename)", [StringComparison]::Ordinal)) { Fail 'manifest archive URL is not canonical' }
    if ($archive.sha256 -notmatch '^[0-9a-f]{64}$' -or $payload.sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'manifest checksum is not lowercase SHA-256' }
    if (-not [string]::Equals($payload.license_mode, 'enforced', [StringComparison]::Ordinal)) { Fail 'manifest payload is not license-enforced' }
    if (-not [string]::Equals($payload.executable_mode, '0755', [StringComparison]::Ordinal)) { Fail 'manifest executable mode is not production mode' }
    if (-not [string]::Equals($payload.version_output, "context-engine $Version", [StringComparison]::Ordinal)) { Fail 'manifest version output does not match release' }
    return @{ Archive = $archive; Payload = $payload; ArchiveSize = $archiveSize; PayloadSize = $payloadSize }
}

function Get-Checksum([string]$Path, [string]$Filename) {
    $checksumMatches = @(Get-Content -LiteralPath $Path | Where-Object {
            $parts = $_ -split '\s+', 2
            $parts.Count -eq 2 -and [string]::Equals($parts[1], $Filename, [StringComparison]::Ordinal)
        })
    if ($checksumMatches.Count -ne 1) { Fail 'checksum record is missing or ambiguous' }
    $parts = $checksumMatches[0] -split '\s+', 2
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-f]{64}$') { Fail 'checksum record is malformed' }
    return $parts[0]
}

function Test-SafeZipEntry([System.IO.Compression.ZipArchiveEntry]$Entry, [bool]$RequirePayloadMode = $false) {
    $name = [string]$Entry.FullName
    if ([string]::IsNullOrEmpty($name) -or $name.EndsWith('/') -or $name.StartsWith('/') -or $name.StartsWith('\') -or $name.Contains('\') -or $name -match '^[A-Za-z]:') { return $false }
    if ($name -match '(^|/)\.\.?(/|$)') { return $false }
    $attributes = [int64]$Entry.ExternalAttributes
    if (($attributes -band 0x10) -ne 0 -or ($attributes -band 0x400) -ne 0) { return $false }
    $mode = ($attributes -shr 16) -band 0xF000
    if ($mode -ne 0 -and $mode -ne 0x8000) { return $false }
    if ($RequirePayloadMode) {
        $permissions = ($attributes -shr 16) -band 0x0FFF
        if ($mode -ne 0x8000 -or $permissions -ne 0x1ED) { return $false }
    }
    return $true
}

function Read-ZipPayload([string]$ArchivePath, [string]$PayloadName, [string]$Destination, [Int64]$ExpectedSize) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entries = @($zip.Entries)
        $payloadEntries = @()
        foreach ($candidate in $entries) {
            if (-not (Test-SafeZipEntry $candidate ($candidate.FullName -eq $PayloadName))) { Fail 'archive contains an unsafe entry' }
            if ($candidate.FullName -eq $PayloadName) { $payloadEntries += $candidate }
        }
        if ($payloadEntries.Count -ne 1) { Fail 'archive must contain exactly one root executable' }
        $entry = $payloadEntries[0]; $zipInput = $entry.Open()
        $output = New-Object System.IO.FileStream($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $total = [Int64]0
        try {
            $buffer = New-Object byte[] 65536
            while ($true) {
                $read = $zipInput.Read($buffer, 0, $buffer.Length)
                if ($read -eq 0) { break }
                $total += [Int64]$read
                if ($total -gt $ExpectedSize) { Fail 'extracted payload exceeds its exact manifest size' }
                $output.Write($buffer, 0, $read)
            }
        }
        finally { $output.Dispose(); $zipInput.Dispose() }
        if ($total -ne $ExpectedSize) { Fail 'extracted payload size does not match the manifest' }
    }
    finally { $zip.Dispose() }
}

function Invoke-VersionCheck([string]$Binary, [string]$Expected) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Binary; $info.Arguments = '--version'; $info.UseShellExecute = $false
    $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process; $process.StartInfo = $info
    try {
        if (-not $process.Start()) { Fail 'could not start staged binary' }
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) { $process.Kill(); $process.WaitForExit(); Fail 'staged binary did not finish within ten seconds' }
        $actual = $stdout.GetAwaiter().GetResult(); $stderr.GetAwaiter().GetResult() | Out-Null
        $expectedLf = $Expected + "`n"; $expectedCrLf = $Expected + "`r`n"
        $exact = [string]::Equals($actual, $expectedLf, [StringComparison]::Ordinal) -or [string]::Equals($actual, $expectedCrLf, [StringComparison]::Ordinal)
        if ($process.ExitCode -ne 0 -or -not $exact -or $actual -like '*(UNLICENSED DEV BUILD)*') { Fail 'staged binary version output is invalid' }
    }
    finally { $process.Dispose() }
}

function Write-Marker([string]$Path) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $lines = @('{', '  "schema_version": 1,', '  "installation_method": "direct",', ('  "distribution_repository": "' + $script:Repository + '"'), '}')
    [IO.File]::WriteAllText($Path, ($lines -join [Environment]::NewLine) + [Environment]::NewLine, $encoding)
}

function Test-SafeRegularFile([string]$Path) {
    try { $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return $false }
    return $item -is [IO.FileInfo] -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}

function Test-Marker([string]$Path) {
    if (-not (Test-SafeRegularFile $Path)) { return $false }
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return $false }
        $raw = [IO.File]::ReadAllText($Path, $encoding)
        $lines = @('{', '  "schema_version": 1,', '  "installation_method": "direct",', ('  "distribution_repository": "' + $script:Repository + '"'), '}')
        $expected = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
        if (-not [string]::Equals($raw, $expected, [StringComparison]::Ordinal)) { return $false }
        $value = $raw | ConvertFrom-Json
    }
    catch { return $false }
    $names = @($value.PSObject.Properties.Name)
    $expectedNames = @('schema_version', 'installation_method', 'distribution_repository')
    if ($names.Count -ne $expectedNames.Count) { return $false }
    foreach ($expectedName in $expectedNames) {
        $nameMatches = @($names | Where-Object { [string]::Equals([string]$_, $expectedName, [StringComparison]::Ordinal) })
        if ($nameMatches.Count -ne 1) { return $false }
    }
    $schema = Get-ExactPropertyValue -Object $value -Name 'schema_version' -Context 'marker'
    $installationMethod = Get-ExactPropertyValue -Object $value -Name 'installation_method' -Context 'marker'
    $repository = Get-ExactPropertyValue -Object $value -Name 'distribution_repository' -Context 'marker'
    if ($schema -is [string] -or $schema -is [bool] -or $schema -is [double] -or $schema -is [decimal]) { return $false }
    return $schema -eq 1 -and $installationMethod -is [string] -and [string]::Equals($installationMethod, 'direct', [StringComparison]::Ordinal) -and $repository -is [string] -and [string]::Equals($repository, $script:Repository, [StringComparison]::Ordinal)
}

function Get-PathComparisonValue([string]$Path) {
    $normalized = $Path
    while ($normalized.Length -gt 1 -and ($normalized.EndsWith('\') -or $normalized.EndsWith('/'))) {
        if ($normalized.Length -eq 3 -and $normalized[1] -eq ':') { break }
        $normalized = $normalized.Substring(0, $normalized.Length - 1)
    }
    return $normalized
}

function Get-UpdatedUserPath([string]$Directory, [string]$PreviousPath) {
    $entries = @(); if ($PreviousPath) { $entries = @($PreviousPath -split ';') }
    $directoryComparison = Get-PathComparisonValue -Path $Directory
    foreach ($entry in $entries) {
        if ([string]::Equals((Get-PathComparisonValue -Path $entry), $directoryComparison, [StringComparison]::OrdinalIgnoreCase)) { return $PreviousPath }
    }
    if ($PreviousPath) { return "$PreviousPath;$Directory" }
    return $Directory
}

function Test-UserEnvironmentWritable {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $true }
    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        return $null -ne $key
    }
    catch { return $false }
    finally { if ($key) { $key.Dispose() } }
}

function Set-UserEnvironmentPath {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Value)
    if ($PSCmdlet.ShouldProcess('User PATH', 'set')) { [Environment]::SetEnvironmentVariable('PATH', $Value, 'User') }
}

function Assert-SafePathAncestor([string]$Path) {
    $parentInfo = [IO.Directory]::GetParent($Path)
    if (-not $parentInfo) { Fail 'installation parent is invalid' }
    $candidate = $parentInfo.FullName
    while ($candidate) {
        $candidateItem = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($null -ne $candidateItem) {
            if ($candidateItem -isnot [IO.DirectoryInfo]) { Fail 'installation parent is unsafe' }
            if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail 'installation parent is unsafe'
            }
        }
        $nextInfo = [IO.Directory]::GetParent($candidate)
        if (-not $nextInfo) { break }
        $candidate = $nextInfo.FullName
    }
}

function Assert-SafeFreshPath([string]$Root) {
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    if ($null -ne $rootItem) {
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'installation directory is a reparse point' }
        Fail 'existing installation directory is a conflict'
    }
    Assert-SafePathAncestor -Path $Root
}

function Invoke-MarkedReinstall([string]$Root) {
    $binary = [IO.Path]::Combine($Root, 'context-engine.exe')
    $backup = [IO.Path]::Combine($Root, '.context-engine.previous.exe')
    $marker = [IO.Path]::Combine($Root, '.context-engine-installation.json')
    if (-not (Test-Marker $marker)) { return $false }
    $canonicalItem = Get-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
    if ($null -ne $canonicalItem) {
        if (-not (Test-SafeRegularFile $binary)) { return $false }
        $updater = $binary
    }
    else {
        if (-not (Test-SafeRegularFile $backup)) { return $false }
        $updater = $backup
    }
    $pathBefore = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $pathAfter = Get-UpdatedUserPath -Directory $Root -PreviousPath $pathBefore
    if ($pathAfter -ne $pathBefore -and -not (Test-UserEnvironmentWritable)) { Fail 'user PATH storage is not writable' }
    $process = Start-Process -FilePath $updater -ArgumentList 'update' -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) { Fail 'direct updater failed' }
    if ($pathAfter -ne $pathBefore) {
        try { Set-UserEnvironmentPath -Value $pathAfter } catch { Fail "updated binary but could not repair user PATH: $($_.Exception.Message)" }
    }
    Write-Output 'Context Engine direct installation updated.'
    return $true
}

function Invoke-FreshInstall($Selected, [string]$Version, [string]$Working, [string]$Root) {
    if (-not $Root) { $Root = Get-InstallRoot }
    $createdParents = [Collections.Generic.List[string]]::new()
    $stage = $null
    $committed = $false
    $pathChanged = $false
    $pathBefore = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $recoveryErrors = [Collections.Generic.List[string]]::new()
    try {
        $pathAfter = Get-UpdatedUserPath -Directory $Root -PreviousPath $pathBefore
        if ($pathAfter -ne $pathBefore -and -not (Test-UserEnvironmentWritable)) { Fail 'user PATH storage is not writable' }
        Assert-SafeFreshPath -Root $Root
        $parentInfo = [IO.Directory]::GetParent($Root)
        if (-not $parentInfo) { Fail 'installation parent is invalid' }
        $parent = $parentInfo.FullName
        $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
        if ($null -eq $parentItem) {
            $candidate = $parent
            while ($null -eq (Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue)) {
                [void]$createdParents.Add($candidate)
                $candidateInfo = [IO.Directory]::GetParent($candidate)
                if (-not $candidateInfo) { break }
                $candidate = $candidateInfo.FullName
            }
            [IO.Directory]::CreateDirectory($parent) | Out-Null
            $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        }
        if ($parentItem -isnot [IO.DirectoryInfo] -or ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'installation parent is unsafe' }
        $stage = [IO.Path]::Combine($parent, '.context-engine-install-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($stage) | Out-Null
        Copy-Item -LiteralPath (Join-Path $Working 'context-engine.exe') -Destination (Join-Path $stage 'context-engine.exe') -Force
        Write-Marker (Join-Path $stage '.context-engine-installation.json')
        [IO.Directory]::Move($stage, $Root); $committed = $true; $stage = $null
        if ($pathAfter -ne $pathBefore) { $pathChanged = $true; Set-UserEnvironmentPath -Value $pathAfter }
        Write-Output "Context Engine $Version installed. Open a new terminal to use it."
    }
    catch {
        $primaryError = $_.Exception.Message
        if ($pathChanged) {
            try { Set-UserEnvironmentPath -Value $pathBefore } catch { [void]$recoveryErrors.Add("restore user PATH: $($_.Exception.Message)") }
        }
        if ($committed) {
            try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop } catch { [void]$recoveryErrors.Add("remove promoted installation: $($_.Exception.Message)") }
        }
        if ($stage) {
            try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop; $stage = $null } catch { [void]$recoveryErrors.Add("remove staging directory: $($_.Exception.Message)"); $stage = $null }
        }
        foreach ($created in $createdParents) {
            try {
                if (([IO.Directory]::GetFileSystemEntries($created)).Count -eq 0) { [IO.Directory]::Delete($created) }
            }
            catch { [void]$recoveryErrors.Add("remove created parent: $($_.Exception.Message)") }
        }
        if ($recoveryErrors.Count -gt 0) { Fail "$primaryError; recovery failed: $($recoveryErrors -join '; ')" }
        throw
    }
}

function Invoke-Installer {
    $root = Get-InstallRoot
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if ($null -ne $rootItem) {
        if ($rootItem -isnot [IO.DirectoryInfo] -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'existing installation directory is unsafe' }
        Assert-SafePathAncestor -Path $root
        if (Invoke-MarkedReinstall $root) { return }
        Fail 'existing installation directory is not a valid marked direct installation'
    }
    Assert-SafeFreshPath -Root $root
    $pathBefore = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $pathAfter = Get-UpdatedUserPath -Directory $root -PreviousPath $pathBefore
    if ($pathAfter -ne $pathBefore -and -not (Test-UserEnvironmentWritable)) { Fail 'user PATH storage is not writable' }
    $client = $null
    $working = $null
    $primaryError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        $client = Get-HttpClient
        $tag = Get-LatestTag -Client $client -Url $script:LatestReleaseUrl; $version = $tag.Substring(1)
        if ([Version]$version -lt $script:MinimumVersion) { Fail "latest product release is older than $($script:MinimumVersion)" }
        $working = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'context-engine-install-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($working) | Out-Null
        $base = "$script:ReleaseRoot/$tag"
        $manifestPath = Join-Path $working 'release-manifest.json'; $checksumsPath = Join-Path $working 'SHA256SUMS'
        Save-RemoteFile -Client $client -Url "$base/release-manifest.json" -Destination $manifestPath -ExpectedSize -1 -MaximumSize 4194304
        Save-RemoteFile -Client $client -Url "$base/SHA256SUMS" -Destination $checksumsPath -ExpectedSize -1 -MaximumSize 4194304
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $selected = Get-SelectedManifest -Manifest $manifest -Target (Get-Target) -Tag $tag -Version $version
        $checksum = Get-Checksum -Path $checksumsPath -Filename $selected.Archive.filename
        if ($checksum -ne $selected.Archive.sha256) { Fail 'checksum record disagrees with manifest' }
        $archivePath = Join-Path $working $selected.Archive.filename
        Save-RemoteFile -Client $client -Url $selected.Archive.url -Destination $archivePath -ExpectedSize $selected.ArchiveSize -MaximumSize $selected.ArchiveSize
        if ((Get-Sha256 $archivePath) -ne $selected.Archive.sha256) { Fail 'archive SHA-256 mismatch' }
        $staged = Join-Path $working 'context-engine.exe'
        Read-ZipPayload -ArchivePath $archivePath -PayloadName $selected.Payload.filename -Destination $staged -ExpectedSize $selected.PayloadSize
        if ((Get-Sha256 $staged) -ne $selected.Payload.sha256) { Fail 'payload SHA-256 mismatch' }
        Invoke-VersionCheck $staged $selected.Payload.version_output
        Invoke-FreshInstall -Selected $selected -Version $version -Working $working -Root $root
    }
    catch { $primaryError = $_ }
    finally {
        if ($client) {
            try { $client.Dispose() } catch { [void]$cleanupErrors.Add("dispose HTTP client: $($_.Exception.Message)") }
        }
        if ($working -and (Test-Path -LiteralPath $working)) {
            try { Remove-Item -LiteralPath $working -Recurse -Force -ErrorAction Stop } catch { [void]$cleanupErrors.Add("remove working directory: $($_.Exception.Message)") }
        }
    }
    if ($null -ne $primaryError) {
        if ($cleanupErrors.Count -gt 0) { throw "$($primaryError.Exception.Message); cleanup failed: $($cleanupErrors -join '; ')" }
        throw $primaryError
    }
    if ($cleanupErrors.Count -gt 0) { Fail "cleanup failed: $($cleanupErrors -join '; ')" }
}

if (-not $script:TestOnly) { Invoke-Installer }
