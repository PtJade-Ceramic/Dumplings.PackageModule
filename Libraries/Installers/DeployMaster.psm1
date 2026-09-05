# SPDX-License-Identifier: Apache-2.0
# Static DeployMaster parser derived from controlled DeployMaster 7.7 builds,
# validated legacy packages, and the documented installer command-line behavior.
# Reference: https://www.deploymaster.com/manual.html
#
# Binary structure consumed here (absolute offsets and little-endian integers):
#
#   PE image
#   +-- [0x80] package locator
#   |   +-- PackageOffset:u32 -> overlay
#   |   +-- IntegrityLength:u32 and CRC32:u32
#   |   `-- ExpectedFileSize:u64 and Reserved:u32
#   `-- overlay at PackageOffset
#       +-- raw-LZMA properties[5]
#       +-- 70-byte legacy or 74-byte current control header
#       +-- architecture-specific compressed runtime core(s)
#       +-- optional UTF-16 expiration message selected by header date fields
#       +-- language and identity data blocks
#       +-- current package settings and portable-folder block
#       +-- metadata-resident readme, license, and support-DLL records
#       +-- component block and CRLF file-name block
#       +-- parallel file catalog: offsets, sizes, dates, attributes, CRC32
#       +-- install-tree, registry, and file-association blocks
#       +-- prerequisite, completion, uninstall, and update records
#       `-- file payload ranges at absolute catalog offsets
#
#   DataBlock := Size:i32
#     Size == 0  -> empty
#     Size < 0   -> -Size stored bytes
#     Size > 0   -> CompressedSize:i32 + raw-LZMA bytes yielding Size bytes
#
# The CRC covers only the declared integrity range. Undocumented header fields
# remain observed evidence; scope/architecture fields are decoded only for
# controlled layouts whose size and record boundaries validate.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-DeployMasterScopeInfo {
  <#
  .SYNOPSIS
    Convert the DeployMaster package scope byte to WinGet scope evidence
  .NOTES
    Controlled current-user, all-users, and dual-scope builds encode 0, 1,
    and 2 respectively at the normalized package-header scope offset.
  .PARAMETER Value
    Format-specific field or value interpreted according to the current record/version.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(0, 255)][int]$Value)

  switch ($Value) {
    0 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false } }
    1 { [pscustomobject]@{ Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false } }
    2 { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true } }
    default { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false } }
  }
}

function Get-DeployMasterPackageLocator {
  <#
  .SYNOPSIS
    Read and validate the fixed DeployMaster package locator at file offset 0x80
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER MaximumIntegrityBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [ValidateRange(74, [long]::MaxValue)][long]$MaximumIntegrityBytes = 1073741824
  )

  # The locator is a fixed absolute structure in the PE stub. Validate all declared ranges and the
  # complete-file size before hashing or following the package pointer.
  if (-not $Stream.CanSeek -or $Stream.Length -lt 0x98) { throw 'The file is too small for a DeployMaster package locator.' }
  $PackageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset 0x80 -Size 4)
  $IntegrityLength = [long](Read-BinaryInteger -Stream $Stream -Offset 0x84 -Size 4)
  $ExpectedCrc32 = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x88 -Size 4)
  $ExpectedFileSize = [uint64](Read-BinaryInteger -Stream $Stream -Offset 0x8C -Size 8)
  $Reserved = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x94 -Size 4)

  if ($PackageOffset -lt 512 -or $IntegrityLength -lt 70 -or $IntegrityLength -gt $MaximumIntegrityBytes) {
    throw 'The DeployMaster package locator contains invalid range values.'
  }
  if ($PackageOffset + $IntegrityLength -gt $Stream.Length) { throw 'The DeployMaster integrity region is truncated.' }
  if ($ExpectedFileSize -ne [uint64]$Stream.Length) { throw 'The DeployMaster package locator file-size check failed.' }

  # CRC32 authenticates only the declared package-control region, not trailing file payloads.
  $IntegrityStream = New-BoundedReadStream -Stream $Stream -Offset $PackageOffset -Length $IntegrityLength -LeaveOpen
  try { $ActualCrc32 = [uint32](Get-BinaryCrc32 -Stream $IntegrityStream -MaximumBytes $IntegrityLength) }
  finally { $IntegrityStream.Dispose() }
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw 'The DeployMaster package integrity CRC32 check failed.' }

  [pscustomobject]@{
    LocatorOffset     = 0x80L
    PackageOffset     = $PackageOffset
    IntegrityLength   = $IntegrityLength
    PackageDataOffset = $PackageOffset + $IntegrityLength
    ExpectedCrc32     = $ExpectedCrc32
    ActualCrc32       = $ActualCrc32
    ExpectedFileSize  = $ExpectedFileSize
    Reserved          = $Reserved
  }
}

function Get-DeployMasterPackageHeader {
  <#
  .SYNOPSIS
    Normalize legacy and current DeployMaster package-control layouts
  .DESCRIPTION
    Current packages have a 74-byte control header. Older packages omit one
    four-byte platform field and therefore use the same fields shifted by four
    bytes in a 70-byte header. Candidate core ranges select the valid layout.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Locator
    Current structured format node or record being interpreted.
  .PARAMETER MaximumCoreBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Locator,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumCoreBytes = 1073741824
  )

  $Properties = Read-BinaryBytes -Stream $Stream -Offset $Locator.PackageOffset -Count 5
  $DictionarySize = [uint32][BitConverter]::ToUInt32($Properties, 1)
  if ($Properties[0] -gt 224 -or $DictionarySize -lt 65536 -or $DictionarySize -gt 1073741824) {
    throw 'The DeployMaster package has invalid LZMA properties.'
  }

  # Probe both controlled layouts through their range invariants. Never select a generation from
  # PE version strings alone because the four-byte shift changes every following field.
  $Layouts = @(
    [pscustomobject]@{ Name = 'Current'; Shift = 0; HeaderSize = 74; Version = '7.7+' },
    [pscustomobject]@{ Name = 'Legacy'; Shift = -4; HeaderSize = 70; Version = 'Legacy' }
  )
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Layout in $Layouts) {
    $PrimaryOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x16 + $Layout.Shift) -Size 4)
    $PrimaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1A + $Layout.Shift) -Size 4)
    $PrimaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1E + $Layout.Shift) -Size 4)
    $SecondaryOffsetValue = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x22 + $Layout.Shift) -Size 4)
    $SecondaryOffset = [long]$SecondaryOffsetValue
    $SecondaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x26 + $Layout.Shift) -Size 4)
    $SecondaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2A + $Layout.Shift) -Size 4)
    $LanguageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2E + $Layout.Shift) -Size 4)
    $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
    $CoreEntries = [Collections.Generic.List[object]]::new()
    # Core offsets are absolute and must remain within the CRC-protected integrity region.
    if ($PrimaryOffset -ne 0) {
      if ($PrimaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $PrimaryCompressedSize -le 0 -or
        $PrimaryUncompressedSize -le 0 -or $PrimaryUncompressedSize -gt $MaximumCoreBytes -or
        $PrimaryOffset + $PrimaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x86'; Offset = $PrimaryOffset; CompressedSize = $PrimaryCompressedSize; UncompressedSize = $PrimaryUncompressedSize })
    } elseif ($PrimaryCompressedSize -ne 0 -or $PrimaryUncompressedSize -ne 0) { continue }
    if ($SecondaryOffsetValue -notin 0, [uint32]::MaxValue) {
      if ($SecondaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $SecondaryCompressedSize -le 0 -or
        $SecondaryUncompressedSize -le 0 -or $SecondaryUncompressedSize -gt $MaximumCoreBytes -or
        $SecondaryOffset + $SecondaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x64'; Offset = $SecondaryOffset; CompressedSize = $SecondaryCompressedSize; UncompressedSize = $SecondaryUncompressedSize })
    } elseif ($SecondaryCompressedSize -ne 0 -or $SecondaryUncompressedSize -ne 0) { continue }
    if ($CoreEntries.Count -eq 0) { continue }
    $LastCoreEnd = ($CoreEntries | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum
    if ($LanguageOffset -lt $LastCoreEnd -or $LanguageOffset + 8 -gt $IntegrityEnd) { continue }

    $ScopeValue = [int](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x15 + $Layout.Shift) -Size 1)
    if ($ScopeValue -gt 2) { continue }
    $Candidates.Add([pscustomobject]@{
        Layout               = $Layout.Name
        FormatVersion        = $Layout.Version
        HeaderSize           = $Layout.HeaderSize
        ScopeValue           = $ScopeValue
        CoreEntries          = $CoreEntries.ToArray()
        SecondaryOffsetValue = $SecondaryOffsetValue
        LanguageBlockOffset  = $LanguageOffset
      })
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster package-control layout could not be normalized unambiguously.' }

  $Candidate = $Candidates[0]
  $ScopeInfo = Get-DeployMasterScopeInfo -Value $Candidate.ScopeValue
  # Current media compiles either expiration mode into one final calendar date. The adjacent
  # UTF-16 message is stored directly between the runtime core and the normal language text.
  # Both source modes intentionally converge here, so do not infer whether the project used a
  # fixed date or a number of days after the release date.
  $LayoutShift = if ($Candidate.Layout -eq 'Legacy') { -4 } else { 0 }
  $ExpirationYear = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x32 + $LayoutShift) -Size 2)
  $ExpirationMonth = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x34 + $LayoutShift) -Size 2)
  $ExpirationDay = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x36 + $LayoutShift) -Size 2)
  $ExpirationMessageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x38 + $LayoutShift) -Size 4)
  $ExpirationMessageCharacterCount = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x3C + $LayoutShift) -Size 2)
  $ExpirationDate = $null
  $ExpirationMessage = $null
  if ($ExpirationYear -or $ExpirationMonth -or $ExpirationDay -or $ExpirationMessageOffset -or $ExpirationMessageCharacterCount) {
    try { $ExpirationDate = [datetime]::new($ExpirationYear, $ExpirationMonth, $ExpirationDay) }
    catch { throw 'The DeployMaster package contains an invalid compiled expiration date.' }

    $LastCoreEnd = [long](($Candidate.CoreEntries | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum)
    $ExpirationMessageByteCount = [long]$ExpirationMessageCharacterCount * 2
    if ($ExpirationMessageCharacterCount -eq 0 -or $ExpirationMessageOffset -lt $LastCoreEnd -or
      $ExpirationMessageOffset + $ExpirationMessageByteCount -gt $Candidate.LanguageBlockOffset) {
      throw 'The DeployMaster expiration message is outside the bounded pre-language range.'
    }
    $ExpirationMessageBytes = Read-BinaryBytes -Stream $Stream -Offset $ExpirationMessageOffset -Count ([int]$ExpirationMessageByteCount)
    try { $ExpirationMessage = [Text.UnicodeEncoding]::new($false, $false, $true).GetString($ExpirationMessageBytes) }
    catch { throw 'The DeployMaster expiration message is not valid UTF-16LE text.' }
  }
  # The first eight control bytes are a platform bitset. Current builder differentials prove the
  # modern Windows bits below; legacy/unused bits remain available through PlatformFlags.
  $PlatformFlags = [uint64](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 5) -Size 8)
  $SupportedWindowsVersions = [Collections.Generic.List[string]]::new()
  foreach ($Platform in @(
      [pscustomobject]@{ Mask = [uint64]0x0000000000000080; Name = 'Windows7' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000100; Name = 'Windows8' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000200; Name = 'Windows8.1' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000400; Name = 'Windows10' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000800; Name = 'Windows11' }
    )) {
    if ($PlatformFlags -band $Platform.Mask) { $SupportedWindowsVersions.Add($Platform.Name) }
  }
  $PrimaryCore = @($Candidate.CoreEntries | Where-Object Architecture -EQ 'x86' | Select-Object -First 1)
  $SecondaryCore = @($Candidate.CoreEntries | Where-Object Architecture -EQ 'x64' | Select-Object -First 1)
  # A missing x64 core and the x86-only sentinel distinguish OS support from the architecture of
  # the installer stub itself.
  $ApplicationArchitectureMode = if ($PrimaryCore.Count -and $SecondaryCore.Count) {
    'x86AndX64Application'
  } elseif ($SecondaryCore.Count) {
    'x64Application'
  } elseif ($Candidate.SecondaryOffsetValue -eq [uint32]::MaxValue) {
    'x86ApplicationForX86WindowsOnly'
  } else {
    'x86ApplicationForX86AndX64Windows'
  }
  $OperatingSystemArchitectures = switch ($ApplicationArchitectureMode) {
    'x86ApplicationForX86WindowsOnly' { @('x86') }
    'x64Application' { @('x64') }
    default { @('x86', 'x64') }
  }
  $FirstCore = $Candidate.CoreEntries | Select-Object -First 1
  [pscustomobject]@{
    Layout                                = $Candidate.Layout
    FormatVersion                         = $Candidate.FormatVersion
    HeaderSize                            = $Candidate.HeaderSize
    LzmaProperties                        = $Properties
    LzmaPropertyByte                      = [byte]$Properties[0]
    DictionarySize                        = $DictionarySize
    PlatformFlags                         = $PlatformFlags
    SupportedWindowsVersions              = $SupportedWindowsVersions.ToArray()
    SupportsFutureWindowsVersions         = [bool]((Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0C) -Size 1) -band 0x80)
    MinimumWindows10VersionCode           = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0D) -Size 2)
    MaximumWindows10VersionCode           = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0F) -Size 2)
    MinimumWindows11VersionCode           = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x11) -Size 2)
    MaximumWindows11VersionCode           = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x13) -Size 2)
    ExpirationPolicy                      = [pscustomobject]@{
      IsTimeLimited         = $null -ne $ExpirationDate
      ExpirationDate        = $ExpirationDate
      Message               = $ExpirationMessage
      MessageOffset         = $ExpirationMessageOffset
      MessageCharacterCount = $ExpirationMessageCharacterCount
      SourceMode            = if ($ExpirationDate) { 'CompiledFinalDate' } else { $null }
    }
    ScopeValue                            = $Candidate.ScopeValue
    Scope                                 = $ScopeInfo.Scope
    DefaultScope                          = $ScopeInfo.DefaultScope
    SupportedScopes                       = $ScopeInfo.SupportedScopes
    SupportsDualScope                     = $ScopeInfo.SupportsDualScope
    CoreOffset                            = $FirstCore.Offset
    CoreCompressedSize                    = $FirstCore.CompressedSize
    CoreUncompressedSize                  = $FirstCore.UncompressedSize
    CoreEntries                           = $Candidate.CoreEntries
    ApplicationArchitectureMode           = $ApplicationArchitectureMode
    ApplicationArchitectures              = @($Candidate.CoreEntries | Select-Object -ExpandProperty Architecture)
    SupportedOperatingSystemArchitectures = $OperatingSystemArchitectures
    LanguageBlockOffset                   = $Candidate.LanguageBlockOffset
  }
}

function Read-DeployMasterDataBlock {
  <#
  .SYNOPSIS
    Decode one DeployMaster size-prefixed data block.
  .DESCRIPTION
    DeployMaster uses a signed 32-bit size discriminator. Zero represents an empty block, a
    negative value is the stored byte count, and a positive value is the uncompressed size of a
    raw-LZMA stream whose compressed size follows as another signed 32-bit integer.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Limit
    Absolute end offset of the integrity/package region. The complete size-prefixed block must end at or before this boundary.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][long]$Limit,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 16777216
  )

  if ($Offset -lt 0 -or $Offset + 4 -gt $Limit) { throw 'The DeployMaster data-block header is outside the package bounds.' }
  $Size = [long](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4 -Signed)
  if ($Size -eq [int]::MinValue) { throw 'The DeployMaster stored-block size cannot be negated safely.' }

  if ($Size -eq 0) {
    return [pscustomobject]@{
      Offset = $Offset; DataOffset = $Offset + 4; HeaderSize = 4; CompressedSize = 0L
      UncompressedSize = 0L; EndOffset = $Offset + 4; Compression = 'Empty'; Bytes = [byte[]]::new(0)
    }
  }

  if ($Size -lt 0) {
    $StoredSize = - $Size
    if ($StoredSize -gt $MaximumBytes -or $Offset + 4 + $StoredSize -gt $Limit -or $StoredSize -gt [int]::MaxValue) {
      throw 'The DeployMaster stored block contains invalid size values.'
    }
    return [pscustomobject]@{
      Offset = $Offset; DataOffset = $Offset + 4; HeaderSize = 4; CompressedSize = $StoredSize
      UncompressedSize = $StoredSize; EndOffset = $Offset + 4 + $StoredSize; Compression = 'Store'
      Bytes = Read-BinaryBytes -Stream $Stream -Offset ($Offset + 4) -Count ([int]$StoredSize)
    }
  }

  if ($Offset + 8 -gt $Limit) { throw 'The DeployMaster LZMA-block header is truncated.' }
  $UncompressedSize = $Size
  $CompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4 -Signed)
  if ($UncompressedSize -gt $MaximumBytes -or $CompressedSize -le 0 -or $Offset + 8 + $CompressedSize -gt $Limit) {
    throw 'The DeployMaster LZMA block contains invalid size values.'
  }

  # Give the decoder only the declared compressed bytes and require its output to match the record header exactly.
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset ($Offset + 8) -Length $CompressedSize -LeaveOpen
  $OutputStream = [IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
    $Bytes = $OutputStream.ToArray()
  } finally {
    $InputStream.Dispose()
    $OutputStream.Dispose()
  }

  [pscustomobject]@{
    Offset           = $Offset
    DataOffset       = $Offset + 8
    HeaderSize       = 8
    CompressedSize   = $CompressedSize
    UncompressedSize = $UncompressedSize
    EndOffset        = $Offset + 8 + $CompressedSize
    Compression      = 'Lzma'
    Bytes            = $Bytes
  }
}

function ConvertFrom-DeployMasterIdentity {
  <#
  .SYNOPSIS
    Convert the structured DeployMaster identity block to package metadata
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER ScopeValue
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$ScopeValue
  )

  # Form-feed delimiters define the identity schema. Strict UTF-8 prevents replacement characters
  # from silently changing paths or ARP values.
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  try { $Fields = $Utf8.GetString($Bytes).Split([char]12) }
  catch { throw 'The DeployMaster identity block is not valid UTF-8.' }
  if ($Fields.Count -lt 19) { throw 'The DeployMaster identity block is incomplete.' }

  $MachineLocationField = [string]$Fields[11]
  $LocationMarker = if ($MachineLocationField.Length) { [int][char]$MachineLocationField[0] } else { 0 }
  # The first identity-path byte carries the effective registry/install route. Marker 6 is the
  # current-user route with the builder's independent "require admin rights" option enabled; its
  # package-control scope byte is 1, so the identity marker is needed to avoid calling it machine.
  $IdentityScope = switch ($LocationMarker) {
    1 { [pscustomobject]@{ Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false; RequiresAdministrativeRights = $true; RegistryRoot = 'HKLM'; EffectiveScopeValue = 1 } }
    2 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false; RequiresAdministrativeRights = $false; RegistryRoot = 'HKCU'; EffectiveScopeValue = 0 } }
    3 { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true; RequiresAdministrativeRights = $null; RegistryRoot = 'SHCTX'; EffectiveScopeValue = 2 } }
    6 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false; RequiresAdministrativeRights = $true; RegistryRoot = 'HKCU'; EffectiveScopeValue = 0 } }
    default { $null }
  }
  $MachineInstallLocation = if ($IdentityScope) { $MachineLocationField.Substring(1) } else { $MachineLocationField.TrimStart([char]0) }
  $UserInstallLocation = [string]$Fields[12]
  $ReadmeFileName = [string]$Fields[7]
  $RawLicenseFileName = [string]$Fields[8]
  $LicenseRequiredEveryInstall = $RawLicenseFileName.StartsWith('*', [StringComparison]::Ordinal)
  $LicenseFileName = $RawLicenseFileName.TrimStart('*')
  $SupportDll32FileName = [string]$Fields[9]
  $SupportDll64FileName = [string]$Fields[10]
  # Readme, license, and architecture-specific support DLLs are catalogued before ordinary payload
  # names. Deduplicate them because one physical file may also be installed by a component.
  $AuxiliaryFileNames = [Collections.Generic.List[string]]::new()
  $AuxiliaryFileNameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($AuxiliaryFileName in $ReadmeFileName, $LicenseFileName, $SupportDll32FileName, $SupportDll64FileName) {
    if (-not [string]::IsNullOrWhiteSpace($AuxiliaryFileName) -and $AuxiliaryFileNameSet.Add($AuxiliaryFileName)) { $AuxiliaryFileNames.Add($AuxiliaryFileName) }
  }
  $ReleaseDate = $null
  $ReleaseDateValue = 0.0
  # Release dates are stored as OLE Automation dates; invalid values remain absent evidence.
  if ([double]::TryParse([string]$Fields[5], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ReleaseDateValue)) {
    try { $ReleaseDate = [datetime]::FromOADate($ReleaseDateValue).Date } catch {}
  }

  [pscustomobject]@{
    Publisher                    = [string]$Fields[0]
    PublisherUrl                 = [string]$Fields[1]
    DisplayName                  = [string]$Fields[2]
    PackageUrl                   = [string]$Fields[3]
    DisplayVersion               = [string]$Fields[4]
    ReleaseDateValue             = [string]$Fields[5]
    ReleaseDate                  = $ReleaseDate
    Copyright                    = [string]$Fields[6]
    ReadmeFileName               = $ReadmeFileName
    LicenseFileName              = $LicenseFileName
    LicenseRequiredEveryInstall  = $LicenseRequiredEveryInstall
    SupportDll32FileName         = $SupportDll32FileName
    SupportDll64FileName         = $SupportDll64FileName
    AuxiliaryFileNames           = $AuxiliaryFileNames.ToArray()
    MachineInstallLocation       = $MachineInstallLocation
    UserInstallLocation          = $UserInstallLocation
    CommonFilesLocation          = [string]$Fields[13]
    CommonPublisherLocation      = [string]$Fields[14]
    MachineMenuLocation          = [string]$Fields[15]
    UserMenuLocation             = [string]$Fields[16]
    CommonDataLocation           = [string]$Fields[17]
    UserDataLocation             = [string]$Fields[18]
    LocationMarker               = $LocationMarker
    Scope                        = if ($IdentityScope) { $IdentityScope.Scope } else { $null }
    DefaultScope                 = if ($IdentityScope) { $IdentityScope.DefaultScope } else { $null }
    SupportedScopes              = if ($IdentityScope) { $IdentityScope.SupportedScopes } else { @() }
    SupportsDualScope            = if ($IdentityScope) { $IdentityScope.SupportsDualScope } else { $false }
    RequiresAdministrativeRights = if ($IdentityScope) { $IdentityScope.RequiresAdministrativeRights } else { $null }
    RegistryRoot                 = if ($IdentityScope) { $IdentityScope.RegistryRoot } else { $null }
    EffectiveScopeValue          = if ($IdentityScope) { $IdentityScope.EffectiveScopeValue } else { $ScopeValue }
    LocationMarkerMatchesScope   = $IdentityScope -and ($LocationMarker -in @{
        0 = @(2)
        1 = @(1, 6)
        2 = @(3)
      }[$ScopeValue])
    Fields                       = $Fields
  }
}

function Get-DeployMasterFileNameBlock {
  <#
  .SYNOPSIS
    Locate and validate the CRLF-delimited file-name data block before a catalog.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER SearchOffset
    Absolute lower bound for candidate data-block headers.
  .PARAMETER CatalogOffset
    Absolute beginning of the parallel file catalog.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  .PARAMETER ExpectedCount
    Exact number of non-empty names required from the decoded block.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$SearchOffset,
    [Parameter(Mandatory)][long]$CatalogOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateRange(0, 4096)][int]$ExpectedCount
  )

  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Candidates = [Collections.Generic.List[object]]::new()
  for ($Offset = $SearchOffset; $Offset + 4 -le $CatalogOffset; $Offset++) {
    $Size = [long](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4 -Signed)
    if ($Size -eq 0 -or $Size -eq [int]::MinValue) { continue }
    if ($Size -lt 0) { $EndOffset = $Offset + 4 - $Size }
    else {
      if ($Offset + 8 -gt $CatalogOffset -or $Size -gt 1048576) { continue }
      $StoredSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4 -Signed)
      if ($StoredSize -le 0) { continue }
      $EndOffset = $Offset + 8 + $StoredSize
    }
    if ($EndOffset -gt $CatalogOffset -or $CatalogOffset - $EndOffset -gt 16) { continue }
    try {
      $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Offset -Properties $Properties -Limit $CatalogOffset -MaximumBytes 1048576
      $Names = @($Utf8.GetString($Block.Bytes) -split "`r`n" | Where-Object { -not [string]::IsNullOrEmpty($_) })
      if ($Names.Count -ne $ExpectedCount -or $Names | Where-Object { $_ -match '[\x00-\x1F]' }) { continue }
      $Candidates.Add([pscustomobject]@{ Block = $Block; Names = [string[]]$Names; PaddingBytes = $CatalogOffset - $Block.EndOffset })
    } catch {}
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster file-name table could not be decoded unambiguously.' }
  return $Candidates[0]
}

function Get-DeployMasterFileEntry {
  <#
  .SYNOPSIS
    Read the bounded DeployMaster file-offset and size tables
  .DESCRIPTION
    The file table stores a run of absolute offsets followed by parallel raw
    and stored-size arrays. File names immediately precede the arrays; the
    readme, license, and support-DLL file names are carried by the identity block.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Identity
    Installer identity value used to select or report the matching static metadata record.
  .PARAMETER IdentityEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER PackageDataOffset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER TableKind
    Detected format variant controlling version-specific parsing rules.
  .PARAMETER MaximumEntries
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER MaximumMetadataBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Identity,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateSet('Current', 'Legacy')][string]$TableKind,
    [ValidateRange(2, 4096)][int]$MaximumEntries = 4096,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumMetadataBytes = 33554432
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt $MaximumMetadataBytes -or $MetadataLength -gt [int]::MaxValue) {
    throw 'The DeployMaster file-table region is outside the configured bounds.'
  }
  # Search only the bounded metadata gap between identity and package data for parallel offset and
  # size arrays. Structural agreement across all arrays identifies the table.
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Candidates = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index + 48 -le $Metadata.Length; $Index++) {
    $FirstOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index)
    $SecondOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index + 8)
    if ($FirstOffset -lt [uint64]$IdentityEnd -or $SecondOffset -le $FirstOffset -or $SecondOffset -ge [uint64]$Stream.Length) { continue }

    $Boundaries = [Collections.Generic.List[long]]::new()
    $Cursor = $Index
    # Absolute payload offsets form a strictly increasing run terminated by the first non-offset.
    while ($Boundaries.Count -lt $MaximumEntries -and $Cursor + 8 -le $Metadata.Length) {
      $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor)
      if ($Value -lt [uint64]$IdentityEnd -or $Value -ge [uint64]$Stream.Length -or ($Boundaries.Count -and $Value -le [uint64]$Boundaries[$Boundaries.Count - 1])) { break }
      $Boundaries.Add([long]$Value)
      $Cursor += 8
    }
    if ($Boundaries.Count -lt 2 -or $Boundaries -notcontains $PackageDataOffset) { continue }

    # Current tables have one size per boundary; legacy tables prepend a separately located license
    # block and therefore have one additional record.
    foreach ($CandidateTableKind in $TableKind) {
      $EntryCount = if ($CandidateTableKind -eq 'Current') { $Boundaries.Count } else { $Boundaries.Count + 1 }
      # Six parallel catalog columns follow: five UInt64 arrays and one UInt32 CRC32 array.
      $SerializedTableSize = (8 * $Boundaries.Count) + (36 * $EntryCount)
      if ($EntryCount -gt $MaximumEntries -or $Index + $SerializedTableSize -gt $Metadata.Length) { continue }
      $RawSizes = [Collections.Generic.List[long]]::new()
      $StoredSizes = [Collections.Generic.List[long]]::new()
      $Valid = $true
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor + (8 * $EntryIndex))
        if ($Value -eq 0 -or $Value -gt [uint64][long]::MaxValue) { $Valid = $false; break }
        $RawSizes.Add([long]$Value)
      }
      if (-not $Valid) { continue }
      $StoredSizeOffset = $Cursor + (8 * $EntryCount)
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        $Value = [uint64][BitConverter]::ToUInt64($Metadata, $StoredSizeOffset + (8 * $EntryIndex))
        if ($Value -eq 0 -or $Value -gt [uint64]$RawSizes[$EntryIndex]) { $Valid = $false; break }
        $StoredSizes.Add([long]$Value)
      }
      if (-not $Valid) { continue }

      $Offsets = [Collections.Generic.List[long]]::new()
      if ($CandidateTableKind -eq 'Current') {
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
      } else {
        # Legacy packages keep the mandatory license block before the file
        # boundary table as [stored-size][raw-size][raw LZMA bytes].
        $LicenseOffsets = [Collections.Generic.List[long]]::new()
        for ($LicenseHeader = 0; $LicenseHeader + 8 + $StoredSizes[0] -le $Index; $LicenseHeader++) {
          if ([BitConverter]::ToUInt32($Metadata, $LicenseHeader) -eq $StoredSizes[0] -and
            [BitConverter]::ToUInt32($Metadata, $LicenseHeader + 4) -eq $RawSizes[0]) {
            $LicenseOffsets.Add($IdentityEnd + $LicenseHeader + 8)
          }
        }
        if ($LicenseOffsets.Count -ne 1) { continue }
        $Offsets.Add($LicenseOffsets[0])
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
      }
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        if ($Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Stream.Length) { $Valid = $false; break }
      }
      if ($Valid) {
        $TimestampOffset = $StoredSizeOffset + (8 * $EntryCount)
        $AttributeOffset = $TimestampOffset + (8 * $EntryCount)
        $CrcOffset = $AttributeOffset + (8 * $EntryCount)
        $Timestamps = [Collections.Generic.List[uint64]]::new()
        $Attributes = [Collections.Generic.List[uint64]]::new()
        $Crc32 = [Collections.Generic.List[uint32]]::new()
        for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
          $Timestamps.Add([BitConverter]::ToUInt64($Metadata, $TimestampOffset + (8 * $EntryIndex)))
          $Attributes.Add([BitConverter]::ToUInt64($Metadata, $AttributeOffset + (8 * $EntryIndex)))
          $Crc32.Add([BitConverter]::ToUInt32($Metadata, $CrcOffset + (4 * $EntryIndex)))
        }
        $Candidates.Add([pscustomobject]@{
            TableKind       = $CandidateTableKind
            TableOffset     = $Index
            TableEndOffset  = $CrcOffset + (4 * $EntryCount)
            Offsets         = $Offsets.ToArray()
            RawSizes        = $RawSizes.ToArray()
            StoredSizes     = $StoredSizes.ToArray()
            TimestampValues = $Timestamps.ToArray()
            AttributeValues = $Attributes.ToArray()
            Crc32Values     = $Crc32.ToArray()
          })
      }
    }
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster file table could not be located unambiguously.' }

  $Candidate = $Candidates[0]
  $Names = [Collections.Generic.List[string]]::new()
  foreach ($AuxiliaryFileName in $Identity.AuxiliaryFileNames) { $Names.Add($AuxiliaryFileName) }
  $RemainingNameCount = $Candidate.Offsets.Count - $Names.Count
  # The CRLF-delimited name list is always one stored or LZMA data block ending exactly where the
  # parallel catalog begins. Legacy output may retain up to 16 bytes of alignment/reserved padding.
  $NameResult = Get-DeployMasterFileNameBlock -Stream $Stream -SearchOffset ([Math]::Max($IdentityEnd, $IdentityEnd + $Candidate.TableOffset - 1048576)) -CatalogOffset ($IdentityEnd + $Candidate.TableOffset) -Properties $Properties -ExpectedCount $RemainingNameCount
  $NameBlock = $NameResult.Block
  $PayloadNames = $NameResult.Names
  foreach ($PayloadName in $PayloadNames) { $Names.Add($PayloadName) }
  if ($Names.Count -ne $Candidate.Offsets.Count) { throw 'The DeployMaster file-name and offset table counts differ.' }

  for ($EntryIndex = 0; $EntryIndex -lt $Names.Count; $EntryIndex++) {
    try { $Timestamp = [datetime]::FromOADate([BitConverter]::Int64BitsToDouble([int64]$Candidate.TimestampValues[$EntryIndex])) }
    catch { $Timestamp = $null }
    [pscustomobject]@{
      Index            = $EntryIndex
      Name             = $Names[$EntryIndex]
      FullName         = $Names[$EntryIndex]
      Offset           = $Candidate.Offsets[$EntryIndex]
      CompressedSize   = $Candidate.StoredSizes[$EntryIndex]
      UncompressedSize = $Candidate.RawSizes[$EntryIndex]
      Compression      = if ($Candidate.StoredSizes[$EntryIndex] -eq $Candidate.RawSizes[$EntryIndex]) { 'Store' } else { 'Lzma' }
      TimestampValue   = $Candidate.TimestampValues[$EntryIndex]
      Timestamp        = $Timestamp
      AttributeValue   = $Candidate.AttributeValues[$EntryIndex]
      Crc32            = $Candidate.Crc32Values[$EntryIndex]
      CatalogOffset    = $IdentityEnd + $Candidate.TableOffset
      CatalogEndOffset = $IdentityEnd + $Candidate.TableEndOffset
      NameBlockOffset  = $NameBlock.Offset
    }
  }
}

function Read-DeployMasterStreamString {
  <#
  .SYNOPSIS
    Read one UInt16-length-prefixed UTF-8 string from a bounded metadata stream.
  .PARAMETER Stream
    Caller-owned sequential stream. The current position advances across the encoded string.
  .PARAMETER MaximumBytes
    Maximum encoded UTF-8 byte length accepted for one string.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [ValidateRange(0, 65535)][int]$MaximumBytes = 65535
  )

  $Length = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
  if ($Length -gt $MaximumBytes -or $Stream.Position + $Length -gt $Stream.Length) { throw 'The DeployMaster metadata string is outside its containing block.' }
  if ($Length -eq 0) { return '' }
  $Bytes = [byte[]]::new($Length)
  $Read = $Stream.Read($Bytes, 0, $Length)
  if ($Read -ne $Length) { throw 'The DeployMaster metadata string is truncated.' }
  try { return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
  catch { throw 'The DeployMaster metadata string is not valid UTF-8.' }
}

function ConvertFrom-DeployMasterComponentBlock {
  <#
  .SYNOPSIS
    Decode the component catalog stored before the file-name catalog.
  .PARAMETER Bytes
    Decompressed component data. The input is bounded by its enclosing DeployMaster data block.
  .PARAMETER MaximumComponents
    Maximum number of component records accepted.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateRange(1, 255)][int]$MaximumComponents = 255
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Components = [Collections.Generic.List[object]]::new()
  try {
    if ($Stream.Length -lt 1) { throw 'The DeployMaster component catalog is empty.' }
    $Count = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    if ($Count -gt $MaximumComponents) { throw 'The DeployMaster component count exceeds the configured limit.' }
    for ($Index = 0; $Index -lt $Count; $Index++) {
      $Name = Read-DeployMasterStreamString -Stream $Stream
      $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      $RequirementCount = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($RequirementCount -gt $Count -or $Stream.Position + $RequirementCount -gt $Stream.Length) { throw 'The DeployMaster component requirement list is invalid.' }
      $Requirements = [byte[]]::new($RequirementCount)
      if ($RequirementCount -and $Stream.Read($Requirements, 0, $RequirementCount) -ne $RequirementCount) { throw 'The DeployMaster component requirement list is truncated.' }
      if ($Requirements | Where-Object { $_ -ge $Count }) { throw 'The DeployMaster component requirement index is outside the component catalog.' }
      $Components.Add([pscustomobject]@{
          Index            = $Index
          Name             = $Name
          InstallByDefault = [bool]($Flags -band 2)
          UserSelectable   = [bool]($Flags -band 1)
          Flags            = $Flags
          Requires         = [int[]]$Requirements
          Description      = Read-DeployMasterStreamString -Stream $Stream
        })
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster component catalog contains trailing data.' }
  } finally { $Stream.Dispose() }
  return $Components.ToArray()
}

function ConvertFrom-DeployMasterInstallTreeBlock {
  <#
  .SYNOPSIS
    Decode component destination trees, installed files, shortcuts, and URL shortcuts.
  .PARAMETER Bytes
    Decompressed install-tree stream shared by all components in catalog order.
  .PARAMETER Components
    Parsed component records controlling the number and identity of root trees.
  .PARAMETER FileEntries
    Parsed file catalog used to resolve file and executable indexes.
  .PARAMETER MaximumDepth
    Maximum recursive destination-folder depth.
  .PARAMETER MaximumItems
    Maximum total folder and item records accepted.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [ValidateRange(1, 128)][int]$MaximumDepth = 32,
    [ValidateRange(1, 1048576)][int]$MaximumItems = 65536
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Folders = [Collections.Generic.List[object]]::new()
  $Files = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()
  $ItemCount = 0

  function ReadTree([string]$ParentPath, [int]$ComponentIndex, [int]$Depth) {
    if ($Depth -gt $MaximumDepth) { throw 'The DeployMaster install-tree depth exceeds the configured limit.' }
    $Marker = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    while ($Marker -lt 0xFE) {
      $ItemCount++
      if ($ItemCount -gt $MaximumItems) { throw 'The DeployMaster install-tree item count exceeds the configured limit.' }
      $CharacterCount = [int]$Marker
      $ByteCount = 2 * $CharacterCount
      if ($Stream.Position + $ByteCount + 1 -gt $Stream.Length) { throw 'The DeployMaster destination-folder record is truncated.' }
      $NameBytes = [byte[]]::new($ByteCount)
      if ($ByteCount -and $Stream.Read($NameBytes, 0, $ByteCount) -ne $ByteCount) { throw 'The DeployMaster destination-folder name is truncated.' }
      $Name = [Text.Encoding]::Unicode.GetString($NameBytes)
      $CreateIfEmpty = [bool](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      $FullPath = [string]::IsNullOrEmpty($ParentPath) ? $Name : "$($ParentPath.TrimEnd('\'))\$Name"
      $Folders.Add([pscustomobject]@{ ComponentIndex = $ComponentIndex; Name = $Name; FullName = $FullPath; CreateIfEmpty = $CreateIfEmpty })
      ReadTree -ParentPath $FullPath -ComponentIndex $ComponentIndex -Depth ($Depth + 1)
      $Marker = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    }
    if ($Marker -eq 0xFF) { return }
    if ($Marker -ne 0xFE) { throw "Unsupported DeployMaster install-tree marker 0x$($Marker.ToString('X2'))." }

    $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    while ($Opcode -ne 0xFF) {
      $ItemCount++
      if ($ItemCount -gt $MaximumItems) { throw 'The DeployMaster install-tree item count exceeds the configured limit.' }
      switch ($Opcode -band 0xF0) {
        0x80 {
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The DeployMaster install-tree file index is outside the file catalog.' }
          $OptionalArgument = ($Flags -band 0x10) ? (Read-DeployMasterStreamString -Stream $Stream) : $null
          $Entry = $FileEntries[$FileIndex]
          $InstalledPath = [string]::IsNullOrEmpty($ParentPath) ? $Entry.Name : "$($ParentPath.TrimEnd('\'))\$($Entry.Name)"
          $Files.Add([pscustomobject]@{
              ComponentIndex   = $ComponentIndex
              DestinationPath  = $InstalledPath
              Directory        = $ParentPath
              FileIndex        = $FileIndex
              SourceName       = $Entry.Name
              Included         = [bool]($Flags -band 1)
              FileAction       = [int]($Opcode -band 3)
              OpcodeFlags      = [byte]($Opcode -band 0x0F)
              Flags            = $Flags
              OptionalArgument = $OptionalArgument
            })
        }
        0x40 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The DeployMaster shortcut file index is outside the file catalog.' }
          $Values = @(
            Read-DeployMasterStreamString -Stream $Stream
            Read-DeployMasterStreamString -Stream $Stream
            Read-DeployMasterStreamString -Stream $Stream
          )
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $Shortcuts.Add([pscustomobject]@{
              ComponentIndex = $ComponentIndex; Directory = $ParentPath; TargetFileIndex = $FileIndex
              TargetFile = $FileEntries[$FileIndex].Name; Values = $Values; Flags = [byte]($Flags -band 0x0F)
              Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 3)
            })
        }
        0x20 {
          $Name = Read-DeployMasterStreamString -Stream $Stream
          $Url = Read-DeployMasterStreamString -Stream $Stream
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $UrlShortcuts.Add([pscustomobject]@{
              ComponentIndex = $ComponentIndex; Directory = $ParentPath; Name = $Name; Url = $Url
              Flags = [byte]($Flags -band 0x0F); Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 3)
            })
        }
        default { throw "Unsupported DeployMaster install-tree opcode 0x$($Opcode.ToString('X2'))." }
      }
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    }
  }

  try {
    for ($ComponentIndex = 0; $ComponentIndex -lt $Components.Count; $ComponentIndex++) {
      ReadTree -ParentPath '' -ComponentIndex $ComponentIndex -Depth 0
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster install-tree stream contains trailing data.' }
  } finally { $Stream.Dispose() }
  return [pscustomobject]@{
    Folders = $Folders.ToArray(); Files = $Files.ToArray(); Shortcuts = $Shortcuts.ToArray(); UrlShortcuts = $UrlShortcuts.ToArray()
  }
}

function ConvertFrom-DeployMasterRegistryBlock {
  <#
  .SYNOPSIS
    Decode DeployMaster's recursive registry operation stream.
  .PARAMETER Bytes
    Decompressed registry operation data.
  .PARAMETER ScopeValue
    Package scope byte used to resolve the virtual HKEY_AUTO root.
  .PARAMETER MaximumDepth
    Maximum nested registry-key depth.
  .PARAMETER MaximumOperations
    Maximum opcode count accepted across all roots.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, 255)][int]$ScopeValue,
    [ValidateRange(1, 128)][int]$MaximumDepth = 64,
    [ValidateRange(1, 1048576)][int]$MaximumOperations = 65536
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Writes = [Collections.Generic.List[object]]::new()
  $DeletedKeys = [Collections.Generic.List[object]]::new()
  $OperationCount = 0

  function ReadBranch([string]$Root, [string]$Key, [int]$Depth) {
    if ($Depth -gt $MaximumDepth) { throw 'The DeployMaster registry-tree depth exceeds the configured limit.' }
    $ValueName = ''
    $KeepExisting = $false
    while ($true) {
      $OperationCount++
      if ($OperationCount -gt $MaximumOperations) { throw 'The DeployMaster registry operation count exceeds the configured limit.' }
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      switch ($Opcode) {
        0x01 {
          $Child = Read-DeployMasterStreamString -Stream $Stream
          $ChildKey = [string]::IsNullOrEmpty($Key) ? $Child : "$($Key.TrimEnd('\'))\$Child"
          ReadBranch -Root $Root -Key $ChildKey -Depth ($Depth + 1)
        }
        0x02 { $DeletedKeys.Add([pscustomobject]@{ Root = $Root; Key = $Key; Evidence = 'DeployMaster delete-key-on-uninstall opcode' }) }
        0x03 { $ValueName = ''; $KeepExisting = $false }
        0x04 { $ValueName = Read-DeployMasterStreamString -Stream $Stream; $KeepExisting = $false }
        0x05 { $KeepExisting = $true }
        0x06 { }
        0x07 {
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = Read-DeployMasterStreamString -Stream $Stream; Type = 'REG_SZ'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0x08 {
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = [uint32](Read-BinarySequentialInteger -Stream $Stream -Size 4); Type = 'REG_DWORD'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0x09 {
          $Length = [long](Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed)
          if ($Length -lt 0 -or $Length -gt 16777216 -or $Stream.Position + $Length -gt $Stream.Length) { throw 'The DeployMaster binary registry value has an invalid size.' }
          $Value = [byte[]]::new([int]$Length)
          if ($Length -and $Stream.Read($Value, 0, [int]$Length) -ne $Length) { throw 'The DeployMaster binary registry value is truncated.' }
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = $Value; Type = 'REG_BINARY'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0xFF { return }
        default { throw "Unsupported DeployMaster registry opcode 0x$($Opcode.ToString('X2'))." }
      }
    }
  }

  try {
    while ($Stream.Position -lt $Stream.Length) {
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($Opcode -ne 1) { break }
      $EncodedRoot = Read-DeployMasterStreamString -Stream $Stream
      $Root = switch ($EncodedRoot) {
        'HKEY_AUTO' { switch ($ScopeValue) { 0 { 'HKCU' } 1 { 'HKLM' } default { 'SHCTX' } } }
        'HKEY_CLASSES_ROOT' { 'HKCR' }
        'HKEY_CURRENT_USER' { 'HKCU' }
        'HKEY_LOCAL_MACHINE' { 'HKLM' }
        'HKEY_USERS' { 'HKU' }
        default { throw "Unsupported DeployMaster registry root '$EncodedRoot'." }
      }
      ReadBranch -Root $Root -Key '' -Depth 0
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster registry operation stream contains trailing data.' }
  } finally { $Stream.Dispose() }
  return [pscustomobject]@{ RegistryWrites = $Writes.ToArray(); DeletedKeys = $DeletedKeys.ToArray() }
}

function ConvertFrom-DeployMasterTextBlock {
  <#
  .SYNOPSIS
    Decode a bounded DeployMaster compressed-string payload without guessing field semantics.
  .PARAMETER Bytes
    Stored or decompressed string bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) { return [pscustomobject]@{ Text = ''; Fields = [string[]]@(); Encoding = 'Empty' } }
  $EncodingName = 'UTF-8'
  try {
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
      $Text = [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
      $EncodingName = 'UTF-16LE'
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
      $Text = [Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
      $EncodingName = 'UTF-16BE'
    } elseif (($Bytes | Where-Object { $_ -eq 0 }).Count -gt [Math]::Floor($Bytes.Length / 4)) {
      $Text = [Text.Encoding]::Unicode.GetString($Bytes)
      $EncodingName = 'UTF-16LE'
    } else {
      $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    }
  } catch { throw 'The DeployMaster compressed-string payload has an invalid text encoding.' }
  return [pscustomobject]@{
    Text     = $Text.TrimEnd([char]0)
    # DeployMaster uses bare CR separators in prerequisite descriptors and CRLF in file-name
    # catalogs. Preserve empty positional fields while accepting every documented line ending.
    Fields   = [string[]]@($Text.TrimEnd([char]0) -split "`r`n|`r|`n")
    Encoding = $EncodingName
  }
}

function ConvertFrom-DeployMasterDotNetFrameworkRecord {
  <#
  .SYNOPSIS
    Project the DeployMaster .NET Framework bitmask and descriptor into named prerequisite evidence.
  .PARAMETER Flags
    Builder compatibility bitmask. Bits 0 through 4 represent .NET Framework 1.0, 1.1, 2.0, 3.0,
    and 3.5; bit 5 enables the 4.x family.
  .PARAMETER VersionCode
    Minimum .NET Framework 4.x version selector used when bit 5 is set.
  .PARAMETER Descriptor
    Decoded CR-delimited descriptor block. Field 0 is an optional framework installer filename and
    field 1 is the fallback download URL.
  .PARAMETER RawValues
    Sixteen observed bytes following the descriptor. Their semantics are not assigned until a
    controlled builder differential proves them.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte]$Flags,
    [Parameter(Mandatory)][byte]$VersionCode,
    [Parameter(Mandatory)][psobject]$Descriptor,
    [Parameter(Mandatory)][byte[]]$RawValues
  )

  $VersionBits = [ordered]@{
    0x01 = '1.0'
    0x02 = '1.1'
    0x04 = '2.0'
    0x08 = '3.0'
    0x10 = '3.5'
  }
  $CompatibleVersions = [Collections.Generic.List[string]]::new()
  foreach ($Pair in $VersionBits.GetEnumerator()) {
    if ($Flags -band [byte]$Pair.Key) { $CompatibleVersions.Add([string]$Pair.Value) }
  }

  $Minimum4xVersion = $null
  if ($Flags -band 0x20) {
    $Minimum4xVersion = @('4.0', '4.5', '4.5.1', '4.5.2', '4.6', '4.6.1', '4.6.2', '4.7', '4.7.1', '4.7.2', '4.8', '4.8.1')[$VersionCode]
    if ($null -ne $Minimum4xVersion) { $CompatibleVersions.Add("$Minimum4xVersion+") }
  }

  $DescriptorFields = [string[]]@($Descriptor.Fields)
  $InstallerFileName = if ($DescriptorFields.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($DescriptorFields[0])) { $DescriptorFields[0] } else { $null }
  $DownloadUrl = if ($DescriptorFields.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($DescriptorFields[1])) { $DescriptorFields[1] } else { $null }
  return [pscustomobject]@{
    Kind                  = 'DotNetFramework'
    Flags                 = $Flags
    CompatibleVersions    = $CompatibleVersions.ToArray()
    Requires4x            = [bool]($Flags -band 0x20)
    Minimum4xVersion      = $Minimum4xVersion
    VersionCode           = $VersionCode
    InstallerFileName     = $InstallerFileName
    HasAutomaticInstaller = -not [string]::IsNullOrWhiteSpace($InstallerFileName)
    DownloadUrl           = $DownloadUrl
    Descriptor            = $Descriptor.Text
    DescriptorFields      = $DescriptorFields
    UnknownFlags          = [byte]($Flags -band 0xC0)
    RawValues             = $RawValues
  }
}

function Read-DeployMasterTrailingMetadata {
  <#
  .SYNOPSIS
    Decode prerequisite, completion, launch, uninstall, and update records after file associations.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Offset
    Absolute first byte after the file-association data block.
  .PARAMETER Limit
    Absolute package-data boundary; all trailing records must end exactly here.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Limit,
    [Parameter(Mandatory)][byte[]]$Properties
  )

  function ReadTextBlock([ref]$Cursor) {
    $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Cursor.Value -Properties $Properties -Limit $Limit -MaximumBytes 4194304
    $Cursor.Value = $Block.EndOffset
    $Text = ConvertFrom-DeployMasterTextBlock -Bytes $Block.Bytes
    return [pscustomobject]@{ Block = $Block; Text = $Text.Text; Fields = $Text.Fields; Encoding = $Text.Encoding }
  }
  function ReadInteger([ref]$Cursor, [int]$Size, [switch]$Signed) {
    if ($Cursor.Value + $Size -gt $Limit) { throw 'The DeployMaster trailing metadata is truncated.' }
    $Value = Read-BinaryInteger -Stream $Stream -Offset $Cursor.Value -Size $Size -Signed:$Signed
    $Cursor.Value += $Size
    return $Value
  }
  function ConvertToTextList([AllowNull()][psobject]$Record) {
    if ($null -eq $Record) { return [string[]]@() }
    # The builder accepts semicolon-separated values in each UI line. Normalize both delimiters
    # while retaining the original text block below for exact format evidence.
    return [string[]]@($Record.Fields | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }

  $Cursor = $Offset
  $Prerequisites = [Collections.Generic.List[object]]::new()
  $FrameworkFlags = [byte](ReadInteger -Cursor ([ref]$Cursor) -Size 1)
  $Framework = $null
  if ($FrameworkFlags) {
    $FrameworkVersionCode = [byte](ReadInteger -Cursor ([ref]$Cursor) -Size 1)
    $Descriptor = ReadTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster .NET prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Framework = ConvertFrom-DeployMasterDotNetFrameworkRecord -Flags $FrameworkFlags -VersionCode $FrameworkVersionCode -Descriptor $Descriptor -RawValues $RawValues
    $Prerequisites.Add($Framework)
  }

  $CustomCount = [long](ReadInteger -Cursor ([ref]$Cursor) -Size 4 -Signed)
  if ($CustomCount -lt 0 -or $CustomCount -gt 256) { throw 'The DeployMaster custom prerequisite count is invalid.' }
  for ($Index = 0; $Index -lt $CustomCount; $Index++) {
    $Descriptor = ReadTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster custom prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Prerequisites.Add([pscustomobject]@{
        Kind = 'Custom'; Index = $Index; Descriptor = $Descriptor.Text
        DescriptorFields = $Descriptor.Fields; RawValues = $RawValues
      })
  }

  # Completion flags are followed by optional architecture-specific launch indexes and arguments.
  $CompletionFlags = [byte](ReadInteger -Cursor ([ref]$Cursor) -Size 1)
  $Launch32FileIndex = if ($CompletionFlags -band 4) { [int](ReadInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $Launch64FileIndex = if ($CompletionFlags -band 8) { [int](ReadInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $LaunchArguments = (($CompletionFlags -band 0x0C) -ne 0) ? (ReadTextBlock -Cursor ([ref]$Cursor)).Text : $null

  $PreUninstall32FileIndex = [int16](ReadInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  $PreUninstall64FileIndex = [int16](ReadInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  $PreUninstallArguments = ($PreUninstall32FileIndex -ne -1 -or $PreUninstall64FileIndex -ne -1) ? (ReadTextBlock -Cursor ([ref]$Cursor)).Text : $null
  $UninstallShortcutFlags = [byte](ReadInteger -Cursor ([ref]$Cursor) -Size 1)
  $UninstallShortcutReferenceValue = [uint16](ReadInteger -Cursor ([ref]$Cursor) -Size 2)
  $UninstallShortcutReference = if ($UninstallShortcutReferenceValue -eq [uint16]::MaxValue) { $null } else { [int]$UninstallShortcutReferenceValue }

  # The final three-byte update header gates up to three following compressed-string records.
  $UpdateFlags = [byte](ReadInteger -Cursor ([ref]$Cursor) -Size 1)
  $RequiredReleaseDay = [uint16](ReadInteger -Cursor ([ref]$Cursor) -Size 2)
  $PatchRequirement = ($UpdateFlags -band 2) ? (ReadTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowClasses = ($UpdateFlags -band 4) ? (ReadTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowCaptions = ($UpdateFlags -band 8) ? (ReadTextBlock -Cursor ([ref]$Cursor)) : $null
  if ($Cursor -ne $Limit) { throw 'The DeployMaster trailing metadata contains unsupported or trailing records.' }

  return [pscustomobject]@{
    Prerequisites   = $Prerequisites.ToArray()
    DotNetFramework = $Framework
    Completion      = [pscustomobject]@{
      Flags               = $CompletionFlags
      ShowMessage         = [bool]($CompletionFlags -band 0x80)
      PromptForReboot     = [bool]($CompletionFlags -band 0x40)
      ShowStartMenuFolder = [bool]($CompletionFlags -band 0x02)
      Launch32FileIndex   = $Launch32FileIndex
      Launch64FileIndex   = $Launch64FileIndex
      LaunchArguments     = $LaunchArguments
    }
    Uninstall       = [pscustomobject]@{
      PreUninstall32FileIndex = $PreUninstall32FileIndex
      PreUninstall64FileIndex = $PreUninstall64FileIndex
      PreUninstallArguments   = $PreUninstallArguments
      ShortcutFlags           = $UninstallShortcutFlags
      CreateStartMenuShortcut = [bool]($UninstallShortcutFlags -band 1)
      ShortcutReference       = $UninstallShortcutReference
      ShortcutReferenceValue  = $UninstallShortcutReferenceValue
    }
    Update          = [pscustomobject]@{
      Flags                   = $UpdateFlags
      DeleteObsoleteFiles     = [bool]($UpdateFlags -band 1)
      IsPatchPackage          = [bool]($UpdateFlags -band 2)
      RequiresPreviousRelease = [bool]($UpdateFlags -band 2)
      RequiredReleaseDay      = $RequiredReleaseDay
      RequiredReleaseDate     = if (($UpdateFlags -band 2) -and $RequiredReleaseDay) { [datetime]::FromOADate($RequiredReleaseDay).Date } else { $null }
      PatchRequirement        = $PatchRequirement?.Text
      PatchRequirementLines   = ConvertToTextList -Record $PatchRequirement
      BlockedWindowClasses    = ConvertToTextList -Record $BlockedWindowClasses
      BlockedWindowCaptions   = ConvertToTextList -Record $BlockedWindowCaptions
      RawRecords              = [pscustomobject]@{
        PatchRequirement      = $PatchRequirement
        BlockedWindowClasses  = $BlockedWindowClasses
        BlockedWindowCaptions = $BlockedWindowCaptions
      }
    }
  }
}

function Read-DeployMasterStructuredMetadata {
  <#
  .SYNOPSIS
    Follow the exact current DeployMaster metadata record order after catalog discovery.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Header
    Normalized DeployMaster control header.
  .PARAMETER Locator
    Validated fixed package locator.
  .PARAMETER IdentityEnd
    Absolute end of the identity data block.
  .PARAMETER FileEntries
    File catalog carrying exact catalog, name-block, and payload boundaries.
  .PARAMETER ScopeValue
    Effective registry scope after combining the package-control scope byte with the identity route.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Header,
    [Parameter(Mandatory)][psobject]$Locator,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][ValidateRange(0, 2)][int]$ScopeValue
  )

  if ($FileEntries.Count -eq 0) { throw 'The DeployMaster structured metadata requires a decoded file catalog.' }
  $NameBlockOffset = [long]$FileEntries[0].NameBlockOffset
  $MetadataResidentFiles = @($FileEntries | Where-Object { $_.Offset -lt $NameBlockOffset })
  if ($MetadataResidentFiles.Count -eq 0) { throw 'The DeployMaster component block boundary could not be derived from the metadata-resident file records.' }
  $ComponentOffset = [long](($MetadataResidentFiles | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum)
  $ComponentBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $ComponentOffset -Properties $Header.LzmaProperties -Limit $NameBlockOffset -MaximumBytes 4194304
  if ($ComponentBlock.EndOffset -ne $NameBlockOffset) { throw 'The DeployMaster component block is not adjacent to the file-name catalog.' }
  $Components = @(ConvertFrom-DeployMasterComponentBlock -Bytes $ComponentBlock.Bytes)

  $InstallTreeBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ([long]$FileEntries[0].CatalogEndOffset) -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $InstallTree = ConvertFrom-DeployMasterInstallTreeBlock -Bytes $InstallTreeBlock.Bytes -Components $Components -FileEntries $FileEntries
  $RegistryBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $InstallTreeBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $Registry = if ($RegistryBlock.Bytes.Length) { ConvertFrom-DeployMasterRegistryBlock -Bytes $RegistryBlock.Bytes -ScopeValue $ScopeValue } else { [pscustomobject]@{ RegistryWrites = @(); DeletedKeys = @() } }
  $AssociationBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $RegistryBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 4194304
  $FileAssociations = if ($AssociationBlock.Bytes.Length) { @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $AssociationBlock.Bytes) } else { @() }
  $Trailing = Read-DeployMasterTrailingMetadata -Stream $Stream -Offset $AssociationBlock.EndOffset -Limit $Locator.PackageDataOffset -Properties $Header.LzmaProperties

  return [pscustomobject]@{
    ComponentBlock = $ComponentBlock; Components = $Components
    InstallTreeBlock = $InstallTreeBlock; InstallTree = $InstallTree
    RegistryBlock = $RegistryBlock; Registry = $Registry
    AssociationBlock = $AssociationBlock; FileAssociations = $FileAssociations
    TrailingMetadata = $Trailing
  }
}

function ConvertFrom-DeployMasterFileAssociationBlock {
  <#
  .SYNOPSIS
    Parse a structured DeployMaster file-type metadata record
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  # The block begins with a bounded association count followed by sequential
  # variable-length records. Any trailing or truncated data rejects the block.
  if ($Bytes.Length -lt 2) { throw 'The DeployMaster file-type record is too small.' }
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Cursor = 0
  $Count = [int]$Bytes[$Cursor++]
  if ($Count -lt 1 -or $Count -gt 64) { throw 'The DeployMaster file-type count is invalid.' }

  function ReadAssociationUInt16([ref]$Position) {
    <#
    .SYNOPSIS
      Read a sequential unsigned 16-bit little-endian association field.
    .PARAMETER Position
      Mutable block-relative byte cursor advanced by two after a bounded read.
    #>
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [uint16][BitConverter]::ToUInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function ReadAssociationInt16([ref]$Position) {
    <#
    .SYNOPSIS
      Read a sequential signed 16-bit little-endian association field.
    .PARAMETER Position
      Mutable block-relative byte cursor advanced by two after a bounded read.
    #>
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [int16][BitConverter]::ToInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function ReadAssociationString([ref]$Position) {
    <#
    .SYNOPSIS
      Read a uint16-length-prefixed UTF-8 association string.
    .PARAMETER Position
      Mutable block-relative cursor advanced across the length field and string bytes.
    #>
    $Length = [int](ReadAssociationUInt16 -Position $Position)
    if ($Position.Value + $Length -gt $Bytes.Length) { throw 'The DeployMaster file-type string is truncated.' }
    $Value = $Utf8.GetString($Bytes, $Position.Value, $Length)
    $Position.Value += $Length
    return $Value
  }

  $Associations = [Collections.Generic.List[object]]::new()
  # Each association contains architecture-specific icon references and a nested
  # action list. Preserve file indexes for later catalog resolution.
  for ($AssociationIndex = 0; $AssociationIndex -lt $Count; $AssociationIndex++) {
    if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -notin 0, 1) { throw 'The DeployMaster file-type default flag is invalid.' }
    $CreateByDefault = [bool]$Bytes[$Cursor++]
    $Description = ReadAssociationString -Position ([ref]$Cursor)
    $Extension = ReadAssociationString -Position ([ref]$Cursor)
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') { throw 'The DeployMaster file-type extension is invalid.' }
    $Icon32FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 32-bit icon record is truncated.' }
    $Icon32ResourceIndex = [int]$Bytes[$Cursor++]
    $Icon64FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 64-bit icon record is truncated.' }
    $Icon64ResourceIndex = [int]$Bytes[$Cursor++]
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster file-type action count is missing.' }
    $ActionCount = [int]$Bytes[$Cursor++]
    if ($ActionCount -gt 64) { throw 'The DeployMaster file-type action count is invalid.' }
    $Actions = [Collections.Generic.List[object]]::new()
    # Actions carry separate x86/x64 executable indexes plus literal parameters;
    # parsing records them as evidence and never invokes the commands.
    for ($ActionIndex = 0; $ActionIndex -lt $ActionCount; $ActionIndex++) {
      $Actions.Add([pscustomobject]@{
          Name                  = ReadAssociationString -Position ([ref]$Cursor)
          Executable32FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
          Executable64FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
          Parameters            = ReadAssociationString -Position ([ref]$Cursor)
        })
    }
    $Associations.Add([pscustomobject]@{
        Extension           = $Extension.ToLowerInvariant()
        FileExtension       = $Extension.TrimStart('.').ToLowerInvariant()
        Description         = $Description
        CreateByDefault     = $CreateByDefault
        Icon32FileIndex     = $Icon32FileIndex
        Icon32ResourceIndex = $Icon32ResourceIndex
        Icon64FileIndex     = $Icon64FileIndex
        Icon64ResourceIndex = $Icon64ResourceIndex
        Actions             = $Actions.ToArray()
      })
  }
  # Exact consumption authenticates the candidate found by the outer scanner and
  # prevents a valid prefix in unrelated package data from being accepted.
  if ($Cursor -ne $Bytes.Length) { throw 'The DeployMaster file-type record has trailing data.' }
  $Associations.ToArray()
}

function Get-DeployMasterFileAssociation {
  <#
  .SYNOPSIS
    Locate and decode structured file-type records in package metadata
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER IdentityEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER PackageDataOffset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER MaximumBlocks
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [ValidateRange(1, 128)][int]$MaximumBlocks = 128
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt 33554432 -or $MetadataLength -gt [int]::MaxValue) { return }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Associations = [Collections.Generic.List[object]]::new()
  $DecodedBlockCount = 0
  for ($BlockOffset = 0; $BlockOffset + 9 -le $Metadata.Length -and $DecodedBlockCount -lt $MaximumBlocks; $BlockOffset++) {
    $RawSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset)
    $StoredSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset + 4)
    if ($RawSize -eq 0 -or $RawSize -gt 1048576 -or $StoredSize -eq 0 -or $StoredSize -gt $RawSize -or $BlockOffset + 8 + $StoredSize -gt $Metadata.Length) { continue }
    $InputStream = [IO.MemoryStream]::new($Metadata, $BlockOffset + 8, [int]$StoredSize, $false, $true)
    $OutputStream = [IO.MemoryStream]::new()
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes 1048576 -Properties $Properties -CompressedSize $StoredSize -UncompressedSize $RawSize
      $DecodedBlockCount++
      $Parsed = @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $OutputStream.ToArray())
      foreach ($Association in $Parsed) { $Associations.Add($Association) }
      $BlockOffset += 7 + $StoredSize
    } catch {
    } finally {
      $InputStream.Dispose()
      $OutputStream.Dispose()
    }
  }
  $Associations.ToArray()
}

function Read-DeployMasterPackageData {
  <#
  .SYNOPSIS
    Parse one DeployMaster package from an already-open installer stream
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $Locator = Get-DeployMasterPackageLocator -Stream $Stream
  $Header = Get-DeployMasterPackageHeader -Stream $Stream -Locator $Locator
  $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
  $LanguageBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $Header.LanguageBlockOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $IdentityBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $LanguageBlock.EndOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $Identity = ConvertFrom-DeployMasterIdentity -Bytes $IdentityBlock.Bytes -ScopeValue $Header.ScopeValue
  $Warnings = [Collections.Generic.List[object]]::new()
  if (-not $Identity.LocationMarkerMatchesScope) { $Warnings.Add('The DeployMaster identity scope marker does not match the package-control scope byte.') }
  try { $FileEntries = @(Get-DeployMasterFileEntry -Stream $Stream -Identity $Identity -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties -TableKind $Header.Layout) }
  catch {
    $FileEntries = @()
    $Warnings.Add("The DeployMaster payload file table was not decoded: $($_.Exception.Message)")
  }
  try {
    $StructuredMetadata = Read-DeployMasterStructuredMetadata -Stream $Stream -Header $Header -Locator $Locator -IdentityEnd $IdentityBlock.EndOffset -FileEntries $FileEntries -ScopeValue $Identity.EffectiveScopeValue
    $FileAssociations = @($StructuredMetadata.FileAssociations)
  } catch {
    $StructuredError = $_.Exception.Message
    $StructuredMetadata = $null
    # Legacy packages predate some current metadata records. Preserve the proven association fallback
    # while reporting that the remaining behavioral model is incomplete.
    try { $FileAssociations = @(Get-DeployMasterFileAssociation -Stream $Stream -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties) }
    catch { $FileAssociations = @() }
    $PackageSettings = $null
    $Warnings.Add("The DeployMaster behavioral metadata stream was not fully decoded: $StructuredError")
  }
  $PackageSettings = $null
  if ($StructuredMetadata -and $Header.Layout -eq 'Current') {
    try {
      $ConfigurationBytes = Read-BinaryBytes -Stream $Stream -Offset $IdentityBlock.EndOffset -Count 5
      $PortableFolder = $null
      try {
        $PortableFolderBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ($IdentityBlock.EndOffset + 5) -Properties $Header.LzmaProperties -Limit $StructuredMetadata.ComponentBlock.Offset -MaximumBytes 65535
        $PortableFolder = (ConvertFrom-DeployMasterTextBlock -Bytes $PortableFolderBlock.Bytes).Text
      } catch {}
      $PackageSettings = [pscustomobject]@{
        Flags                         = $ConfigurationBytes[0]
        IdentityPrompts               = [pscustomobject]@{
          AskName             = [bool]($ConfigurationBytes[1] -band 1)
          AskCompany          = [bool]($ConfigurationBytes[1] -band 2)
          AskSerialNumber     = [bool]($ConfigurationBytes[1] -band 4)
          AskRegistrationCode = [bool]($ConfigurationBytes[1] -band 8)
        }
        PortableInstallationMode      = switch ($ConfigurationBytes[2]) { 0 { 'Never' } 1 { 'UserChoice' } 2 { 'Always' } default { 'Unknown' } }
        PortableInstallationModeValue = $ConfigurationBytes[2]
        PortableMarkerMode            = switch ($ConfigurationBytes[3]) { 0 { 'Never' } 1 { 'WhenAnyDriveIsAllowed' } 2 { 'Always' } default { 'Unknown' } }
        PortableMarkerModeValue       = $ConfigurationBytes[3]
        PortableAllowAnyDrive         = [bool]$ConfigurationBytes[4]
        PortableDefaultFolder         = $PortableFolder
      }
    } catch { $Warnings.Add("The DeployMaster current-generation package settings were not decoded: $($_.Exception.Message)") }
  }

  [pscustomobject]@{
    Locator            = $Locator
    Header             = $Header
    LanguageBlock      = $LanguageBlock
    IdentityBlock      = $IdentityBlock
    Identity           = $Identity
    FileEntries        = $FileEntries
    FileAssociations   = $FileAssociations
    StructuredMetadata = $StructuredMetadata
    Settings           = $PackageSettings
    Diagnostics        = @(ConvertTo-InstallerDiagnostic -InputObject @(@($Warnings)) -Source 'DeployMaster' -Kind Incomplete -Areas Metadata)
  }
}

function ConvertTo-DeployMasterRegistryWrite {
  <#
  .SYNOPSIS
    Build the explicit built-in DeployMaster uninstall-entry evidence
  .PARAMETER PackageData
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER Value
    Format-specific field or value interpreted according to the current record/version.
  #>
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][object]$Value
  )

  $Root = $PackageData.Identity.RegistryRoot
  [pscustomobject]@{
    Root     = $Root
    Key      = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)"
    Name     = $Name
    Value    = $Value
    Type     = 'REG_SZ'
    Evidence = 'DeployMaster structured identity and built-in uninstaller configuration'
  }
}

function Get-DeployMasterCustomAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Project explicit Registry-tab uninstall writes into ARP entries.
  .PARAMETER RegistryWrite
    Parsed DeployMaster registry writes. Conditional keep-existing writes are retained as raw evidence but excluded from authoritative ARP values.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Groups = @($RegistryWrite | Where-Object {
      -not $_.OnlyIfMissing -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)(?<ProductCode>[^\\]+)$'
    } | Group-Object Root, Key)
  foreach ($Group in $Groups) {
    $Values = [ordered]@{}
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    # Windows hides entries without DisplayName and entries explicitly marked as system components.
    # Keep their registry writes in CustomRegistryWrites, but do not present them as visible ARP rows.
    $SystemComponent = 0L
    $IsHidden = $Values.Contains('SystemComponent') -and [long]::TryParse([string]$Values.SystemComponent, [ref]$SystemComponent) -and $SystemComponent -ne 0
    if (-not $Values.Contains('DisplayName') -or [string]::IsNullOrWhiteSpace([string]$Values.DisplayName) -or $IsHidden) { continue }
    $ProductCode = ([string]$Group.Group[0].Key -split '\\')[-1]
    $Entry = [ordered]@{ ProductCode = $ProductCode; InstallerType = 'exe' }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if ($Values.Contains($Name) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$Name])) { $Entry[$Name] = [string]$Values[$Name] }
    }
    [pscustomobject]$Entry
  }
}

function Merge-DeployMasterAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Merge built-in and explicit DeployMaster uninstall records by ProductCode.
  .PARAMETER Entry
    ARP projections in precedence order. Later explicit registry values replace corresponding built-in values.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entry)

  $ByProductCode = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Candidate in $Entry) {
    $ProductCode = [string]$Candidate.ProductCode
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { continue }
    $Values = [ordered]@{}
    if ($ByProductCode.Contains($ProductCode)) {
      foreach ($Property in $ByProductCode[$ProductCode].PSObject.Properties) { $Values[$Property.Name] = $Property.Value }
    }
    foreach ($Property in $Candidate.PSObject.Properties) {
      if ($null -ne $Property.Value -and -not ($Property.Value -is [string] -and [string]::IsNullOrWhiteSpace($Property.Value))) {
        $Values[$Property.Name] = $Property.Value
      }
    }
    $ByProductCode[$ProductCode] = [pscustomobject]$Values
  }
  return [object[]]@($ByProductCode.Values)
}

function Get-DeployMasterInfo {
  <#
  .SYNOPSIS
    Read structured DeployMaster identity, scope, ARP, and payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      # Parse the complete package model while one stream is open, then separately corroborate the
      # overlay location and PE runtime identity.
      $PackageData = Read-DeployMasterPackageData -Stream $Stream
      $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
      $PELayout = Get-PELayout -Stream $Stream
    } finally { $Stream.Dispose() }

    if ($OverlayOffset -ne $PackageData.Locator.PackageOffset) { throw 'The DeployMaster package locator does not point to the PE overlay.' }
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $VersionStrings = Get-PEVersionStringTable -Path $File.FullName
    $RuntimeProductName = ([string]$VersionInfo.ProductName).Trim()
    $RuntimeComments = ([string]$VersionStrings.Comments).Trim()
    if ($RuntimeProductName -notmatch '(?i)DeployMaster' -and $RuntimeComments -notmatch '(?i)DeployMaster') { throw 'The validated package overlay is not paired with a DeployMaster runtime identity.' }

    $Identity = $PackageData.Identity
    $InstallLocation = switch ($Identity.Scope) {
      'user' { $Identity.UserInstallLocation }
      'machine' { $Identity.MachineInstallLocation }
      default { $null }
    }
    # Built-in uninstall fields come from the structured identity block. Explicit Registry-tab
    # records are appended and separately projected when they target an uninstall key.
    $BuiltInRegistryWrites = @(
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name DisplayName -Value $Identity.DisplayName
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name DisplayVersion -Value $Identity.DisplayVersion
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name Publisher -Value $Identity.Publisher
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name InstallLocation -Value $InstallLocation
    )
    $CustomRegistryWrites = if ($PackageData.StructuredMetadata) { @($PackageData.StructuredMetadata.Registry.RegistryWrites) } else { @() }
    $RegistryWrites = @($BuiltInRegistryWrites) + @($CustomRegistryWrites)
    $CustomAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $CustomRegistryWrites
    $FileExtensions = @((@($PackageData.FileAssociations | Select-Object -ExpandProperty FileExtension) + @($CustomAssociationInfo.FileExtensions)) | Sort-Object -Unique)
    $RegistryAssociationInfo = [pscustomobject]@{
      Protocols                 = @($CustomAssociationInfo.Protocols)
      FileExtensions            = $FileExtensions
      ProtocolAssociations      = @($CustomAssociationInfo.ProtocolAssociations)
      FileExtensionAssociations = @($PackageData.FileAssociations) + @($CustomAssociationInfo.FileExtensionAssociations)
      RegistryWrites            = @($CustomAssociationInfo.RegistryWrites)
      Diagnostics               = @($CustomAssociationInfo.Diagnostics)
    }
    $BuiltInAppsAndFeaturesEntry = [pscustomobject]@{
      ProductCode = $Identity.DisplayName; DisplayName = $Identity.DisplayName; DisplayVersion = $Identity.DisplayVersion
      Publisher = $Identity.Publisher; InstallerType = 'exe'
    }
    $CustomAppsAndFeaturesEntries = @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $CustomRegistryWrites)
    $AppsAndFeaturesEntries = @(Merge-DeployMasterAppsAndFeaturesEntry -Entry (@($BuiltInAppsAndFeaturesEntry) + $CustomAppsAndFeaturesEntries))
    $Warnings = [Collections.Generic.List[object]]::new()
    foreach ($Warning in $PackageData.Diagnostics) { $Warnings.Add($Warning) }
    foreach ($Warning in $RegistryAssociationInfo.Diagnostics) { $Warnings.Add($Warning) }
    if ($PackageData.Header.ExpirationPolicy.IsTimeLimited) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.TimeLimited' -Source 'DeployMaster' -Message "This installer stops working after $($PackageData.Header.ExpirationPolicy.ExpirationDate.ToString('yyyy-MM-dd')); use a non-expiring release artifact when one is available." -Kind Risk -Areas Installability -Evidence $PackageData.Header.ExpirationPolicy))
    }
    $SupportDlls = @(
      if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll32FileName)) { [pscustomobject]@{ Architecture = 'x86'; FileName = $Identity.SupportDll32FileName } }
      if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll64FileName)) { [pscustomobject]@{ Architecture = 'x64'; FileName = $Identity.SupportDll64FileName } }
    )
    if ($SupportDlls.Count) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.SupportDllEffectsOpaque' -Source 'DeployMaster' -Message 'The installer invokes one or more DeployMaster support DLLs. Their custom validation, folder, registry, and post-install effects require separate static inspection or VM validation.' -Kind ManualValidation -Areas Metadata, Installability, Security -Evidence $SupportDlls))
    }
    if ($Identity.SupportsDualScope) { $Warnings.Add('This DeployMaster package supports both user and machine scope; validate the default scope and any elevation-sensitive behavior in a VM.') }
    if ($PackageData.FileAssociations.Actions | Where-Object { $_.Executable32FileIndex -lt 0 -and $_.Executable64FileIndex -lt 0 }) {
      $Warnings.Add('One or more DeployMaster file-type actions do not resolve to packaged executable indexes and will not create an open command.')
    }
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $PackageData.StructuredMetadata) {
      foreach ($Field in 'Components', 'InstallationItems', 'RegistryWrites', 'Prerequisites', 'CompletionActions', 'UpdatePolicy') { $UnresolvedFields.Add($Field) }
    }
    if ($SupportDlls.Count) { $UnresolvedFields.Add('SupportDllEffects') }
    $InstallerArchitecture = switch ($PELayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
    # Distinguish a pure x64 installer from an x86 bootstrapper that deploys a 64-bit application.
    $ApplicationArchitectureMode = if ($PackageData.Header.ApplicationArchitectureMode -eq 'x64Application') {
      if ($InstallerArchitecture -eq 'x86') { 'x64ApplicationWithX86InstallerStub' } else { 'x64ApplicationWithX64Installer' }
    } else { $PackageData.Header.ApplicationArchitectureMode }
    $Components = [object[]]@()
    $InstallationFolders = [object[]]@()
    $InstalledFiles = [object[]]@()
    $Shortcuts = [object[]]@()
    $UrlShortcuts = [object[]]@()
    $Prerequisites = [object[]]@()
    $DeletedRegistryKeys = [object[]]@()
    $CompletionActions = $null
    $UninstallConfiguration = $null
    $UpdatePolicy = $null
    $ExecutedPayloads = [Collections.Generic.List[object]]::new()
    if ($PackageData.StructuredMetadata) {
      $Components = [object[]]@($PackageData.StructuredMetadata.Components)
      $InstallationFolders = [object[]]@($PackageData.StructuredMetadata.InstallTree.Folders)
      $InstalledFiles = [object[]]@($PackageData.StructuredMetadata.InstallTree.Files)
      $Shortcuts = [object[]]@($PackageData.StructuredMetadata.InstallTree.Shortcuts)
      $UrlShortcuts = [object[]]@($PackageData.StructuredMetadata.InstallTree.UrlShortcuts)
      $Prerequisites = [object[]]@($PackageData.StructuredMetadata.TrailingMetadata.Prerequisites)
      $DeletedRegistryKeys = [object[]]@($PackageData.StructuredMetadata.Registry.DeletedKeys)
      $CompletionActions = $PackageData.StructuredMetadata.TrailingMetadata.Completion
      $UninstallConfiguration = $PackageData.StructuredMetadata.TrailingMetadata.Uninstall
      $UpdatePolicy = $PackageData.StructuredMetadata.TrailingMetadata.Update
      foreach ($Execution in @(
          [pscustomobject]@{ Stage = 'AfterInstall'; Architecture = 'x86'; FileIndex = $CompletionActions.Launch32FileIndex; Arguments = $CompletionActions.LaunchArguments },
          [pscustomobject]@{ Stage = 'AfterInstall'; Architecture = 'x64'; FileIndex = $CompletionActions.Launch64FileIndex; Arguments = $CompletionActions.LaunchArguments },
          [pscustomobject]@{ Stage = 'BeforeUninstall'; Architecture = 'x86'; FileIndex = $UninstallConfiguration.PreUninstall32FileIndex; Arguments = $UninstallConfiguration.PreUninstallArguments },
          [pscustomobject]@{ Stage = 'BeforeUninstall'; Architecture = 'x64'; FileIndex = $UninstallConfiguration.PreUninstall64FileIndex; Arguments = $UninstallConfiguration.PreUninstallArguments }
        )) {
        if ($Execution.FileIndex -ge 0 -and $Execution.FileIndex -lt $PackageData.FileEntries.Count) {
          $ExecutedPayloads.Add([pscustomobject]@{
              Stage        = $Execution.Stage
              Architecture = $Execution.Architecture
              FileIndex    = $Execution.FileIndex
              FileName     = $PackageData.FileEntries[$Execution.FileIndex].Name
              Arguments    = $Execution.Arguments
              Evidence     = 'DeployMaster completion or pre-uninstall file index'
            })
        }
      }
    }
    $InstallationItems = [object[]]@($InstallationFolders) + @($InstalledFiles) + @($Shortcuts) + @($UrlShortcuts)

    [pscustomobject][ordered]@{
      Path                                  = $File.FullName
      InstallerType                         = 'exe'
      ProductCode                           = $Identity.DisplayName
      UpgradeCode                           = $null
      DisplayName                           = $Identity.DisplayName
      DisplayVersion                        = $Identity.DisplayVersion
      Publisher                             = $Identity.Publisher
      Scope                                 = $Identity.Scope
      DefaultInstallLocation                = $InstallLocation
      WritesAppsAndFeaturesEntry            = $true
      AppsAndFeaturesProductCode            = $Identity.DisplayName
      AppsAndFeaturesInstallerType          = 'exe'
      AppsAndFeaturesEntries                = $AppsAndFeaturesEntries
      Diagnostics                           = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'DeployMaster' -Kind Incomplete -Areas Metadata))
      UnresolvedFields                      = $UnresolvedFields.ToArray()
      Family                                = 'DeployMaster'
      ProductCodeEvidence                   = 'DeployMaster structured identity and built-in uninstall-key convention'
      PublisherUrl                          = $Identity.PublisherUrl
      PackageUrl                            = $Identity.PackageUrl
      Copyright                             = $Identity.Copyright
      ReadmeFileName                        = $Identity.ReadmeFileName
      LicenseFileName                       = $Identity.LicenseFileName
      LicenseRequiredEveryInstall           = $Identity.LicenseRequiredEveryInstall
      SupportDlls                           = $SupportDlls
      ReleaseDate                           = $Identity.ReleaseDate
      MachineInstallLocation                = $Identity.MachineInstallLocation
      UserInstallLocation                   = $Identity.UserInstallLocation
      CommonFilesLocation                   = $Identity.CommonFilesLocation
      CommonPublisherLocation               = $Identity.CommonPublisherLocation
      MachineMenuLocation                   = $Identity.MachineMenuLocation
      UserMenuLocation                      = $Identity.UserMenuLocation
      CommonDataLocation                    = $Identity.CommonDataLocation
      UserDataLocation                      = $Identity.UserDataLocation
      RuntimeProductName                    = $RuntimeProductName
      FileDescription                       = ([string]$VersionInfo.FileDescription).Trim()
      DefaultScope                          = $Identity.DefaultScope
      SupportedScopes                       = $Identity.SupportedScopes
      SupportsDualScope                     = $Identity.SupportsDualScope
      RequiresAdministrativeRights          = $Identity.RequiresAdministrativeRights
      InstallerArchitecture                 = $InstallerArchitecture
      ApplicationArchitectureMode           = $ApplicationArchitectureMode
      ApplicationArchitectures              = $PackageData.Header.ApplicationArchitectures
      SupportedArchitectures                = $PackageData.Header.ApplicationArchitectures
      SupportedOperatingSystemArchitectures = $PackageData.Header.SupportedOperatingSystemArchitectures
      RegistryView                          = switch ($ApplicationArchitectureMode) {
        { $_ -in 'x86ApplicationForX86WindowsOnly', 'x86ApplicationForX86AndX64Windows' } { '32-bit'; break }
        { $_ -in 'x64ApplicationWithX86InstallerStub', 'x64ApplicationWithX64Installer', 'x64Application' } { '64-bit'; break }
        'x86AndX64Application' { 'architecture-selected'; break }
        default { 'default' }
      }
      SupportedWindowsVersions              = $PackageData.Header.SupportedWindowsVersions
      SupportsFutureWindowsVersions         = $PackageData.Header.SupportsFutureWindowsVersions
      MinimumWindows10VersionCode           = $PackageData.Header.MinimumWindows10VersionCode
      MaximumWindows10VersionCode           = $PackageData.Header.MaximumWindows10VersionCode
      MinimumWindows11VersionCode           = $PackageData.Header.MinimumWindows11VersionCode
      MaximumWindows11VersionCode           = $PackageData.Header.MaximumWindows11VersionCode
      RequestedExecutionLevel               = Get-PERequestedExecutionLevel -Path $File.FullName
      InstallerSwitches                     = [ordered]@{ Silent = '/silent'; InstallLocation = '/appfolder "<INSTALLPATH>"' }
      InstallModes                          = @('interactive', 'silent')
      CommandLineSwitches                   = [pscustomobject]@{
        Silent                   = @('/s', '/silent')
        SuppressDesktopShortcuts = '/nodesktop'
        ForceX86                 = if ($ApplicationArchitectureMode -eq 'x86AndX64Application') { '/32' } else { $null }
        TemporaryFolder          = '/temp "<PATH>"'
        InstallationFolders      = [ordered]@{
          Application = '/appfolder "<PATH>"'
          CommonFiles = '/appcommonfolder "<PATH>"'
          StartMenu   = '/appmenu "<PATH>"'
          UserData    = '/userdata "<PATH>"'
        }
      }
      UninstallerSwitches                   = [ordered]@{ Silent = '/silent' }
      RegistryWrites                        = $RegistryWrites
      CustomRegistryWrites                  = $CustomRegistryWrites
      DeletedRegistryKeys                   = $DeletedRegistryKeys
      RegistryAssociationInfo               = $RegistryAssociationInfo
      Protocols                             = $RegistryAssociationInfo.Protocols
      FileExtensions                        = $RegistryAssociationInfo.FileExtensions
      FileAssociations                      = $PackageData.FileAssociations
      Components                            = $Components
      InstallationItems                     = $InstallationItems
      InstallationFolders                   = $InstallationFolders
      InstalledFiles                        = $InstalledFiles
      Shortcuts                             = $Shortcuts
      UrlShortcuts                          = $UrlShortcuts
      ExecutedPayloads                      = $ExecutedPayloads.ToArray()
      Prerequisites                         = $Prerequisites
      DotNetFrameworkRequirement            = if ($PackageData.StructuredMetadata) { $PackageData.StructuredMetadata.TrailingMetadata.DotNetFramework } else { $null }
      CompletionActions                     = $CompletionActions
      UninstallConfiguration                = $UninstallConfiguration
      UpdatePolicy                          = $UpdatePolicy
      ExpirationPolicy                      = $PackageData.Header.ExpirationPolicy
      PackageSettings                       = $PackageData.Settings
      FileEntries                           = $PackageData.FileEntries
      ExtractedFiles                        = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
      OverlayInfo                           = [pscustomobject]@{
        OverlayOffset     = $PackageData.Locator.PackageOffset
        OverlayLength     = $File.Length - $PackageData.Locator.PackageOffset
        IntegrityLength   = $PackageData.Locator.IntegrityLength
        ExpectedCrc32     = $PackageData.Locator.ExpectedCrc32
        ActualCrc32       = $PackageData.Locator.ActualCrc32
        DictionarySize    = $PackageData.Header.DictionarySize
        FormatVersion     = $PackageData.Header.FormatVersion
        PackageDataOffset = $PackageData.Locator.PackageDataOffset
      }
      CanExpand                             = $true
      ParserVersionInfo                     = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DeployMaster'; ParserMajor = 3; Sources = @('DeployMaster 0x80 package locator', 'CRC32-protected package-control header', 'stored and bounded LZMA data blocks', 'controlled builder outputs', 'DeployMaster builder help') }
    }
  }
}

function Export-DeployMasterRange {
  <#
  .SYNOPSIS
    Export one stored or raw-LZMA DeployMaster range
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Entry,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumBytes
  )

  # A bounded source range prevents the decoder from consuming the next package record.
  $Output = [IO.File]::Open($DestinationPath, 'CreateNew', 'Write', 'None')
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Entry.Offset -Length $Entry.CompressedSize -LeaveOpen
  try {
    if ($Entry.Compression -eq 'Store') {
      $null = Copy-BoundedStream -Source $InputStream -Destination $Output -MaximumBytes $MaximumBytes -ExpectedBytes $Entry.UncompressedSize
    } else {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $Output -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize $Entry.CompressedSize -UncompressedSize $Entry.UncompressedSize
    }
  } finally {
    $InputStream.Dispose()
    $Output.Dispose()
  }
  # The final catalog column is CRC32 over the expanded file. Reject damaged payloads before the
  # caller can consume them, and remove the partial output on failure.
  if ($Entry.PSObject.Properties['Crc32']) {
    $ActualCrc32 = [uint32](Get-BinaryCrc32 -Path $DestinationPath -MaximumBytes $MaximumBytes)
    if ($ActualCrc32 -ne [uint32]$Entry.Crc32) {
      Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction Ignore
      throw "The DeployMaster payload CRC32 check failed for '$($Entry.FullName)'."
    }
  }
  Get-Item -LiteralPath $DestinationPath -Force
}

function Expand-DeployMasterInstaller {
  <#
  .SYNOPSIS
    Expand validated DeployMaster runtime, metadata, and payload files
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-DeployMaster-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Results = [Collections.Generic.List[object]]::new()
    $ExpandedBytes = 0L
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
      $PackageData = Read-DeployMasterPackageData -Stream $Stream
      # Normalize runtime cores, decoded metadata blocks, and application files into one extraction
      # catalog so selection and accounting follow the same path.
      $Items = [Collections.Generic.List[object]]::new()
      foreach ($Core in $PackageData.Header.CoreEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Runtime/DeployMasterCore-$($Core.Architecture).exe"; Kind = 'Compressed'; Offset = $Core.Offset; CompressedSize = $Core.CompressedSize; UncompressedSize = $Core.UncompressedSize; Compression = 'Lzma' })
      }
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Language.txt'; Kind = 'Bytes'; Bytes = $PackageData.LanguageBlock.Bytes; UncompressedSize = $PackageData.LanguageBlock.Bytes.Length })
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Identity.txt'; Kind = 'Bytes'; Bytes = $PackageData.IdentityBlock.Bytes; UncompressedSize = $PackageData.IdentityBlock.Bytes.Length })
      foreach ($Entry in $PackageData.FileEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Payload/$($Entry.FullName)"; Kind = 'Compressed'; Offset = $Entry.Offset; CompressedSize = $Entry.CompressedSize; UncompressedSize = $Entry.UncompressedSize; Compression = $Entry.Compression })
      }

      # Check the aggregate uncompressed size and destination identity before writing each item.
      foreach ($Item in $Items) {
        if (-not (Test-ExtractionPattern -Path $Item.FullName -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.FullName `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($ExpandedBytes + $Item.UncompressedSize -gt $MaximumExpandedBytes) { throw "The DeployMaster expansion exceeds the $MaximumExpandedBytes-byte output limit." }
        $OutputPath = $Target.Path
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if ($Item.Kind -eq 'Bytes') {
          [IO.File]::WriteAllBytes($OutputPath, $Item.Bytes)
          $Result = Get-Item -LiteralPath $OutputPath -Force
        } else {
          $Result = Export-DeployMasterRange -Stream $Stream -Entry $Item -Properties $PackageData.Header.LzmaProperties -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
        }
        $ExpandedBytes += $Item.UncompressedSize
        $Results.Add($Result)
      }
    } finally { $Stream.Dispose() }
    $Results.ToArray()
  }
}

function Test-DeployMaster {
  <#
  .SYNOPSIS
    Test whether a file contains a validated DeployMaster package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-DeployMasterInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal URL protocol names from DeployMaster registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal file extensions from DeployMaster registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster package display name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayName }
}

function Read-PublisherFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the built-in DeployMaster uninstall-key identity
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).ProductCode }
}

function Read-ScopeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster installation scope
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-DeployMasterInfo, Expand-DeployMasterInstaller, Test-DeployMaster, Read-ProtocolsFromDeployMaster, Read-FileExtensionsFromDeployMaster, Read-ProductVersionFromDeployMaster, Read-ProductNameFromDeployMaster, Read-PublisherFromDeployMaster, Read-ProductCodeFromDeployMaster, Read-ScopeFromDeployMaster
