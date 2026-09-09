# SPDX-License-Identifier: Apache-2.0
# Static DeployMaster parser derived from controlled DeployMaster 7.7 builds,
# validated legacy packages, and the documented installer command-line behavior.
# Reference: https://www.deploymaster.com/manual.html
# Version history: https://www.deploymaster.com/history.html
#
# Binary structure consumed here (absolute offsets and little-endian integers):
#
#   PE image (DeployMaster 6.0 and later)
#   +-- [0x80] package locator
#   |   +-- PackageOffset:u32 -> overlay
#   |   +-- IntegrityLength:u32 and CRC32:u32
#   |   `-- ExpectedFileSize:u64 and Reserved:u32
#   +-- optional zero padding to an eight-byte boundary
#   +-- optional Authenticode certificate table outside ExpectedFileSize
#   `-- overlay at PackageOffset
#       +-- raw-LZMA properties[5]
#       +-- catalog-selected 66-, 70-, or 74-byte control header
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
#   Classic DeployMaster 2.x overlay
#   +-- BZip2-compressed installer runtime
#   +-- FF FF FF FF end marker
#   +-- Length:u32 + zlib language record
#   +-- Length:u32 + zlib form-feed identity record
#   +-- legacy installation metadata records
#   +-- Length:u32 + zlib CRLF file-name catalog
#   +-- zlib behavior records, including registry and file associations
#   `-- contiguous Length:u32 + zlib payload records through logical EOF
#
# The CRC covers only the declared integrity range. Undocumented header fields
# remain observed evidence; scope/architecture fields are decoded only for
# controlled layouts whose size and record boundaries validate.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:DeployMasterFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'DeployMasterFormatCatalog.psd1')
if ([int]$Script:DeployMasterFormatCatalog.CatalogVersion -ne 1) { throw "Unsupported DeployMaster format catalog version '$($Script:DeployMasterFormatCatalog.CatalogVersion)'." }
$Script:DeployMasterHeaderProfiles = [Collections.Generic.List[object]]::new()
$Script:DeployMasterHeaderProfilesById = @{}
foreach ($CatalogProfile in $Script:DeployMasterFormatCatalog.HeaderProfiles) {
  $HeaderProfile = [pscustomobject]$CatalogProfile
  if ($HeaderProfile.HeaderSize -notin 66, 70, 74 -or $HeaderProfile.Shift -notin -8, -4, 0 -or
    $HeaderProfile.RegistryRoute -notin 'Opcode', 'LegacyDelimited' -or
    $HeaderProfile.AssociationRoute -notin 'Auto', 'LengthPrefixedUtf8', 'FormFeedDelimitedAnsi' -or
    $HeaderProfile.UninstallCommandRoute -notin 'QuotedExecutableAndLog', 'UnquotedExecutableQuotedLog') { throw "DeployMaster header profile '$($HeaderProfile.Id)' has an unsupported layout." }
  if ($Script:DeployMasterHeaderProfilesById.ContainsKey([string]$HeaderProfile.Id)) { throw "The DeployMaster format catalog contains duplicate profile '$($HeaderProfile.Id)'." }
  $Script:DeployMasterHeaderProfiles.Add($HeaderProfile)
  $Script:DeployMasterHeaderProfilesById[[string]$HeaderProfile.Id] = $HeaderProfile
}
if ($Script:DeployMasterHeaderProfiles.Count -eq 0) { throw 'The DeployMaster format catalog contains no header profiles.' }
foreach ($ClassicRoute in $Script:DeployMasterFormatCatalog.ClassicRoutes) {
  if ([string]$ClassicRoute.PackageMagic -notmatch '^.{4}$' -or $ClassicRoute.RuntimeCompression -ne 'BZip2' -or $ClassicRoute.PayloadCompression -ne 'Zlib' -or
    $ClassicRoute.RegistryRoute -ne 'ClassicNullTerminatedAnsi' -or $ClassicRoute.AssociationRoute -ne 'ClassicFormFeedAnsi') {
    throw "DeployMaster classic route '$($ClassicRoute.Id)' has an unsupported layout."
  }
}

function Get-DeployMasterClassicRoute {
  <#
  .SYNOPSIS
    Identify a structurally distinct classic DeployMaster package route.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Its position is restored by the binary and PE helpers.
  .PARAMETER RuntimeIdentity
    Trusted PE version-resource identity used with the overlay magic to reject unrelated BZip2 SFX files.
  .OUTPUTS
    The matching classic-route descriptor, or no output when the artifact is not recognized.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][string]$RuntimeIdentity
  )

  if ($RuntimeIdentity -notmatch '(?im)^DeployMaster$' -or $RuntimeIdentity -notmatch '(?i)(?:built with|JGsoft\s+)DeployMaster') { return }

  $OverlayOffset = try { Get-PEOverlayOffset -Stream $Stream } catch { return }
  if ($OverlayOffset + 4 -gt $Stream.Length) { return }
  $Magic = [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 4))

  foreach ($RouteData in $Script:DeployMasterFormatCatalog.ClassicRoutes) {
    if ($Magic -ceq [string]$RouteData.PackageMagic) { return [pscustomobject]$RouteData }
  }
}

function Test-DeployMasterClassicZlibHeader {
  <#
  .SYNOPSIS
    Test the two-byte RFC 1950 header used by a classic DeployMaster record.
  .PARAMETER Bytes
    Exactly two bytes beginning at the compressed-data boundary.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][ValidateCount(2, 2)][byte[]]$Bytes)

  # Classic media uses Deflate with a 32 KiB window and no preset dictionary. Checking FCHECK
  # avoids treating arbitrary 0x78 bytes inside compressed payloads as record boundaries.
  return $Bytes[0] -eq 0x78 -and (([int]$Bytes[0] * 256 + $Bytes[1]) % 31) -eq 0 -and ($Bytes[1] -band 0x20) -eq 0
}

function Get-DeployMasterClassicLogicalEndCandidate {
  <#
  .SYNOPSIS
    Return physical or pre-certificate offsets at which the classic record stream may end.
  .PARAMETER Stream
    Caller-owned seekable installer stream. The function does not dispose it.
  .PARAMETER PELayout
    Parsed PE layout used to separate an Authenticode certificate table from the installer data.
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$PELayout
  )

  $Candidates = [Collections.Generic.List[long]]::new()
  $Candidates.Add($Stream.Length)
  $Certificate = $PELayout.DataDirectories['Certificate']
  if ($Certificate -and [long]$Certificate.Offset -gt 0 -and [long]$Certificate.Size -gt 0 -and
    [long]$Certificate.Offset + [long]$Certificate.Size -eq $Stream.Length) {
    $CertificateOffset = [long]$Certificate.Offset
    # Authenticode starts on an eight-byte boundary. Try every all-zero alignment suffix because
    # classic media does not carry the modern locator's explicit logical file length.
    for ($PaddingLength = 0; $PaddingLength -le 7; $PaddingLength++) {
      $LogicalEnd = $CertificateOffset - $PaddingLength
      if ($LogicalEnd -le 0) { continue }
      if ($PaddingLength) {
        $Padding = Read-BinaryBytes -Stream $Stream -Offset $LogicalEnd -Count $PaddingLength
        if ($Padding | Where-Object { $_ -ne 0 } | Select-Object -First 1) { continue }
      }
      if (-not $Candidates.Contains($LogicalEnd)) { $Candidates.Add($LogicalEnd) }
    }
  }
  return $Candidates.ToArray()
}

function Get-DeployMasterClassicRuntimeRecord {
  <#
  .SYNOPSIS
    Locate and validate the BZip2-compressed runtime at the start of a classic overlay.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER OverlayOffset
    Absolute offset of the BZip2 member.
  .PARAMETER MaximumEndOffset
    Exclusive upper bound for the package data, excluding any certificate table.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted expanded runtime size.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$OverlayOffset,
    [Parameter(Mandatory)][long]$MaximumEndOffset,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 67108864
  )

  $ScanLength = [Math]::Min($MaximumEndOffset - $OverlayOffset - 4, 268435456L)
  if ($ScanLength -le 0) { throw 'The classic DeployMaster BZip2 runtime is truncated.' }
  # A random compressed stream should contain very few four-byte all-ones runs. Keep candidate
  # decompression bounded as well as byte scanning so a hostile file cannot force thousands of
  # full BZip2 probes before parser rejection.
  $Markers = @(Find-BinaryPattern -Stream $Stream -Pattern ([byte[]](0xFF, 0xFF, 0xFF, 0xFF)) -StartOffset ($OverlayOffset + 4) -Length $ScanLength -Maximum 65)
  if ($Markers.Count -gt 64) { throw 'The classic DeployMaster runtime contains too many candidate end markers.' }

  foreach ($MarkerOffset in $Markers) {
    # The marker is accepted only when the following bytes begin a bounded length-prefixed zlib
    # record and the preceding BZip2 member expands to a valid PE runtime.
    if ($MarkerOffset + 10 -gt $MaximumEndOffset) { continue }
    $FirstRecordLength = [long](Read-BinaryInteger -Stream $Stream -Offset ($MarkerOffset + 4) -Size 4)
    if ($FirstRecordLength -lt 6 -or $FirstRecordLength -gt $MaximumEndOffset - ($MarkerOffset + 8)) { continue }
    $ZlibHeader = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset + 8) -Count 2
    if (-not (Test-DeployMasterClassicZlibHeader -Bytes $ZlibHeader)) { continue }

    $CompressedSize = $MarkerOffset - $OverlayOffset
    $InputStream = New-BoundedReadStream -Stream $Stream -Offset $OverlayOffset -Length $CompressedSize -LeaveOpen
    $Output = [IO.MemoryStream]::new()
    try {
      try { $ExpandedSize = Expand-InstallerCompressedStream -Algorithm BZip2 -Stream $InputStream -Destination $Output -MaximumBytes $MaximumExpandedBytes }
      catch { continue }
      $Output.Position = 0
      try { $RuntimeLayout = Get-PELayout -Stream $Output }
      catch { continue }
      return [pscustomobject]@{
        Offset           = $OverlayOffset
        CompressedSize   = $CompressedSize
        UncompressedSize = [long]$ExpandedSize
        EndOffset        = [long]$MarkerOffset
        MarkerOffset     = [long]$MarkerOffset
        Compression      = 'BZip2'
        Architecture     = switch ($RuntimeLayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
        MachineName      = $RuntimeLayout.MachineName
      }
    } finally {
      $Output.Dispose()
      $InputStream.Dispose()
    }
  }
  throw 'The classic DeployMaster BZip2 runtime does not have a validated end marker.'
}

function Get-DeployMasterClassicZlibRecord {
  <#
  .SYNOPSIS
    Index candidate classic length-prefixed zlib records without expanding their payloads.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER StartOffset
    Absolute beginning of the record search.
  .PARAMETER EndOffset
    Exclusive absolute package boundary.
  .PARAMETER MaximumRecordCount
    Maximum accepted number of structurally valid candidates.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$StartOffset,
    [Parameter(Mandatory)][long]$EndOffset,
    [ValidateRange(1, 1048576)][int]$MaximumRecordCount = 131072
  )

  if ($StartOffset -lt 0 -or $EndOffset -le $StartOffset -or $EndOffset -gt $Stream.Length) { throw 'The classic DeployMaster zlib search range is invalid.' }
  $ByOffset = [Collections.Generic.Dictionary[long, object]]::new()
  foreach ($Header in [byte[]](0x78, 0x01), [byte[]](0x78, 0x5E), [byte[]](0x78, 0x9C), [byte[]](0x78, 0xDA)) {
    $PatternOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern $Header -StartOffset $StartOffset -Length ($EndOffset - $StartOffset) -Maximum ($MaximumRecordCount + 1))
    if ($PatternOffsets.Count -gt $MaximumRecordCount) { throw 'The classic DeployMaster package exceeds the zlib candidate limit.' }
    foreach ($DataOffset in $PatternOffsets) {
      $RecordOffset = [long]$DataOffset - 4
      if ($RecordOffset -lt $StartOffset) { continue }
      $CompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset $RecordOffset -Size 4)
      if ($CompressedSize -lt 6 -or $CompressedSize -gt $EndOffset - [long]$DataOffset) { continue }
      $RecordEnd = [long]$DataOffset + $CompressedSize
      if (-not $ByOffset.ContainsKey($RecordOffset)) {
        $ByOffset.Add($RecordOffset, [pscustomobject]@{
            Offset           = $RecordOffset
            DataOffset       = [long]$DataOffset
            CompressedSize   = $CompressedSize
            UncompressedSize = $null
            EndOffset        = $RecordEnd
            Compression      = 'Zlib'
          })
        if ($ByOffset.Count -gt $MaximumRecordCount) { throw 'The classic DeployMaster package exceeds the zlib record limit.' }
      }
    }
  }
  return [object[]]@($ByOffset.Values | Sort-Object Offset)
}

function Read-DeployMasterClassicZlibRecordData {
  <#
  .SYNOPSIS
    Expand one validated classic zlib record into a bounded byte array.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Record
    Record returned by Get-DeployMasterClassicZlibRecord.
  .PARAMETER MaximumBytes
    Maximum expanded byte count.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Record,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes = 4194304
  )

  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Record.DataOffset -Length $Record.CompressedSize -LeaveOpen
  $Output = [IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $Output -MaximumBytes $MaximumBytes -CompressedSize $Record.CompressedSize
    return $Output.ToArray()
  } finally {
    $Output.Dispose()
    $InputStream.Dispose()
  }
}

function ConvertFrom-DeployMasterClassicFileNameBlock {
  <#
  .SYNOPSIS
    Validate a classic CRLF-delimited payload-name block.
  .PARAMETER Bytes
    Expanded candidate metadata bytes.
  .PARAMETER ExpectedCount
    Number of trailing payload records that the name block must describe.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(1, 65536)][int]$ExpectedCount
  )

  $Text = [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char[]]@([char]0, [char]13, [char]10))
  $Names = [regex]::Split($Text, '\r\n|\n|\r')
  if ($Names.Count -ne $ExpectedCount) { return }
  foreach ($Name in $Names) {
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 1024 -or $Name.IndexOf([char]0) -ge 0 -or
      [IO.Path]::IsPathRooted($Name) -or $Name -match '^[A-Za-z]:' -or
      @($Name -split '[\\/]' | Where-Object { $_ -in '.', '..' }).Count) { return }
  }
  return [pscustomobject]@{ Names = [string[]]$Names; Bytes = $Bytes }
}

function Find-DeployMasterClassicPayloadCatalog {
  <#
  .SYNOPSIS
    Match a trailing contiguous zlib chain with its nearest validated filename catalog.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Record
    All indexed classic zlib record candidates.
  .PARAMETER LogicalEndCandidate
    Candidate physical ends before any Authenticode table.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][long[]]$LogicalEndCandidate
  )

  $ByEnd = @{}
  foreach ($Candidate in $Record) {
    $Key = ([long]$Candidate.EndOffset).ToString([Globalization.CultureInfo]::InvariantCulture)
    if (-not $ByEnd.ContainsKey($Key)) { $ByEnd[$Key] = [Collections.Generic.List[object]]::new() }
    $ByEnd[$Key].Add($Candidate)
  }

  $Chains = [Collections.Generic.List[object]]::new()
  foreach ($LogicalEnd in $LogicalEndCandidate) {
    $ReverseRecords = [Collections.Generic.List[object]]::new()
    $Cursor = [long]$LogicalEnd
    while ($ReverseRecords.Count -lt 65536) {
      $Key = $Cursor.ToString([Globalization.CultureInfo]::InvariantCulture)
      if (-not $ByEnd.ContainsKey($Key)) { break }
      $Candidate = $ByEnd[$Key] | Sort-Object Offset -Descending | Select-Object -First 1
      $ReverseRecords.Add($Candidate)
      $Cursor = [long]$Candidate.Offset
    }
    if ($ReverseRecords.Count) {
      $Records = $ReverseRecords.ToArray()
      [Array]::Reverse($Records)
      $Chains.Add([pscustomobject]@{ LogicalEnd = [long]$LogicalEnd; Records = [object[]]$Records })
    }
  }

  foreach ($Chain in @($Chains | Sort-Object { $_.Records.Count } -Descending)) {
    $PayloadStart = [long]$Chain.Records[0].Offset
    # The filename catalog is close to, but not necessarily adjacent to, the first payload. Decode
    # only small metadata candidates and require an exact one-name-per-record match.
    foreach ($Candidate in @($Record | Where-Object {
          $_.EndOffset -le $PayloadStart -and $PayloadStart - $_.EndOffset -le 4194304 -and $_.CompressedSize -le 1048576
        } | Sort-Object Offset -Descending)) {
      try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 4194304 }
      catch { continue }
      $Catalog = ConvertFrom-DeployMasterClassicFileNameBlock -Bytes $Bytes -ExpectedCount $Chain.Records.Count
      if ($Catalog) {
        return [pscustomobject]@{
          LogicalEnd     = $Chain.LogicalEnd
          Records        = $Chain.Records
          FileNameRecord = $Candidate
          FileNameBytes  = $Catalog.Bytes
          FileNames      = $Catalog.Names
        }
      }
    }
  }
  throw 'The classic DeployMaster trailing payload records do not have a matching filename catalog.'
}

function Complete-DeployMasterClassicFileCatalog {
  <#
  .SYNOPSIS
    Reconstruct the complete classic file-index namespace around the ordinary trailing payload chain.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access helpers restore its position.
  .PARAMETER Record
    All validated classic zlib records in the logical package.
  .PARAMETER Catalog
    Ordinary trailing payload chain and its matching filename record.
  .PARAMETER Identity
    Parsed classic identity containing the four possible auxiliary payload names.
  .PARAMETER IdentityEnd
    Absolute first byte after the classic identity record; auxiliary payload candidates begin here.
  .OUTPUTS
    The input catalog augmented with auxiliary records, complete names, expanded sizes, CRC32 values,
    preserved catalog-tail bytes, and the first structurally proven destination root when present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][psobject]$Identity,
    [Parameter(Mandatory)][long]$IdentityEnd
  )

  $OrdinaryRecords = @($Catalog.Records)
  $BehaviorStart = @($Record | Where-Object { $_.Offset -gt $Catalog.FileNameRecord.EndOffset -and $_.Offset -lt $OrdinaryRecords[0].Offset } | Sort-Object Offset | Select-Object -First 1)
  if ($BehaviorStart.Count -ne 1) { throw 'The classic DeployMaster file catalog does not have a bounded behavior-record boundary.' }
  $CatalogOffset = [long]$Catalog.FileNameRecord.EndOffset
  $CatalogLength = [long]$BehaviorStart[0].Offset - $CatalogOffset
  if ($CatalogLength -le 0 -or $CatalogLength -gt 1048576 -or $CatalogLength -gt [int]::MaxValue) { throw 'The classic DeployMaster file catalog is outside the configured bounds.' }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $CatalogOffset -Count ([int]$CatalogLength)

  # Classic catalogs reserve one 0xFFFFFFFF offset for each auxiliary payload physically stored
  # before the table. The remaining offsets must match the trailing zlib chain exactly.
  $AuxiliaryCount = 0
  while ($AuxiliaryCount -lt 4 -and 4 * ($AuxiliaryCount + 1) -le $Bytes.Length -and [BitConverter]::ToUInt32($Bytes, 4 * $AuxiliaryCount) -eq [uint32]::MaxValue) { $AuxiliaryCount++ }
  $EntryCount = $AuxiliaryCount + $OrdinaryRecords.Count
  if ($EntryCount -le 0 -or 24 * $EntryCount -gt $Bytes.Length) { throw 'The classic DeployMaster file catalog is truncated.' }
  for ($Index = 0; $Index -lt $OrdinaryRecords.Count; $Index++) {
    $SerializedOffset = [uint32][BitConverter]::ToUInt32($Bytes, 4 * ($AuxiliaryCount + $Index))
    if ($SerializedOffset -ne [uint32]$OrdinaryRecords[$Index].Offset) { throw 'The classic DeployMaster file catalog offsets do not match the payload chain.' }
  }

  $AuxiliaryNames = @(
    $Identity.DisplayIconFileName
    $Identity.ReadmeFileName
    $Identity.LicenseFileName
    $Identity.SupportDll32FileName
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
  if ($AuxiliaryNames.Count -ne $AuxiliaryCount) { throw 'The classic DeployMaster auxiliary file names do not match the file catalog.' }

  $ExpandedSizes = [Collections.Generic.List[long]]::new($EntryCount)
  $Crc32Values = [Collections.Generic.List[uint32]]::new($EntryCount)
  for ($Index = 0; $Index -lt $EntryCount; $Index++) {
    $ExpandedSize = [uint32][BitConverter]::ToUInt32($Bytes, (16 * $EntryCount) + (4 * $Index))
    if ($ExpandedSize -eq 0) { throw 'The classic DeployMaster file catalog contains an empty expanded-size entry.' }
    $ExpandedSizes.Add([long]$ExpandedSize)
    $Crc32Values.Add([uint32][BitConverter]::ToUInt32($Bytes, (20 * $EntryCount) + (4 * $Index)))
  }

  # Locate auxiliary payloads by the expanded-size and CRC columns. UI/configuration records can
  # occur in the same pre-catalog range, so neither record position nor apparent file magic alone
  # is sufficient evidence. Each auxiliary record must match exactly once and in catalog order.
  $PreCatalogRecords = @($Record | Where-Object { $_.Offset -ge $IdentityEnd -and $_.EndOffset -le $Catalog.FileNameRecord.Offset } | Sort-Object Offset)
  $DecodedCandidates = [Collections.Generic.List[object]]::new()
  $MaximumCandidateBytes = [Math]::Max(1L, ($ExpandedSizes | Measure-Object -Maximum).Maximum)
  foreach ($Candidate in $PreCatalogRecords) {
    if ($Candidate.CompressedSize -gt 134217728) { continue }
    try {
      $CandidateBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes $MaximumCandidateBytes
      $DecodedCandidates.Add([pscustomobject]@{ Record = $Candidate; ExpandedSize = [long]$CandidateBytes.Length; Crc32 = [uint32](Get-BinaryCrc32 -Bytes $CandidateBytes) })
    } catch { continue }
  }
  $AuxiliaryRecords = [Collections.Generic.List[object]]::new($AuxiliaryCount)
  $PreviousOffset = -1L
  for ($Index = 0; $Index -lt $AuxiliaryCount; $Index++) {
    $CandidateMatches = @($DecodedCandidates | Where-Object { $_.Record.Offset -gt $PreviousOffset -and $_.ExpandedSize -eq $ExpandedSizes[$Index] -and $_.Crc32 -eq $Crc32Values[$Index] })
    if ($CandidateMatches.Count -ne 1) { throw "The classic DeployMaster auxiliary file at index $Index could not be located unambiguously." }
    $AuxiliaryRecords.Add($CandidateMatches[0].Record)
    $PreviousOffset = [long]$CandidateMatches[0].Record.Offset
  }

  $AllRecords = [Collections.Generic.List[object]]::new($EntryCount)
  foreach ($Candidate in $AuxiliaryRecords) { $AllRecords.Add($Candidate) }
  foreach ($Candidate in $OrdinaryRecords) { $AllRecords.Add($Candidate) }
  $AllNames = [Collections.Generic.List[string]]::new($EntryCount)
  foreach ($Name in $AuxiliaryNames) { $AllNames.Add([string]$Name) }
  foreach ($Name in $Catalog.FileNames) { $AllNames.Add([string]$Name) }

  $DestinationRoot = ConvertFrom-DeployMasterClassicDestinationTail -Bytes $(
    if (24 * $EntryCount -lt $Bytes.Length) { [byte[]]$Bytes[(24 * $EntryCount)..($Bytes.Length - 1)] }
    else { [byte[]]::new(0) }
  )
  return [pscustomobject]@{
    LogicalEnd        = $Catalog.LogicalEnd
    Records           = $OrdinaryRecords
    FileNameRecord    = $Catalog.FileNameRecord
    FileNameBytes     = $Catalog.FileNameBytes
    FileNames         = $Catalog.FileNames
    AuxiliaryCount    = $AuxiliaryCount
    AuxiliaryRecords  = $AuxiliaryRecords.ToArray()
    AllRecords        = $AllRecords.ToArray()
    AllFileNames      = $AllNames.ToArray()
    ExpandedSizes     = $ExpandedSizes.ToArray()
    Crc32Values       = $Crc32Values.ToArray()
    CatalogOffset     = $CatalogOffset
    CatalogLength     = $CatalogLength
    InstallTreeOffset = $CatalogOffset + (24 * $EntryCount)
    ObservedTailBytes = if (24 * $EntryCount -lt $Bytes.Length) { $Bytes[(24 * $EntryCount)..($Bytes.Length - 1)] } else { [byte[]]::new(0) }
    DestinationRoot   = $DestinationRoot
  }
}

function ConvertFrom-DeployMasterClassicDestinationTail {
  <#
  .SYNOPSIS
    Decode the classic catalog suffix that introduces the first installation-item destination.
  .PARAMETER Bytes
    Catalog-relative bytes after the six parallel file-entry columns. The caller retains ownership
    of the array.
  .OUTPUTS
    A folder record when the complete suffix is one bounded Windows-1252 name followed by the
    classic 0xFE item-list marker; otherwise no output.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  # Archived 2.5.3 media emits [Length:u8][Name:Windows-1252][0xFE]. Do not consume a prefix of a
  # richer unknown tail: exact length and terminator checks keep later classic variants unresolved.
  if ($Bytes.Length -lt 3 -or $Bytes[-1] -ne 0xFE) { return }
  $Length = [int]$Bytes[0]
  if ($Length -lt 1 -or $Length + 2 -ne $Bytes.Length) { return }
  $Name = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, 1, $Length)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { return }
  return [pscustomobject]@{
    ComponentIndex = $null
    Name           = $Name
    FullName       = $Name
    CreateIfEmpty  = $false
    Evidence       = 'Classic catalog destination name followed by the 0xFE item-list marker'
  }
}

function ConvertFrom-DeployMasterClassicComponentBlock {
  <#
  .SYNOPSIS
    Decode one classic DeployMaster component descriptor.
  .PARAMETER Bytes
    Expanded component record using byte-sized flags, name length, and requirement indexes followed
    by a Windows-1252 description.
  .PARAMETER ComponentIndex
    Zero-based record-order index used to validate that requirements reference earlier components.
  .OUTPUTS
    A normalized component record, or no output when the byte sequence is not a complete component.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, 255)][int]$ComponentIndex
  )

  if ($Bytes.Length -lt 4 -or $Bytes[0] -notin 1, 3) { return }
  $Flags = [int]$Bytes[0]
  $NameLength = [int]$Bytes[1]
  if ($NameLength -lt 1 -or 3 + $NameLength -gt $Bytes.Length) { return }
  $Name = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, 2, $NameLength)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { return }
  $Cursor = 2 + $NameLength
  $RequirementCount = [int]$Bytes[$Cursor++]
  if ($RequirementCount -gt $ComponentIndex -or $Cursor + $RequirementCount -gt $Bytes.Length) { return }
  $Requirements = [Collections.Generic.List[int]]::new($RequirementCount)
  for ($Index = 0; $Index -lt $RequirementCount; $Index++) {
    $Requirement = [int]$Bytes[$Cursor++]
    if ($Requirement -ge $ComponentIndex -or $Requirements.Contains($Requirement)) { return }
    $Requirements.Add($Requirement)
  }
  $Description = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Cursor, $Bytes.Length - $Cursor).TrimEnd([char]0)
  if ($Description.IndexOf([char]0) -ge 0) { return }
  return [pscustomobject]@{
    Index              = $ComponentIndex
    Name               = $Name
    Flags              = $Flags
    InstalledByDefault = [bool]($Flags -band 0x01)
    UserSelectable     = [bool]($Flags -band 0x02)
    Requirements       = $Requirements.ToArray()
    Description        = $Description
  }
}

function Read-DeployMasterClassicComponentCatalog {
  <#
  .SYNOPSIS
    Locate classic component descriptors between the identity and filename catalog records.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER Record
    All indexed classic zlib records in the logical package.
  .PARAMETER Catalog
    Completed classic file catalog, used to exclude auxiliary payload records and bound the scan.
  .PARAMETER IdentityEnd
    Absolute first byte after the identity record.
  .OUTPUTS
    Ordered component descriptors and the zlib records that supplied them.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][long]$IdentityEnd
  )

  $AuxiliaryOffsets = [Collections.Generic.HashSet[long]]::new()
  foreach ($AuxiliaryRecord in @($Catalog.AuxiliaryRecords)) { $null = $AuxiliaryOffsets.Add([long]$AuxiliaryRecord.Offset) }
  $Components = [Collections.Generic.List[object]]::new()
  $ComponentRecords = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in @($Record | Where-Object {
        $_.Offset -ge $IdentityEnd -and $_.EndOffset -le $Catalog.FileNameRecord.Offset -and
        -not $AuxiliaryOffsets.Contains([long]$_.Offset) -and $_.CompressedSize -le 1048576
      } | Sort-Object Offset)) {
    try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 1048576 }
    catch { continue }
    $Component = ConvertFrom-DeployMasterClassicComponentBlock -Bytes $Bytes -ComponentIndex $Components.Count
    if (-not $Component) { continue }
    $Components.Add($Component)
    $ComponentRecords.Add($Candidate)
  }
  return [pscustomobject]@{
    Components       = $Components.ToArray()
    ComponentRecords = $ComponentRecords.ToArray()
  }
}

function ConvertTo-DeployMasterEnvironmentPath {
  <#
  .SYNOPSIS
    Convert DeployMaster-private root variables to standard Windows environment variables.
  .PARAMETER Value
    Compiled DeployMaster path. Unknown and installer-relative variables are preserved verbatim.
  .OUTPUTS
    A path suitable for installed-state comparison and WinGet manifest projection.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value)

  if ($null -eq $Value) { return $null }
  $Result = $Value
  foreach ($Replacement in ([ordered]@{
        '%LOCALAPPDATAROOT%'  = '%LOCALAPPDATA%'
        '%APPDATAROOT%'       = '%APPDATA%'
        '%COMMONAPPDATAROOT%' = '%ProgramData%'
      }).GetEnumerator()) {
    $Result = $Result.Replace($Replacement.Key, $Replacement.Value, [StringComparison]::OrdinalIgnoreCase)
  }
  return $Result
}

function ConvertFrom-DeployMasterClassicIdentity {
  <#
  .SYNOPSIS
    Decode the Windows-1252 form-feed identity record used by DeployMaster 2.x.
  .PARAMETER Bytes
    Expanded classic identity bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Text = [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char]0)
  $Fields = $Text.Split([char]12)
  if ($Fields.Count -lt 17 -or [string]::IsNullOrWhiteSpace($Fields[2]) -or [string]::IsNullOrWhiteSpace($Fields[4])) {
    throw 'The classic DeployMaster identity record is incomplete.'
  }
  $ReleaseDate = $null
  $ReleaseDateValue = 0.0
  if ([double]::TryParse($Fields[5], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ReleaseDateValue)) {
    try { $ReleaseDate = [datetime]::FromOADate($ReleaseDateValue).Date } catch {}
  }
  $RawMachineInstallLocation = [string]$Fields[11]
  $RawUserInstallLocation = [string]$Fields[12]
  $RawMachineMenuLocation = [string]$Fields[13]
  $RawUserMenuLocation = [string]$Fields[14]
  return [pscustomobject]@{
    Publisher                 = $Fields[0]
    PublisherUrl              = $Fields[1]
    DisplayName               = $Fields[2]
    PackageUrl                = $Fields[3]
    DisplayVersion            = $Fields[4]
    ReleaseDateValue          = $Fields[5]
    ReleaseDate               = $ReleaseDate
    Copyright                 = $Fields[6]
    DisplayIconFileName       = $Fields[7]
    ReadmeFileName            = $Fields[8]
    LicenseFileName           = $Fields[9]
    SupportDll32FileName      = $Fields[10]
    MachineInstallLocation    = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineInstallLocation
    UserInstallLocation       = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserInstallLocation
    RawMachineInstallLocation = $RawMachineInstallLocation
    RawUserInstallLocation    = $RawUserInstallLocation
    MachineMenuLocation       = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineMenuLocation
    UserMenuLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserMenuLocation
    RawMachineMenuLocation    = $RawMachineMenuLocation
    RawUserMenuLocation       = $RawUserMenuLocation
    Description               = $Fields[15]
    AdditionalText            = $Fields[16]
    Fields                    = [string[]]$Fields
  }
}

function ConvertFrom-DeployMasterClassicInstallItemBlock {
  <#
  .SYNOPSIS
    Decode one flat classic file, shortcut, and URL-shortcut item stream.
  .PARAMETER Bytes
    Expanded zlib record. The record must be consumed exactly.
  .PARAMETER FileEntries
    Complete classic file catalog, including auxiliary entries at indexes zero through three.
  .PARAMETER GroupIndex
    Stable record-order index within the complete installation tree.
  .PARAMETER Directory
    Folder-tree destination that owns this item block.
  .PARAMETER ComponentIndex
    Zero-based component whose folder tree contains this item block.
  .OUTPUTS
    Installed files, file shortcuts, and URL shortcuts with their decoded destination and component.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$GroupIndex,
    [AllowNull()][string]$Directory,
    [AllowNull()][Nullable[int]]$ComponentIndex
  )

  if ($Bytes.Length -eq 0 -or ($Bytes[0] -band 0xF0) -notin 0x20, 0x40, 0x80) { return }
  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Files = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()

  function Read-DeployMasterClassicItemString {
    $Length = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    if ($Stream.Position + $Length -gt $Stream.Length) { throw 'The classic DeployMaster item string is truncated.' }
    if ($Length -eq 0) { return '' }
    $ValueBytes = [byte[]]::new($Length)
    if ($Stream.Read($ValueBytes, 0, $Length) -ne $Length) { throw 'The classic DeployMaster item string is truncated.' }
    return [Text.Encoding]::GetEncoding(1252).GetString($ValueBytes)
  }

  try {
    while ($Stream.Position -lt $Stream.Length) {
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      switch ($Opcode -band 0xF0) {
        0x80 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The classic DeployMaster file item index is outside the file catalog.' }
          $Entry = $FileEntries[$FileIndex]
          $ActionCode = [int]($Opcode -band 0x0F)
          $DestinationPath = if ([string]::IsNullOrWhiteSpace($Directory)) { $Entry.Name } else { "$Directory\$($Entry.Name)" }
          $Files.Add([pscustomobject]@{
              GroupIndex        = $GroupIndex
              ComponentIndex    = $ComponentIndex
              DestinationPath   = $DestinationPath
              Directory         = $Directory
              FileIndex         = $FileIndex
              SourceName        = $Entry.Name
              Included          = $true
              Architectures     = @('x86')
              FileAction        = $ActionCode
              OverwriteBehavior = switch ($ActionCode) { 0 { 'AlwaysOverwrite' } 1 { 'OverwriteIfNewer' } default { 'Unknown' } }
              NeverUninstall    = $false
              OpcodeFlags       = $ActionCode
              Flags             = $null
              OptionalArgument  = $null
            })
        }
        0x40 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The classic DeployMaster shortcut file index is outside the file catalog.' }
          $Values = @(Read-DeployMasterClassicItemString; Read-DeployMasterClassicItemString; Read-DeployMasterClassicItemString)
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $Shortcuts.Add([pscustomobject]@{
              GroupIndex = $GroupIndex; ComponentIndex = $ComponentIndex; Directory = $Directory; TargetFileIndex = $FileIndex
              TargetFile = $FileEntries[$FileIndex].Name; Values = $Values; Flags = $Flags
              Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 0x0F)
            })
        }
        0x20 {
          $Url = Read-DeployMasterClassicItemString
          $Name = Read-DeployMasterClassicItemString
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $UrlShortcuts.Add([pscustomobject]@{
              GroupIndex = $GroupIndex; ComponentIndex = $ComponentIndex; Directory = $Directory; Name = $Name; Url = $Url
              Flags = $Flags; Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 0x0F)
            })
        }
        default { throw "Unsupported classic DeployMaster item opcode 0x$($Opcode.ToString('X2'))." }
      }
    }
  } finally { $Stream.Dispose() }

  return [pscustomobject]@{
    GroupIndex     = $GroupIndex
    ComponentIndex = $ComponentIndex
    Directory      = $Directory
    Files          = $Files.ToArray()
    Shortcuts      = $Shortcuts.ToArray()
    UrlShortcuts   = $UrlShortcuts.ToArray()
  }
}

function Read-DeployMasterClassicInstallTreeNodeList {
  <#
  .SYNOPSIS
    Decode one recursive folder-node list from a classic DeployMaster installation tree.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER Cursor
    Reference to the absolute next unread byte. The function advances it past one node list.
  .PARAMETER EndOffset
    Exclusive absolute boundary of the classic behavior region.
  .PARAMETER RecordByOffset
    Validated zlib records keyed by their absolute record offset.
  .PARAMETER FileEntries
    Complete classic file-index namespace.
  .PARAMETER ComponentIndex
    Zero-based component that owns this root tree.
  .PARAMETER Directory
    Parent destination. Root node names are DeployMaster variables; nested names append to this path.
  .PARAMETER ResolveRootVariable
    Treat child names as root destination expressions rather than relative folder names.
  .PARAMETER GroupIndex
    Reference to the next stable item-group index.
  .PARAMETER Groups
    Output collection for decoded item groups.
  .PARAMETER Folders
    Output collection for decoded destination folders.
  .PARAMETER InstalledFiles
    Output collection for installed-file items.
  .PARAMETER Shortcuts
    Output collection for file shortcuts.
  .PARAMETER UrlShortcuts
    Output collection for URL shortcuts.
  .PARAMETER ItemRecords
    Output collection for zlib records consumed by 0xFE item markers.
  .PARAMETER Depth
    Current recursion depth, bounded to reject malformed trees.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ref]$Cursor,
    [Parameter(Mandatory)][long]$EndOffset,
    [Parameter(Mandatory)][hashtable]$RecordByOffset,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [AllowNull()][Nullable[int]]$ComponentIndex,
    [AllowNull()][string]$Directory,
    [switch]$ResolveRootVariable,
    [Parameter(Mandatory)][ref]$GroupIndex,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Groups,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Folders,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$InstalledFiles,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Shortcuts,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$UrlShortcuts,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$ItemRecords,
    [ValidateRange(0, 64)][int]$Depth = 0
  )

  if ($Depth -ge 64) { throw 'The classic DeployMaster installation tree exceeds the recursion limit.' }
  while ([long]$Cursor.Value -lt $EndOffset) {
    $Opcode = [byte](Read-BinaryInteger -Stream $Stream -Offset ([long]$Cursor.Value) -Size 1)
    $Cursor.Value = [long]$Cursor.Value + 1

    # 0xFF closes the current folder list. 0xFE attaches one compressed item stream to the
    # current directory and then closes the list, matching the classic runtime reader.
    if ($Opcode -eq 0xFF) { return }
    if ($Opcode -eq 0xFE) {
      $RecordKey = ([long]$Cursor.Value).ToString([Globalization.CultureInfo]::InvariantCulture)
      if (-not $RecordByOffset.ContainsKey($RecordKey)) { throw 'The classic DeployMaster installation tree points to an invalid item record.' }
      $Record = $RecordByOffset[$RecordKey]
      $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Record -MaximumBytes 4194304
      $Group = ConvertFrom-DeployMasterClassicInstallItemBlock -Bytes $Bytes -FileEntries $FileEntries -GroupIndex ([int]$GroupIndex.Value) -Directory $Directory -ComponentIndex $ComponentIndex
      if (-not $Group) { throw 'The classic DeployMaster installation tree contains an invalid item block.' }
      $Groups.Add($Group)
      foreach ($Item in @($Group.Files)) { $InstalledFiles.Add($Item) }
      foreach ($Item in @($Group.Shortcuts)) { $Shortcuts.Add($Item) }
      foreach ($Item in @($Group.UrlShortcuts)) { $UrlShortcuts.Add($Item) }
      $ItemRecords.Add($Record)
      $GroupIndex.Value = [int]$GroupIndex.Value + 1
      $Cursor.Value = [long]$Record.EndOffset
      return
    }

    # Values below 0xFE are byte-sized Windows-1252 folder-name lengths. The root call resolves
    # names such as %APPFOLDER%; recursive calls append ordinary subdirectory names.
    $NameLength = [int]$Opcode
    if ([long]$Cursor.Value + $NameLength -gt $EndOffset) { throw 'The classic DeployMaster installation folder name is truncated.' }
    $NameBytes = if ($NameLength) { Read-BinaryBytes -Stream $Stream -Offset ([long]$Cursor.Value) -Count $NameLength } else { [byte[]]::new(0) }
    $Cursor.Value = [long]$Cursor.Value + $NameLength
    $Name = [Text.Encoding]::GetEncoding(1252).GetString($NameBytes)
    if ($Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { throw 'The classic DeployMaster installation folder name is invalid.' }
    $ChildDirectory = if ($ResolveRootVariable -or [string]::IsNullOrWhiteSpace($Directory)) { $Name } elseif ([string]::IsNullOrEmpty($Name)) { $Directory } else { "$Directory\$Name" }
    $Folders.Add([pscustomobject]@{
        ComponentIndex = $ComponentIndex
        Name           = $Name
        FullName       = $ChildDirectory
        Parent         = $Directory
        Depth          = $Depth
      })
    Read-DeployMasterClassicInstallTreeNodeList -Stream $Stream -Cursor $Cursor -EndOffset $EndOffset -RecordByOffset $RecordByOffset -FileEntries $FileEntries -ComponentIndex $ComponentIndex -Directory $ChildDirectory -GroupIndex $GroupIndex -Groups $Groups -Folders $Folders -InstalledFiles $InstalledFiles -Shortcuts $Shortcuts -UrlShortcuts $UrlShortcuts -ItemRecords $ItemRecords -Depth ($Depth + 1)
  }
  throw 'The classic DeployMaster installation tree is truncated.'
}

function Read-DeployMasterClassicInstallTree {
  <#
  .SYNOPSIS
    Decode the component-indexed folder forests and item streams in classic DeployMaster media.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER StartOffset
    Absolute first folder opcode after the classic file-catalog columns.
  .PARAMETER EndOffset
    Exclusive boundary before the ordinary payload chain.
  .PARAMETER Record
    Validated zlib records that may be referenced by 0xFE item markers.
  .PARAMETER FileEntries
    Complete classic file-index namespace.
  .PARAMETER Components
    Ordered component catalog. The runtime serializes one root folder forest per component.
  .OUTPUTS
    Component-aware folders, item groups, installed files, shortcuts, consumed records, and the
    absolute first byte after the final component tree.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$StartOffset,
    [Parameter(Mandatory)][long]$EndOffset,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components
  )

  if ($StartOffset -lt 0 -or $EndOffset -le $StartOffset -or $EndOffset -gt $Stream.Length) { throw 'The classic DeployMaster installation-tree range is invalid.' }
  $RecordByOffset = @{}
  foreach ($Candidate in $Record) {
    if ($Candidate.Offset -ge $StartOffset -and $Candidate.EndOffset -le $EndOffset) {
      $RecordByOffset[([long]$Candidate.Offset).ToString([Globalization.CultureInfo]::InvariantCulture)] = $Candidate
    }
  }
  $Groups = [Collections.Generic.List[object]]::new()
  $Folders = [Collections.Generic.List[object]]::new()
  $InstalledFiles = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()
  $ItemRecords = [Collections.Generic.List[object]]::new()
  $Cursor = [long]$StartOffset
  $GroupIndex = 0
  $TreeCount = [Math]::Max(1, $Components.Count)
  for ($ComponentIndex = 0; $ComponentIndex -lt $TreeCount; $ComponentIndex++) {
    $PreviousCursor = $Cursor
    $ResolvedComponentIndex = if ($Components.Count) { [Nullable[int]]$ComponentIndex } else { $null }
    Read-DeployMasterClassicInstallTreeNodeList -Stream $Stream -Cursor ([ref]$Cursor) -EndOffset $EndOffset -RecordByOffset $RecordByOffset -FileEntries $FileEntries -ComponentIndex $ResolvedComponentIndex -ResolveRootVariable -GroupIndex ([ref]$GroupIndex) -Groups $Groups -Folders $Folders -InstalledFiles $InstalledFiles -Shortcuts $Shortcuts -UrlShortcuts $UrlShortcuts -ItemRecords $ItemRecords
    if ($Cursor -le $PreviousCursor) { throw 'The classic DeployMaster installation tree did not advance.' }
  }
  return [pscustomobject]@{
    StartOffset    = $StartOffset
    EndOffset      = $Cursor
    Groups         = $Groups.ToArray()
    Folders        = $Folders.ToArray()
    InstalledFiles = $InstalledFiles.ToArray()
    Shortcuts      = $Shortcuts.ToArray()
    UrlShortcuts   = $UrlShortcuts.ToArray()
    ItemRecords    = $ItemRecords.ToArray()
    ComponentCount = $TreeCount
  }
}

function Read-DeployMasterClassicBehavior {
  <#
  .SYNOPSIS
    Decode structurally identifiable registry and file-association records from classic media.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its original position.
  .PARAMETER Record
    Validated classic zlib records indexed for the complete logical package.
  .PARAMETER Catalog
    Validated filename catalog and contiguous payload chain. Records between the filename catalog
    and first payload are the bounded classic behavior region.
  .PARAMETER FileEntries
    Complete classic file-index namespace used to validate installation-item references.
  .PARAMETER Components
    Ordered classic component catalog. Each component owns one serialized destination tree.
  .PARAMETER Route
    Catalog-selected classic registry and association grammars.
  .OUTPUTS
    Parsed registry writes, associations, their source records, and unclassified bounded records.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components,
    [Parameter(Mandatory)][psobject]$Route
  )

  $PayloadStart = [long]$Catalog.Records[0].Offset
  $BehaviorRecords = @($Record | Where-Object {
      $_.Offset -ge $Catalog.FileNameRecord.EndOffset -and $_.EndOffset -le $PayloadStart
    } | Sort-Object Offset)
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $DeletedKeys = [Collections.Generic.List[object]]::new()
  $FileAssociations = [Collections.Generic.List[object]]::new()
  $RegistryRecords = [Collections.Generic.List[object]]::new()
  $AssociationRecords = [Collections.Generic.List[object]]::new()
  $ConsumedOffsets = [Collections.Generic.HashSet[long]]::new()

  # Raw folder opcodes and compressed item streams are interleaved. Decode the component-indexed
  # tree first, then classify only the standalone registry and association records that follow it.
  $InstallTree = Read-DeployMasterClassicInstallTree -Stream $Stream -StartOffset $Catalog.InstallTreeOffset -EndOffset $PayloadStart -Record $BehaviorRecords -FileEntries $FileEntries -Components $Components
  foreach ($ItemRecord in @($InstallTree.ItemRecords)) { $null = $ConsumedOffsets.Add([long]$ItemRecord.Offset) }

  foreach ($Candidate in $BehaviorRecords) {
    if ($ConsumedOffsets.Contains([long]$Candidate.Offset)) { continue }
    if ($Candidate.CompressedSize -gt 4194304) { continue }
    try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 4194304 }
    catch { continue }
    if ($Bytes.Length -eq 0) { continue }

    # Classic registry streams authenticate themselves with a root opcode followed by a literal
    # HKEY name. Exact stream consumption in the decoder prevents component or shortcut records
    # from being accepted merely because their first byte is also 0x01.
    if ($Bytes[0] -eq 1 -and $Bytes.Length -ge 7 -and [Text.Encoding]::ASCII.GetString($Bytes, 1, [Math]::Min(5, $Bytes.Length - 1)) -ceq 'HKEY_') {
      try {
        $Registry = ConvertFrom-DeployMasterRegistryBlock -Bytes $Bytes -ScopeValue 1 -Route $Route.RegistryRoute
        foreach ($Write in @($Registry.RegistryWrites)) { $RegistryWrites.Add($Write) }
        foreach ($DeletedKey in @($Registry.DeletedKeys)) { $DeletedKeys.Add($DeletedKey) }
        $RegistryRecords.Add($Candidate)
        $null = $ConsumedOffsets.Add([long]$Candidate.Offset)
        continue
      } catch { $Registry = $null }
    }

    # File-type records use their own form-feed string framing and one x86 executable index per
    # action. The extension grammar and exact end position reject unrelated legacy records.
    try {
      $Associations = @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $Bytes -Route $Route.AssociationRoute)
      if ($Associations.Count) {
        foreach ($Association in $Associations) { $FileAssociations.Add($Association) }
        $AssociationRecords.Add($Candidate)
        $null = $ConsumedOffsets.Add([long]$Candidate.Offset)
      }
    } catch { $Associations = @() }
  }

  return [pscustomobject][ordered]@{
    Registry              = [pscustomobject]@{ RegistryWrites = $RegistryWrites.ToArray(); DeletedKeys = $DeletedKeys.ToArray() }
    FileAssociations      = $FileAssociations.ToArray()
    RegistryRecords       = $RegistryRecords.ToArray()
    AssociationRecords    = $AssociationRecords.ToArray()
    InstallationFolders   = $InstallTree.Folders
    InstallItemGroups     = $InstallTree.Groups
    InstalledFiles        = $InstallTree.InstalledFiles
    Shortcuts             = $InstallTree.Shortcuts
    UrlShortcuts          = $InstallTree.UrlShortcuts
    InstallItemRecords    = $InstallTree.ItemRecords
    InstallTreeEndOffset  = $InstallTree.EndOffset
    UnclassifiedRecords   = @($BehaviorRecords | Where-Object { -not $ConsumedOffsets.Contains([long]$_.Offset) })
    BehaviorRecordCount   = $BehaviorRecords.Count
    RecognizedRecordCount = $ConsumedOffsets.Count
  }
}

function Read-DeployMasterClassicPackageData {
  <#
  .SYNOPSIS
    Parse the verified DeployMaster 2.x BZip2/zlib package route.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Route
    Catalog route selected from trusted PE identity and overlay magic.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Route
  )

  $PELayout = Get-PELayout -Stream $Stream
  $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  $LogicalEndCandidates = Get-DeployMasterClassicLogicalEndCandidate -Stream $Stream -PELayout $PELayout
  $Runtime = Get-DeployMasterClassicRuntimeRecord -Stream $Stream -OverlayOffset $OverlayOffset -MaximumEndOffset (($LogicalEndCandidates | Measure-Object -Maximum).Maximum)
  $RecordStart = $Runtime.MarkerOffset + 4
  $Records = @(Get-DeployMasterClassicZlibRecord -Stream $Stream -StartOffset $RecordStart -EndOffset (($LogicalEndCandidates | Measure-Object -Maximum).Maximum))
  $ByOffset = @{}
  foreach ($Record in $Records) { $ByOffset[([long]$Record.Offset).ToString([Globalization.CultureInfo]::InvariantCulture)] = $Record }
  $LanguageRecord = $ByOffset[$RecordStart.ToString([Globalization.CultureInfo]::InvariantCulture)]
  if (-not $LanguageRecord) { throw 'The classic DeployMaster language record is missing.' }
  $IdentityRecord = $ByOffset[([long]$LanguageRecord.EndOffset).ToString([Globalization.CultureInfo]::InvariantCulture)]
  if (-not $IdentityRecord) { throw 'The classic DeployMaster identity record is missing.' }
  $LanguageBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $LanguageRecord -MaximumBytes 4194304
  if ([Text.Encoding]::GetEncoding(1252).GetString($LanguageBytes) -notmatch '(?i)%s\s+Setup') { throw 'The classic DeployMaster language record is invalid.' }
  $IdentityBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $IdentityRecord -MaximumBytes 1048576
  $Identity = ConvertFrom-DeployMasterClassicIdentity -Bytes $IdentityBytes
  $Catalog = Find-DeployMasterClassicPayloadCatalog -Stream $Stream -Record $Records -LogicalEndCandidate $LogicalEndCandidates
  $Catalog = Complete-DeployMasterClassicFileCatalog -Stream $Stream -Record $Records -Catalog $Catalog -Identity $Identity -IdentityEnd $IdentityRecord.EndOffset
  $ComponentMetadata = Read-DeployMasterClassicComponentCatalog -Stream $Stream -Record $Records -Catalog $Catalog -IdentityEnd $IdentityRecord.EndOffset

  $FileEntries = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $Catalog.AllRecords.Count; $Index++) {
    $Record = $Catalog.AllRecords[$Index]
    $FileEntries.Add([pscustomobject]@{
        Index            = $Index
        Name             = [IO.Path]::GetFileName($Catalog.AllFileNames[$Index])
        FullName         = $Catalog.AllFileNames[$Index]
        Offset           = $Record.DataOffset
        RecordOffset     = $Record.Offset
        CompressedSize   = $Record.CompressedSize
        UncompressedSize = $Catalog.ExpandedSizes[$Index]
        EndOffset        = $Record.EndOffset
        Compression      = 'Zlib'
        Crc32            = $Catalog.Crc32Values[$Index]
        IsAuxiliary      = $Index -lt $Catalog.AuxiliaryCount
      })
  }
  $BehaviorMetadata = Read-DeployMasterClassicBehavior -Stream $Stream -Record $Records -Catalog $Catalog -FileEntries $FileEntries.ToArray() -Components $ComponentMetadata.Components -Route $Route
  return [pscustomobject]@{
    Route            = $Route
    PELayout         = $PELayout
    OverlayOffset    = $OverlayOffset
    LogicalEnd       = $Catalog.LogicalEnd
    Runtime          = $Runtime
    Header           = [pscustomobject]@{
      FormatProfile        = $Route.Id
      FormatVersion        = 2
      ObservedRuntimeRange = $Route.ObservedRuntimeRange
      ProfileEvidence      = $Route.Evidence
      LzmaProperties       = [byte[]]::new(0)
      CoreEntries          = @($Runtime)
    }
    LanguageBlock    = [pscustomobject]@{ Bytes = $LanguageBytes; Offset = $LanguageRecord.DataOffset; EndOffset = $LanguageRecord.EndOffset }
    IdentityBlock    = [pscustomobject]@{ Bytes = $IdentityBytes; Offset = $IdentityRecord.DataOffset; EndOffset = $IdentityRecord.EndOffset }
    FileNameBlock    = [pscustomobject]@{ Bytes = $Catalog.FileNameBytes; Offset = $Catalog.FileNameRecord.DataOffset; EndOffset = $Catalog.FileNameRecord.EndOffset }
    FileCatalog      = $Catalog
    Identity         = $Identity
    Components       = $ComponentMetadata.Components
    ComponentRecords = $ComponentMetadata.ComponentRecords
    BehaviorMetadata = $BehaviorMetadata
    FileEntries      = $FileEntries.ToArray()
  }
}

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
  # logical package size before hashing or following the package pointer. Signed media appends an
  # aligned Authenticode certificate table after the size recorded by DeployMaster.
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
  $PhysicalFileSize = [uint64]$Stream.Length
  $CertificateOffset = $null
  $CertificateSize = 0L
  $HasSignedEnvelope = $false
  if ($ExpectedFileSize -ne $PhysicalFileSize) {
    $Certificate = try { (Get-PELayout -Stream $Stream).DataDirectories['Certificate'] } catch { $null }
    if ($Certificate -and [long]$Certificate.Offset -ge 0 -and [long]$Certificate.Size -gt 0) {
      $AlignmentRemainder = $ExpectedFileSize % 8
      $AlignedExpectedFileSize = $ExpectedFileSize + ($AlignmentRemainder ? (8 - $AlignmentRemainder) : 0)
      $CertificateOffset = [long]$Certificate.Offset
      $CertificateSize = [long]$Certificate.Size
      if ([uint64]$CertificateOffset -eq $AlignedExpectedFileSize -and
        [uint64]($CertificateOffset + $CertificateSize) -eq $PhysicalFileSize) {
        $PaddingLength = [int]($AlignedExpectedFileSize - $ExpectedFileSize)
        $Padding = $PaddingLength ? (Read-BinaryBytes -Stream $Stream -Offset ([long]$ExpectedFileSize) -Count $PaddingLength) : [byte[]]::new(0)
        $HasSignedEnvelope = -not ($Padding | Where-Object { $_ -ne 0 } | Select-Object -First 1)
      }
    }
    if (-not $HasSignedEnvelope) { throw 'The DeployMaster package locator file-size check failed.' }
  }

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
    PhysicalFileSize  = $PhysicalFileSize
    HasSignedEnvelope = $HasSignedEnvelope
    CertificateOffset = $CertificateOffset
    CertificateSize   = $CertificateSize
    Reserved          = $Reserved
  }
}

function Get-DeployMasterPackageHeader {
  <#
  .SYNOPSIS
    Normalize catalog-backed DeployMaster package-control layouts
  .DESCRIPTION
    DeployMaster 6.0-6.1, 6.5-7.1, and 7.2+ samples use 66-, 70-, and 74-byte
    control headers. Candidate core ranges select the valid structural profile;
    the observed release ranges in the catalog are evidence, not dispatch keys.
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

  # Probe every cataloged layout through its range invariants. The installer PE version fields
  # contain the packaged application's version, so they cannot safely select a runtime profile.
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Layout in $Script:DeployMasterHeaderProfiles) {
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
        Profile              = $Layout
        Layout               = $Layout.Layout
        FormatVersion        = $Layout.Id
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
  $LayoutShift = [int]$Candidate.Profile.Shift
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
  # Windows release bounds were added in separate format revisions. Do not read absent fields:
  # the same bytes hold scope and core pointers in older profiles.
  $MinimumWindows10VersionCode = $null
  $MaximumWindows10VersionCode = $null
  if ($Candidate.Profile.HasWindows10Bounds) {
    $MinimumWindows10VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0D) -Size 2)
    $MaximumWindows10VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0F) -Size 2)
  }
  $MinimumWindows11VersionCode = $null
  $MaximumWindows11VersionCode = $null
  if ($Candidate.Profile.HasWindows11Bounds) {
    $MinimumWindows11VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x11) -Size 2)
    $MaximumWindows11VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x13) -Size 2)
  }
  $FirstCore = $Candidate.CoreEntries | Select-Object -First 1
  [pscustomobject]@{
    Layout                                = $Candidate.Profile.Layout
    FormatProfile                         = $Candidate.Profile.Id
    FormatVersion                         = $Candidate.FormatVersion
    ObservedRuntimeRange                  = $Candidate.Profile.ObservedRuntimeRange
    ProfileEvidence                       = $Candidate.Profile.Evidence
    FileTableKind                         = $Candidate.Profile.FileTableKind
    RegistryRoute                         = $Candidate.Profile.RegistryRoute
    AssociationRoute                      = $Candidate.Profile.AssociationRoute
    HasPackageSettings                    = [bool]$Candidate.Profile.HasPackageSettings
    UninstallCommandRoute                 = [string]$Candidate.Profile.UninstallCommandRoute
    HasInstallForAllUsersSwitch           = [bool]$Candidate.Profile.HasInstallForAllUsersSwitch
    HeaderSize                            = $Candidate.HeaderSize
    LzmaProperties                        = $Properties
    LzmaPropertyByte                      = [byte]$Properties[0]
    DictionarySize                        = $DictionarySize
    PlatformFlags                         = $PlatformFlags
    SupportedWindowsVersions              = $SupportedWindowsVersions.ToArray()
    SupportsFutureWindowsVersions         = [bool]((Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0C) -Size 1) -band 0x80)
    MinimumWindows10VersionCode           = $MinimumWindows10VersionCode
    MaximumWindows10VersionCode           = $MaximumWindows10VersionCode
    MinimumWindows11VersionCode           = $MinimumWindows11VersionCode
    MaximumWindows11VersionCode           = $MaximumWindows11VersionCode
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

function Test-DeployMasterRuntimeSwitch {
  <#
  .SYNOPSIS
    Confirm that a generated DeployMaster runtime recognizes a command-line switch.
  .DESCRIPTION
    Version-dependent setup switches are compiled into the compressed runtime core rather than
    the package metadata. This helper expands one bounded core and searches its UTF-16 string
    table, avoiding guesses from application-owned PE version resources.
  .PARAMETER Stream
    Caller-owned installer stream. The function does not dispose it.
  .PARAMETER Header
    Validated package header containing raw-LZMA properties and bounded runtime-core ranges.
  .PARAMETER CommandLineSwitch
    One or more literal slash-prefixed switches to locate in the runtime string table. Results are
    returned in the same order, allowing one bounded runtime expansion to serve several probes.
  .PARAMETER MaximumCoreBytes
    Maximum uncompressed runtime-core size accepted for this optional feature probe.
  #>
  [OutputType([bool[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Header,
    [Parameter(Mandatory)][ValidatePattern('^/[A-Za-z0-9]+$')][string[]]$CommandLineSwitch,
    [ValidateRange(1, 268435456)][long]$MaximumCoreBytes = 134217728
  )

  $Core = $Header.CoreEntries | Sort-Object { $_.Architecture -ne 'x86' } | Select-Object -First 1
  if (-not $Core -or $Core.UncompressedSize -gt $MaximumCoreBytes) { throw 'The DeployMaster runtime core is unavailable or exceeds the switch-probe limit.' }
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Core.Offset -Length $Core.CompressedSize -LeaveOpen
  $OutputStream = [IO.MemoryStream]::new([int][Math]::Min($Core.UncompressedSize, [int]::MaxValue))
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes $MaximumCoreBytes -Properties $Header.LzmaProperties -CompressedSize $Core.CompressedSize -UncompressedSize $Core.UncompressedSize
    $Results = [Collections.Generic.List[bool]]::new($CommandLineSwitch.Count)
    foreach ($RequestedSwitch in $CommandLineSwitch) {
      $Pattern = [Text.Encoding]::Unicode.GetBytes($RequestedSwitch)
      $Results.Add(@(Find-BinaryPattern -Stream $OutputStream -Pattern $Pattern -Maximum 1).Count -eq 1)
    }
    return $Results.ToArray()
  } finally {
    $InputStream.Dispose()
    $OutputStream.Dispose()
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
  $RawMachineInstallLocation = if ($IdentityScope) { $MachineLocationField.Substring(1) } else { $MachineLocationField.TrimStart([char]0) }
  $RawUserInstallLocation = [string]$Fields[12]
  $RawCommonFilesLocation = [string]$Fields[13]
  $RawCommonPublisherLocation = [string]$Fields[14]
  $RawMachineMenuLocation = [string]$Fields[15]
  $RawUserMenuLocation = [string]$Fields[16]
  $RawCommonDataLocation = [string]$Fields[17]
  $RawUserDataLocation = [string]$Fields[18]
  $MachineInstallLocation = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineInstallLocation
  $UserInstallLocation = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserInstallLocation
  $ReadmeFileName = [string]$Fields[7]
  $RawLicenseFileName = [string]$Fields[8]
  $LicenseRequiredEveryInstall = $RawLicenseFileName.StartsWith('*', [StringComparison]::Ordinal)
  $LicenseFileName = $RawLicenseFileName.TrimStart('*')
  $SupportDll32FileName = [string]$Fields[9]
  $SupportDll64FileName = [string]$Fields[10]
  # Readme, license, and architecture-specific support DLLs are catalogued before ordinary payload
  # names. Readme/license aliases can identify one physical entry, but x86 and x64 support DLLs are
  # separate catalog entries even when both use the same destination file name.
  $AuxiliaryFileNames = [Collections.Generic.List[string]]::new()
  $AuxiliaryFileNameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($AuxiliaryFileName in $ReadmeFileName, $LicenseFileName) {
    if (-not [string]::IsNullOrWhiteSpace($AuxiliaryFileName) -and $AuxiliaryFileNameSet.Add($AuxiliaryFileName)) { $AuxiliaryFileNames.Add($AuxiliaryFileName) }
  }
  foreach ($SupportDllFileName in $SupportDll32FileName, $SupportDll64FileName) {
    if (-not [string]::IsNullOrWhiteSpace($SupportDllFileName)) { $AuxiliaryFileNames.Add($SupportDllFileName) }
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
    RawMachineInstallLocation    = $RawMachineInstallLocation
    RawUserInstallLocation       = $RawUserInstallLocation
    CommonFilesLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonFilesLocation
    CommonPublisherLocation      = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonPublisherLocation
    MachineMenuLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineMenuLocation
    UserMenuLocation             = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserMenuLocation
    CommonDataLocation           = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonDataLocation
    UserDataLocation             = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserDataLocation
    RawCommonFilesLocation       = $RawCommonFilesLocation
    RawCommonPublisherLocation   = $RawCommonPublisherLocation
    RawMachineMenuLocation       = $RawMachineMenuLocation
    RawUserMenuLocation          = $RawUserMenuLocation
    RawCommonDataLocation        = $RawCommonDataLocation
    RawUserDataLocation          = $RawUserDataLocation
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
  .PARAMETER MaximumPaddingBytes
    Maximum reserved gap accepted between the decoded name block and the file catalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$SearchOffset,
    [Parameter(Mandatory)][long]$CatalogOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateRange(0, 4096)][int]$ExpectedCount,
    [ValidateRange(0, 64)][int]$MaximumPaddingBytes = 16
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
    # Archived 6.x media leaves 32 reserved bytes between the name block and the table. Keep the
    # accepted gap small enough that unrelated earlier text blocks cannot become candidates.
    if ($EndOffset -gt $CatalogOffset -or $CatalogOffset - $EndOffset -gt $MaximumPaddingBytes) { continue }
    try {
      $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Offset -Properties $Properties -Limit $CatalogOffset -MaximumBytes 1048576
      $Names = @($Utf8.GetString($Block.Bytes) -split "`r`n" | Where-Object { -not [string]::IsNullOrEmpty($_) })
      if ($Names.Count -ne $ExpectedCount -or $Names | Where-Object { $_ -match '[\x00-\x1F]' }) { continue }
      $Candidates.Add([pscustomobject]@{ Block = $Block; Names = [string[]]$Names; PaddingBytes = $CatalogOffset - $Block.EndOffset })
    } catch {}
  }
  if ($Candidates.Count -eq 0) { throw 'The DeployMaster file-name table could not be decoded.' }
  # Older metadata can contain an earlier data block that decodes to the same number of text lines.
  # The real name table is the valid candidate nearest the catalog; equal-distance candidates remain
  # ambiguous instead of being resolved from their text.
  $MinimumPadding = ($Candidates | Measure-Object -Property PaddingBytes -Minimum).Minimum
  $NearestCandidates = @($Candidates | Where-Object PaddingBytes -EQ $MinimumPadding)
  if ($NearestCandidates.Count -ne 1) { throw 'The DeployMaster file-name table could not be decoded unambiguously.' }
  return $NearestCandidates[0]
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
    # Reject suffixes of a longer valid offset run. Without this maximal-run check, every later
    # payload boundary can look like an independent table beginning at PackageDataOffset.
    if ($Index -ge 8) {
      $PreviousOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index - 8)
      if ($PreviousOffset -ge [uint64]$IdentityEnd -and $PreviousOffset -lt $FirstOffset) { continue }
    }

    $Boundaries = [Collections.Generic.List[long]]::new()
    $Cursor = $Index
    # Absolute payload offsets form a strictly increasing run terminated by the first non-offset.
    while ($Boundaries.Count -lt $MaximumEntries -and $Cursor + 8 -le $Metadata.Length) {
      $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor)
      if ($Value -lt [uint64]$IdentityEnd -or $Value -ge [uint64]$Stream.Length -or ($Boundaries.Count -and $Value -le [uint64]$Boundaries[$Boundaries.Count - 1])) { break }
      $Boundaries.Add([long]$Value)
      $Cursor += 8
    }
    # Current media can place an auxiliary license payload before PackageDataOffset while keeping
    # its absolute offset in the same boundary run. A valid full run must contain the package-data
    # boundary; suffixes beginning later in the payload cannot satisfy that condition.
    if ($Boundaries.Count -lt 2 -or $Boundaries -notcontains $PackageDataOffset) { continue }

    # The boundary run covers payloads stored at PackageDataOffset and later. Earlier releases can
    # keep one or more auxiliary payloads in the metadata gap as [stored-size][raw-size][data]
    # records, while retaining those entries in every parallel catalog column.
    foreach ($CandidateTableKind in $TableKind) {
      $MinimumEmbeddedCount = $CandidateTableKind -eq 'Legacy' ? 1 : 0
      # Both legacy and early Header74 media can omit metadata-resident auxiliary payload offsets
      # from the boundary run while retaining those records in every following catalog column.
      $MaximumEmbeddedCount = [Math]::Min(32, $MaximumEntries - $Boundaries.Count)
      for ($EmbeddedCount = $MinimumEmbeddedCount; $EmbeddedCount -le $MaximumEmbeddedCount; $EmbeddedCount++) {
        $EntryCount = $Boundaries.Count + $EmbeddedCount
        # Six parallel catalog columns follow: five UInt64 arrays and one UInt32 CRC32 array.
        $SerializedTableSize = (8 * $Boundaries.Count) + (36 * $EntryCount)
        if ($EntryCount -gt $MaximumEntries -or $Index + $SerializedTableSize -gt $Metadata.Length) { break }
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
        $EmbeddedSearchOffset = 0
        for ($EntryIndex = 0; $EntryIndex -lt $EmbeddedCount; $EntryIndex++) {
          if ($RawSizes[$EntryIndex] -gt [uint32]::MaxValue -or $StoredSizes[$EntryIndex] -gt [uint32]::MaxValue) { $Valid = $false; break }
          $HeaderPattern = [byte[]]::new(8)
          [BitConverter]::GetBytes([uint32]$StoredSizes[$EntryIndex]).CopyTo($HeaderPattern, 0)
          [BitConverter]::GetBytes([uint32]$RawSizes[$EntryIndex]).CopyTo($HeaderPattern, 4)
          $PatternMatches = @(Find-BinaryPattern -Bytes $Metadata -Pattern $HeaderPattern -StartOffset $EmbeddedSearchOffset -Length ($Index - $EmbeddedSearchOffset) -Maximum 2)
          $PatternMatches = @($PatternMatches | Where-Object { $_ + 8 + $StoredSizes[$EntryIndex] -le $Index })
          if ($PatternMatches.Count -ne 1) { $Valid = $false; break }
          $EmbeddedHeaderOffset = [int]$PatternMatches[0]
          $Offsets.Add($IdentityEnd + $EmbeddedHeaderOffset + 8)
          $EmbeddedSearchOffset = $EmbeddedHeaderOffset + 8 + $StoredSizes[$EntryIndex]
        }
        if (-not $Valid) { continue }
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
        for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
          if ($Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Stream.Length) { $Valid = $false; break }
          if ($EntryIndex -ge $EmbeddedCount -and $EntryIndex + 1 -lt $EntryCount -and
            $Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Offsets[$EntryIndex + 1]) { $Valid = $false; break }
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
              EmbeddedCount   = $EmbeddedCount
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
  }
  if ($Candidates.Count -eq 0) { throw 'The DeployMaster file table could not be located.' }

  # A table has no explicit entry count. Pair each structurally valid width with the adjacent name
  # block and retain only the width whose complete name count agrees with identity-resident files.
  $NamedCandidates = [Collections.Generic.List[object]]::new()
  foreach ($TableCandidate in $Candidates) {
    $RemainingNameCount = $TableCandidate.Offsets.Count - $Identity.AuxiliaryFileNames.Count
    if ($RemainingNameCount -lt 0) { continue }
    try {
      $NameResult = Get-DeployMasterFileNameBlock -Stream $Stream -SearchOffset ([Math]::Max($IdentityEnd, $IdentityEnd + $TableCandidate.TableOffset - 1048576)) -CatalogOffset ($IdentityEnd + $TableCandidate.TableOffset) -Properties $Properties -ExpectedCount $RemainingNameCount -MaximumPaddingBytes 64
      $NamedCandidates.Add([pscustomobject]@{ Table = $TableCandidate; Names = $NameResult })
    } catch {}
  }
  if ($NamedCandidates.Count -eq 0) { throw 'The DeployMaster file-name table does not identify a complete file catalog.' }
  if ($NamedCandidates.Count -ne 1) { throw 'The DeployMaster file table could not be located unambiguously.' }

  $Candidate = $NamedCandidates[0].Table
  $NameResult = $NamedCandidates[0].Names
  $Names = [Collections.Generic.List[string]]::new()
  foreach ($AuxiliaryFileName in $Identity.AuxiliaryFileNames) { $Names.Add($AuxiliaryFileName) }
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

  function Read-DeployMasterInstallTreeBranch([string]$ParentPath, [int]$ComponentIndex, [int]$Depth) {
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
      Read-DeployMasterInstallTreeBranch -ParentPath $FullPath -ComponentIndex $ComponentIndex -Depth ($Depth + 1)
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
          $FileAction = [int]($Opcode -band 3)
          $Architectures = [Collections.Generic.List[string]]::new(2)
          if ($Flags -band 0x01) { $Architectures.Add('x86') }
          if ($Flags -band 0x02) { $Architectures.Add('x64') }
          $Files.Add([pscustomobject]@{
              ComponentIndex    = $ComponentIndex
              DestinationPath   = $InstalledPath
              Directory         = $ParentPath
              FileIndex         = $FileIndex
              SourceName        = $Entry.Name
              Included          = $Architectures.Count -gt 0
              Architectures     = $Architectures.ToArray()
              FileAction        = $FileAction
              OverwriteBehavior = switch ($FileAction) { 0 { 'AlwaysOverwrite' } 1 { 'OverwriteIfNewer' } 2 { 'NeverOverwrite' } default { 'Unknown' } }
              NeverUninstall    = [bool]($Opcode -band 0x04)
              OpcodeFlags       = [byte]($Opcode -band 0x0F)
              Flags             = $Flags
              OptionalArgument  = $OptionalArgument
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
      Read-DeployMasterInstallTreeBranch -ParentPath '' -ComponentIndex $ComponentIndex -Depth 0
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
  .PARAMETER Route
    Catalog-selected registry stream grammar. Header66 media uses a legacy delimiter and opcode
    map; newer profiles use the current operation stream.
  .PARAMETER MaximumDepth
    Maximum nested registry-key depth.
  .PARAMETER MaximumOperations
    Maximum opcode count accepted across all roots.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, 255)][int]$ScopeValue,
    [ValidateSet('Opcode', 'LegacyDelimited', 'ClassicNullTerminatedAnsi')][string]$Route = 'Opcode',
    [ValidateRange(1, 128)][int]$MaximumDepth = 64,
    [ValidateRange(1, 1048576)][int]$MaximumOperations = 65536
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Writes = [Collections.Generic.List[object]]::new()
  $DeletedKeys = [Collections.Generic.List[object]]::new()
  $OperationCount = 0

  function Read-DeployMasterRegistryString {
    if ($Route -ne 'ClassicNullTerminatedAnsi') { return Read-DeployMasterStreamString -Stream $Stream }
    $Start = $Stream.Position
    while ($Stream.Position -lt $Stream.Length -and $Stream.ReadByte() -ne 0) {
      if ($Stream.Position - $Start -gt 65535) { throw 'The classic DeployMaster registry string exceeds the configured limit.' }
    }
    if ($Stream.Position -gt $Stream.Length -or ($Stream.Position -eq $Stream.Length -and $Bytes[$Bytes.Length - 1] -ne 0)) { throw 'The classic DeployMaster registry string is not terminated.' }
    return [Text.Encoding]::GetEncoding(1252).GetString($Bytes, [int]$Start, [int]($Stream.Position - $Start - 1))
  }

  function Read-DeployMasterRegistryBranch([string]$Root, [string]$Key, [int]$Depth) {
    if ($Depth -gt $MaximumDepth) { throw 'The DeployMaster registry-tree depth exceeds the configured limit.' }
    $ValueName = ''
    $KeepExisting = $false
    while ($true) {
      $OperationCount++
      if ($OperationCount -gt $MaximumOperations) { throw 'The DeployMaster registry operation count exceeds the configured limit.' }
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($Route -in 'LegacyDelimited', 'ClassicNullTerminatedAnsi') {
        # DeployMaster 6.0.x serializes a depth-first key tree. 0x1F separates child-key records
        # from value records, 0x02 selects a value name, and 0x04 writes its REG_SZ data.
        switch ($Opcode) {
          0x01 {
            $Child = Read-DeployMasterRegistryString
            $ChildKey = [string]::IsNullOrEmpty($Key) ? $Child : "$($Key.TrimEnd('\'))\$Child"
            Read-DeployMasterRegistryBranch -Root $Root -Key $ChildKey -Depth ($Depth + 1)
          }
          0x1F { }
          0x02 {
            $ValueName = Read-DeployMasterRegistryString
            if ($ValueName -ceq '(Default)') { $ValueName = '' }
          }
          0x04 {
            $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = Read-DeployMasterRegistryString; Type = 'REG_SZ'; OnlyIfMissing = $false; Evidence = 'DeployMaster legacy registry operation stream' })
          }
          0x05 {
            if ($Route -ne 'ClassicNullTerminatedAnsi') { throw 'DeployMaster header-based legacy registry media uses an unsupported DWORD opcode.' }
            $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = [uint32](Read-BinarySequentialInteger -Stream $Stream -Size 4); Type = 'REG_DWORD'; OnlyIfMissing = $false; Evidence = 'DeployMaster classic registry operation stream' })
          }
          0xFF { return }
          default { throw "Unsupported DeployMaster legacy registry opcode 0x$($Opcode.ToString('X2'))." }
        }
        continue
      }
      switch ($Opcode) {
        0x01 {
          $Child = Read-DeployMasterStreamString -Stream $Stream
          $ChildKey = [string]::IsNullOrEmpty($Key) ? $Child : "$($Key.TrimEnd('\'))\$Child"
          Read-DeployMasterRegistryBranch -Root $Root -Key $ChildKey -Depth ($Depth + 1)
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
      $EncodedRoot = Read-DeployMasterRegistryString
      $Root = switch ($EncodedRoot) {
        'HKEY_AUTO' { switch ($ScopeValue) { 0 { 'HKCU' } 1 { 'HKLM' } default { 'SHCTX' } } }
        'HKEY_CLASSES_ROOT' { 'HKCR' }
        'HKEY_CURRENT_USER' { 'HKCU' }
        'HKEY_LOCAL_MACHINE' { 'HKLM' }
        'HKEY_USERS' { 'HKU' }
        default { throw "Unsupported DeployMaster registry root '$EncodedRoot'." }
      }
      Read-DeployMasterRegistryBranch -Root $Root -Key '' -Depth 0
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

function Read-DeployMasterTrailingRecord {
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

  function Read-DeployMasterTrailingTextBlock([ref]$Cursor) {
    $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Cursor.Value -Properties $Properties -Limit $Limit -MaximumBytes 4194304
    $Cursor.Value = $Block.EndOffset
    $Text = ConvertFrom-DeployMasterTextBlock -Bytes $Block.Bytes
    return [pscustomobject]@{ Block = $Block; Text = $Text.Text; Fields = $Text.Fields; Encoding = $Text.Encoding }
  }
  function Read-DeployMasterTrailingInteger([ref]$Cursor, [int]$Size, [switch]$Signed) {
    if ($Cursor.Value + $Size -gt $Limit) { throw 'The DeployMaster trailing metadata is truncated.' }
    $Value = Read-BinaryInteger -Stream $Stream -Offset $Cursor.Value -Size $Size -Signed:$Signed
    $Cursor.Value += $Size
    return $Value
  }
  function ConvertTo-DeployMasterTrailingTextList([AllowNull()][psobject]$Record) {
    if ($null -eq $Record) { return [string[]]@() }
    # The builder accepts semicolon-separated values in each UI line. Normalize both delimiters
    # while retaining the original text block below for exact format evidence.
    return [string[]]@($Record.Fields | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }

  $Cursor = $Offset
  $Prerequisites = [Collections.Generic.List[object]]::new()
  $FrameworkFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $Framework = $null
  if ($FrameworkFlags) {
    $FrameworkVersionCode = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
    $Descriptor = Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster .NET prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Framework = ConvertFrom-DeployMasterDotNetFrameworkRecord -Flags $FrameworkFlags -VersionCode $FrameworkVersionCode -Descriptor $Descriptor -RawValues $RawValues
    $Prerequisites.Add($Framework)
  }

  $CustomCount = [long](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 4 -Signed)
  if ($CustomCount -lt 0 -or $CustomCount -gt 256) { throw 'The DeployMaster custom prerequisite count is invalid.' }
  for ($Index = 0; $Index -lt $CustomCount; $Index++) {
    $Descriptor = Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster custom prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Prerequisites.Add([pscustomobject]@{
        Kind = 'Custom'; Index = $Index; Descriptor = $Descriptor.Text
        DescriptorFields = $Descriptor.Fields; RawValues = $RawValues
      })
  }

  # Completion flags are followed by optional architecture-specific launch indexes and arguments.
  $CompletionFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $Launch32FileIndex = if ($CompletionFlags -band 4) { [int](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $Launch64FileIndex = if ($CompletionFlags -band 8) { [int](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $LaunchArguments = (($CompletionFlags -band 0x0C) -ne 0) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)).Text : $null

  $PreUninstall32FileIndex = [int16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  $PreUninstall64FileIndex = [int16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  # Archived 6.0/6.5 media uses two zero indexes for an absent pre-uninstall command, while 7.1+
  # uses 0xFFFF. Accept zero only when the record has exactly the fixed six-byte suffix remaining;
  # otherwise index zero remains a valid reference and must be followed by its argument block.
  if ($PreUninstall32FileIndex -eq 0 -and $PreUninstall64FileIndex -eq 0 -and $Limit - $Cursor -eq 6) {
    $PreUninstall32FileIndex = -1
    $PreUninstall64FileIndex = -1
  }
  $PreUninstallArguments = ($PreUninstall32FileIndex -ne -1 -or $PreUninstall64FileIndex -ne -1) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)).Text : $null
  $UninstallShortcutFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $UninstallShortcutReferenceValue = [uint16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2)
  $UninstallShortcutReference = if ($UninstallShortcutReferenceValue -eq [uint16]::MaxValue) { $null } else { [int]$UninstallShortcutReferenceValue }

  # The final three-byte update header gates up to three following compressed-string records.
  $UpdateFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $RequiredReleaseDay = [uint16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2)
  $PatchRequirement = ($UpdateFlags -band 2) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowClasses = ($UpdateFlags -band 4) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowCaptions = ($UpdateFlags -band 8) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
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
      PatchRequirementLines   = ConvertTo-DeployMasterTrailingTextList -Record $PatchRequirement
      BlockedWindowClasses    = ConvertTo-DeployMasterTrailingTextList -Record $BlockedWindowClasses
      BlockedWindowCaptions   = ConvertTo-DeployMasterTrailingTextList -Record $BlockedWindowCaptions
      RawRecords              = [pscustomobject]@{
        PatchRequirement      = $PatchRequirement
        BlockedWindowClasses  = $BlockedWindowClasses
        BlockedWindowCaptions = $BlockedWindowCaptions
      }
    }
  }
}

function Find-DeployMasterComponentBlock {
  <#
  .SYNOPSIS
    Locate the component block when no auxiliary payload supplies its leading boundary.
  .PARAMETER Stream
    Caller-owned installer stream. Random-access reads restore its original position.
  .PARAMETER MinimumOffset
    Absolute lower bound of the metadata range following the identity block.
  .PARAMETER NameBlockOffset
    Absolute offset of the file-name block; the component block must end exactly here.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  .PARAMETER MaximumScanBytes
    Maximum metadata suffix inspected for a size-framed component block.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$MinimumOffset,
    [Parameter(Mandatory)][long]$NameBlockOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [ValidateRange(1, 4194304)][int]$MaximumScanBytes = 1048576
  )

  $SearchOffset = [Math]::Max($MinimumOffset, $NameBlockOffset - $MaximumScanBytes)
  $SearchLength = $NameBlockOffset - $SearchOffset
  if ($SearchLength -lt 4 -or $SearchLength -gt [int]::MaxValue) { throw 'The DeployMaster component-search range is invalid.' }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $SearchOffset -Count ([int]$SearchLength)
  $Candidates = [Collections.Generic.List[object]]::new()

  # Component records have no pointer from the surrounding metadata. Authenticate candidates by
  # their exact end boundary and by complete decoding of the component catalog.
  for ($Index = 0; $Index + 4 -le $Metadata.Length; $Index++) {
    $Size = [BitConverter]::ToInt32($Metadata, $Index)
    if ($Size -eq [int]::MinValue) { continue }
    $RelativeEnd = if ($Size -eq 0) {
      $Index + 4
    } elseif ($Size -lt 0) {
      $Index + 4 - $Size
    } elseif ($Index + 8 -le $Metadata.Length) {
      $StoredSize = [BitConverter]::ToInt32($Metadata, $Index + 4)
      $StoredSize -gt 0 ? $Index + 8 + $StoredSize : -1
    } else {
      -1
    }
    if ($RelativeEnd -ne $Metadata.Length) { continue }
    try {
      $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset ($SearchOffset + $Index) -Properties $Properties -Limit $NameBlockOffset -MaximumBytes 4194304
      $Components = @(ConvertFrom-DeployMasterComponentBlock -Bytes $Block.Bytes)
      $Candidates.Add([pscustomobject]@{ Block = $Block; Components = $Components })
    } catch {}
  }

  if ($Candidates.Count -eq 0) { throw 'The DeployMaster component block could not be located before the file-name catalog.' }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster component block could not be located unambiguously.' }
  return $Candidates[0]
}

function Read-DeployMasterStructuredRecord {
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
  if ($MetadataResidentFiles.Count) {
    # Readme, license, and support-DLL payloads precede the component block when configured. Their
    # furthest physical end is therefore the exact next-record boundary.
    $ComponentOffset = [long](($MetadataResidentFiles | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum)
    $ComponentBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $ComponentOffset -Properties $Header.LzmaProperties -Limit $NameBlockOffset -MaximumBytes 4194304
    if ($ComponentBlock.EndOffset -ne $NameBlockOffset) { throw 'The DeployMaster component block is not adjacent to the file-name catalog.' }
    $Components = @(ConvertFrom-DeployMasterComponentBlock -Bytes $ComponentBlock.Bytes)
  } else {
    # License-free projects have no file-table record from which to derive the leading boundary.
    # Search only the bounded metadata suffix and require exact component-catalog consumption.
    $ComponentResult = Find-DeployMasterComponentBlock -Stream $Stream -MinimumOffset $IdentityEnd -NameBlockOffset $NameBlockOffset -Properties $Header.LzmaProperties
    $ComponentBlock = $ComponentResult.Block
    $Components = @($ComponentResult.Components)
  }

  $InstallTreeBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ([long]$FileEntries[0].CatalogEndOffset) -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $InstallTree = ConvertFrom-DeployMasterInstallTreeBlock -Bytes $InstallTreeBlock.Bytes -Components $Components -FileEntries $FileEntries
  $RegistryBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $InstallTreeBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $Registry = if ($RegistryBlock.Bytes.Length) { ConvertFrom-DeployMasterRegistryBlock -Bytes $RegistryBlock.Bytes -ScopeValue $ScopeValue -Route $Header.RegistryRoute } else { [pscustomobject]@{ RegistryWrites = @(); DeletedKeys = @() } }
  $AssociationBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $RegistryBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 4194304
  $FileAssociations = if ($AssociationBlock.Bytes.Length) { @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $AssociationBlock.Bytes -Route $Header.AssociationRoute) } else { @() }
  $Trailing = Read-DeployMasterTrailingRecord -Stream $Stream -Offset $AssociationBlock.EndOffset -Limit $Locator.PackageDataOffset -Properties $Header.LzmaProperties

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
  .PARAMETER Route
    Catalog-selected string and record framing used by the current header profile.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateSet('Auto', 'LengthPrefixedUtf8', 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi')][string]$Route = 'LengthPrefixedUtf8'
  )

  # The block begins with a bounded association count followed by sequential
  # variable-length records. Any trailing or truncated data rejects the block.
  if ($Bytes.Length -lt 2) { throw 'The DeployMaster file-type record is too small.' }
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Cursor = 0
  $Count = [int]$Bytes[$Cursor++]
  if ($Count -lt 1 -or $Count -gt 64) { throw 'The DeployMaster file-type count is invalid.' }
  # Header74 spans the association serialization transition. Current records add a Boolean default
  # flag after the count; archived 7.2 media begins directly with a form-feed-terminated description.
  if ($Route -eq 'Auto') { $Route = $Cursor -lt $Bytes.Length -and $Bytes[$Cursor] -in 0, 1 ? 'LengthPrefixedUtf8' : 'FormFeedDelimitedAnsi' }

  function Read-DeployMasterAssociationUInt16([ref]$Position) {
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
  function Read-DeployMasterAssociationInt16([ref]$Position) {
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
  function Read-DeployMasterAssociationString([ref]$Position) {
    <#
    .SYNOPSIS
      Read a uint16-length-prefixed UTF-8 association string.
    .PARAMETER Position
      Mutable block-relative cursor advanced across the length field and string bytes.
    #>
    if ($Route -in 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi') {
      $End = $Position.Value
      while ($End -lt $Bytes.Length -and $Bytes[$End] -ne 0x0C) { $End++ }
      if ($End -ge $Bytes.Length) { throw 'The legacy DeployMaster file-type string is not terminated.' }
      $Value = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Position.Value, $End - $Position.Value)
      $Position.Value = $End + 1
      return $Value
    }
    $Length = [int](Read-DeployMasterAssociationUInt16 -Position $Position)
    if ($Position.Value + $Length -gt $Bytes.Length) { throw 'The DeployMaster file-type string is truncated.' }
    $Value = $Utf8.GetString($Bytes, $Position.Value, $Length)
    $Position.Value += $Length
    return $Value
  }

  $Associations = [Collections.Generic.List[object]]::new()
  # Each association contains architecture-specific icon references and a nested
  # action list. Preserve file indexes for later catalog resolution.
  for ($AssociationIndex = 0; $AssociationIndex -lt $Count; $AssociationIndex++) {
    if ($Route -in 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi') {
      $CreateByDefault = $null
    } else {
      if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -notin 0, 1) { throw 'The DeployMaster file-type default flag is invalid.' }
      $CreateByDefault = [bool]$Bytes[$Cursor++]
    }
    $Description = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
    $Extension = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') { throw 'The DeployMaster file-type extension is invalid.' }
    $Icon32FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 32-bit icon record is truncated.' }
    $Icon32ResourceIndex = [int]$Bytes[$Cursor++]
    if ($Route -eq 'ClassicFormFeedAnsi') {
      $Icon64FileIndex = -1
      $Icon64ResourceIndex = -1
    } else {
      $Icon64FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
      if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 64-bit icon record is truncated.' }
      $Icon64ResourceIndex = [int]$Bytes[$Cursor++]
    }
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster file-type action count is missing.' }
    $ActionCount = [int]$Bytes[$Cursor++]
    if ($ActionCount -gt 64) { throw 'The DeployMaster file-type action count is invalid.' }
    $Actions = [Collections.Generic.List[object]]::new()
    # Current actions carry separate x86/x64 executable indexes. Classic 2.x carries one x86 index;
    # normalize its absent x64 index to -1 and never invoke any recorded command.
    for ($ActionIndex = 0; $ActionIndex -lt $ActionCount; $ActionIndex++) {
      $ActionName = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
      $Executable32FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
      $Executable64FileIndex = $Route -eq 'ClassicFormFeedAnsi' ? -1 : (Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor))
      $Actions.Add([pscustomobject]@{
          Name                  = $ActionName
          Executable32FileIndex = $Executable32FileIndex
          Executable64FileIndex = $Executable64FileIndex
          Parameters            = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
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
  if (-not $Identity.LocationMarkerMatchesScope) { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Scope.IdentityMarkerMismatch' -Source 'DeployMaster' -Message 'The DeployMaster identity scope marker does not match the package-control scope byte.' -Kind Mismatch -Areas Metadata, Installability -AffectedFields Scope -Evidence $Identity)) }
  try { $FileEntries = @(Get-DeployMasterFileEntry -Stream $Stream -Identity $Identity -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties -TableKind $Header.FileTableKind) }
  catch {
    $FileEntries = @()
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Extraction.FileTableIncomplete' -Source 'DeployMaster' -Message "The DeployMaster payload file table was not decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Extraction -AffectedFields InstallationMetadata -Evidence $_.Exception.Message))
  }
  try {
    $StructuredMetadata = Read-DeployMasterStructuredRecord -Stream $Stream -Header $Header -Locator $Locator -IdentityEnd $IdentityBlock.EndOffset -FileEntries $FileEntries -ScopeValue $Identity.EffectiveScopeValue
    $FileAssociations = @($StructuredMetadata.FileAssociations)
  } catch {
    $StructuredError = $_.Exception.Message
    $StructuredMetadata = $null
    # Legacy packages predate some current metadata records. Preserve the proven association fallback
    # while reporting that the remaining behavioral model is incomplete.
    try { $FileAssociations = @(Get-DeployMasterFileAssociation -Stream $Stream -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties) }
    catch { $FileAssociations = @() }
    $PackageSettings = $null
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.BehavioralStreamIncomplete' -Source 'DeployMaster' -Message "The DeployMaster behavioral metadata stream was not fully decoded: $StructuredError" -Kind Incomplete -Areas Metadata -AffectedFields RegistryWrites, FileExtensions, Protocols -Evidence $StructuredError))
  }
  $PackageSettings = $null
  if ($StructuredMetadata -and $Header.HasPackageSettings) {
    try {
      # The common record is three bytes. Portable-mode values other than Never append marker and
      # drive-policy bytes plus a compressed default-folder block; reading five bytes unconditionally
      # consumed the next record in ordinary 7.2/7.6 packages.
      $ConfigurationBytes = Read-BinaryBytes -Stream $Stream -Offset $IdentityBlock.EndOffset -Count 3
      if ($ConfigurationBytes[2] -gt 2) {
        throw 'The candidate package-settings bytes contain values outside the controlled option ranges.'
      }
      $PortableModeEnabled = $ConfigurationBytes[2] -ne 0
      $PortableBytes = if ($PortableModeEnabled) { Read-BinaryBytes -Stream $Stream -Offset ($IdentityBlock.EndOffset + 3) -Count 2 } else { [byte[]](0, 0) }
      if ($PortableBytes[0] -gt 2 -or $PortableBytes[1] -gt 1) { throw 'The candidate portable-settings bytes contain values outside the controlled option ranges.' }
      $PortableFolder = $null
      if ($PortableModeEnabled) {
        try {
          $PortableFolderBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ($IdentityBlock.EndOffset + 5) -Properties $Header.LzmaProperties -Limit $StructuredMetadata.ComponentBlock.Offset -MaximumBytes 65535
          $PortableFolder = (ConvertFrom-DeployMasterTextBlock -Bytes $PortableFolderBlock.Bytes).Text
        } catch {}
      }
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
        PortableMarkerMode            = switch ($PortableBytes[0]) { 0 { 'Never' } 1 { 'WhenAnyDriveIsAllowed' } 2 { 'Always' } default { 'Unknown' } }
        PortableMarkerModeValue       = $PortableBytes[0]
        PortableAllowAnyDrive         = [bool]$PortableBytes[1]
        PortableDefaultFolder         = $PortableFolder
      }
    } catch { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.PackageSettingsIncomplete' -Source 'DeployMaster' -Message "The DeployMaster current-generation package settings were not decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $_.Exception.Message)) }
  }
  $RuntimeFeatures = [pscustomobject]@{
    PortableSwitch         = $false
    PortableSwitchAnalyzed = $false
    SkipElevationSwitch    = $false
    SkipElevationAnalyzed  = $false
  }
  # Command support lives in the compressed runtime, not the package header. Probe every relevant
  # token in one expansion and do not extrapolate /noadmin back to Header66, where it is absent.
  $RequestedRuntimeSwitches = [Collections.Generic.List[string]]::new()
  $RequestedRuntimeSwitches.Add('/noadmin')
  if ($PackageSettings -and $PackageSettings.PortableInstallationMode -ne 'Never') { $RequestedRuntimeSwitches.Add('/portable') }
  try {
    $RuntimeSwitchResults = @(Test-DeployMasterRuntimeSwitch -Stream $Stream -Header $Header -CommandLineSwitch $RequestedRuntimeSwitches.ToArray())
    $RuntimeFeatures.SkipElevationSwitch = $RuntimeSwitchResults[0]
    $RuntimeFeatures.SkipElevationAnalyzed = $true
    if ($RequestedRuntimeSwitches.Count -gt 1) {
      $RuntimeFeatures.PortableSwitch = $RuntimeSwitchResults[1]
      $RuntimeFeatures.PortableSwitchAnalyzed = $true
    }
  } catch {
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.RuntimeSwitchInspectionIncomplete' -Source 'DeployMaster' -Message "The DeployMaster runtime core could not be inspected for version-dependent command-line switches: $($_.Exception.Message)" -Kind Incomplete -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $_.Exception.Message))
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
    RuntimeFeatures    = $RuntimeFeatures
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
  .PARAMETER Root
    Concrete registry hive or conditional root used by the projected write.
  .PARAMETER Key
    Registry key relative to the selected root.
  .PARAMETER Type
    Registry value type written by the DeployMaster runtime.
  .PARAMETER Evidence
    Source description attached to the registry operation.
  .PARAMETER Condition
    Optional scope condition for a dual-scope registration variant.
  #>
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][object]$Value,
    [string]$Root = $PackageData.Identity.RegistryRoot,
    [string]$Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)",
    [ValidateSet('REG_SZ', 'REG_DWORD', 'REG_BINARY')][string]$Type = 'REG_SZ',
    [string]$Evidence = 'DeployMaster structured identity and built-in uninstaller configuration',
    [string]$Condition
  )

  [pscustomobject]@{
    Root      = $Root
    Key       = $Key
    Name      = $Name
    Value     = $Value
    Type      = $Type
    Condition = $Condition
    Evidence  = $Evidence
  }
}

function Get-DeployMasterBuiltInRegistration {
  <#
  .SYNOPSIS
    Reconstruct one scope-specific DeployMaster uninstall registration.
  .PARAMETER PackageData
    Parsed DeployMaster package model containing the structured identity and format route.
  .PARAMETER Scope
    Normal-install scope whose concrete registry hive and installation path are projected.
  .PARAMETER InstallLocation
    Manifest-safe destination path compiled for this scope.
  .PARAMETER RegistryView
    Registry view selected by the compiled application architecture mode.
  .PARAMETER TargetArchitecture
    Concrete application architecture used to select an architecture-specific generated uninstaller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$Scope,
    [Parameter(Mandatory)][string]$InstallLocation,
    [Parameter(Mandatory)][string]$RegistryView,
    [ValidateSet('x86', 'x64')][string]$TargetArchitecture
  )

  $Root = $Scope -eq 'machine' ? 'HKLM' : 'HKCU'
  $Condition = $PackageData.Identity.SupportsDualScope ? "Normal installation uses $Scope scope" : $null
  $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)"
  $UninstallerFileName = switch ($PackageData.Header.ApplicationArchitectureMode) {
    'x86AndX64Application' {
      if (-not $TargetArchitecture) { throw 'A concrete target architecture is required for a mixed-architecture DeployMaster uninstall registration.' }
      # Mixed media stores distinguishable UnDeploy32/UnDeploy64 payload records, but the runtime
      # installs the selected x86 payload under the ordinary UnDeploy.exe name.
      $TargetArchitecture -eq 'x64' ? 'UnDeploy64.exe' : 'UnDeploy.exe'
    }
    'x64Application' { 'UnDeploy64.exe' }
    default { 'UnDeploy.exe' }
  }
  $UninstallerPath = "$($InstallLocation.TrimEnd('\'))\$UninstallerFileName"
  $DeploymentLogPath = "$($InstallLocation.TrimEnd('\'))\Deploy.log"

  # DeployMaster 7.2 quotes both paths. Controlled VM installations of archived 6.0.1 and 6.5.1
  # media prove that the earlier runtime left the executable path unquoted but quoted the log.
  $UninstallString = switch ($PackageData.Header.UninstallCommandRoute) {
    'QuotedExecutableAndLog' { "`"$UninstallerPath`" `"$DeploymentLogPath`"" }
    'UnquotedExecutableQuotedLog' { "$UninstallerPath `"$DeploymentLogPath`"" }
    default { throw "Unsupported DeployMaster uninstall command route '$($PackageData.Header.UninstallCommandRoute)'." }
  }
  $Writes = [Collections.Generic.List[object]]::new()
  # The runtime writes HelpLink and URLInfoUpdate from the application URL and falls back to the
  # publisher URL when no application URL is configured; the dual-conditional gate is byte-identical
  # in the 6.0.1 through 7.7.0 runtime decompiles.
  $HelpLinkValue = $PackageData.Identity.PackageUrl
  if ([string]::IsNullOrWhiteSpace([string]$HelpLinkValue)) {
    $HelpLinkValue = $PackageData.Identity.PublisherUrl
  }
  $ValueRecords = @(
    [pscustomobject]@{ Name = 'DisplayName'; Value = $PackageData.Identity.DisplayName; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'UninstallString'; Value = $UninstallString; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'NoModify'; Value = 1; Type = 'REG_DWORD' }
    [pscustomobject]@{ Name = 'NoRepair'; Value = 1; Type = 'REG_DWORD' }
    [pscustomobject]@{ Name = 'InstallLocation'; Value = $InstallLocation; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'DisplayVersion'; Value = $PackageData.Identity.DisplayVersion; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'Publisher'; Value = $PackageData.Identity.Publisher; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'HelpLink'; Value = $HelpLinkValue; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'URLInfoUpdate'; Value = $HelpLinkValue; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'URLInfoAbout'; Value = $PackageData.Identity.PublisherUrl; Type = 'REG_SZ' }
  )
  # The runtime writes the first two dot-separated DisplayVersion components as string values;
  # live installs confirm "12.34.56" -> "12"/"34" and "DEMO 6.1.2" -> "DEMO 6"/"1".
  $VersionComponents = @(([string]$PackageData.Identity.DisplayVersion) -split '\.')
  $VersionMajorValue = $VersionComponents.Count -ge 2 ? $VersionComponents[0] : $null
  $VersionMinorValue = $VersionComponents.Count -ge 2 ? $VersionComponents[1] : $null
  if ($null -ne $VersionMajorValue) {
    $ValueRecords += [pscustomobject]@{ Name = 'VersionMajor'; Value = $VersionMajorValue; Type = 'REG_SZ' }
    $ValueRecords += [pscustomobject]@{ Name = 'VersionMinor'; Value = $VersionMinorValue; Type = 'REG_SZ' }
  }
  foreach ($Record in $ValueRecords) {
    if ($null -eq $Record.Value -or ($Record.Value -is [string] -and [string]::IsNullOrWhiteSpace($Record.Value))) { continue }
    $Writes.Add((ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Root $Root -Key $UninstallKey -Name $Record.Name -Value $Record.Value -Type $Record.Type -Condition $Condition))
  }

  # DeployMaster records the deployment log under its vendor key so later installations can find
  # an existing package. The adjacent Stub value contains the runtime source path and is generated
  # during installation, so it is reported as dynamic evidence rather than guessed here.
  $TrackingWrite = ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Root $Root -Key 'Software\JGsoft\DeployIT' -Name $PackageData.Identity.DisplayName -Value $DeploymentLogPath -Condition $Condition -Evidence 'DeployMaster built-in deployment-log tracking convention'
  [pscustomobject][ordered]@{
    Scope                      = $Scope
    Root                       = $Root
    RegistryView               = $RegistryView
    Architecture               = $TargetArchitecture
    ProductCode                = $PackageData.Identity.DisplayName
    UninstallKey               = $UninstallKey
    DisplayName                = $PackageData.Identity.DisplayName
    DisplayVersion             = $PackageData.Identity.DisplayVersion
    Publisher                  = $PackageData.Identity.Publisher
    HelpLink                   = $HelpLinkValue
    URLInfoUpdate              = $HelpLinkValue
    URLInfoAbout               = $PackageData.Identity.PublisherUrl
    InstallLocation            = $InstallLocation
    UninstallerPath            = $UninstallerPath
    DeploymentLogPath          = $DeploymentLogPath
    UninstallString            = $UninstallString
    QuietUninstallString       = $null
    DisplayIcon                = $null
    NoModify                   = $true
    NoRepair                   = $true
    VersionMajor               = $VersionMajorValue
    VersionMinor               = $VersionMinorValue
    RegistryWrites             = $Writes.ToArray()
    DeploymentTrackingWrite    = $TrackingWrite
    RuntimeGeneratedValueNames = @('EstimatedSize', 'InstallDate', 'Stub')
    Evidence                   = 'DeployMaster structured identity plus controlled user-scope and machine-scope installations'
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

function Get-DeployMasterClassicBuiltInRegistration {
  <#
  .SYNOPSIS
    Reconstruct the built-in uninstall registration written by the classic 2.5 runtime.
  .PARAMETER PackageData
    Validated classic package model containing identity and installation-path evidence.
  .OUTPUTS
    The exact static HKLM 32-bit ARP values and deployment-log tracking value confirmed by a
    controlled 2.5.3 installation. Runtime-only Stub data is named but not guessed.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$PackageData)

  $Identity = $PackageData.Identity
  $ProductCode = [string]$Identity.DisplayName
  $InstallLocation = [string]$Identity.MachineInstallLocation
  if ([string]::IsNullOrWhiteSpace($ProductCode) -or [string]::IsNullOrWhiteSpace($InstallLocation)) { return }
  $DisplayName = (@($Identity.Publisher, $Identity.DisplayName, $Identity.DisplayVersion) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ' '
  $DeploymentLogPath = "$InstallLocation\Deploy.log"
  $UninstallerPath = '%WINDOWS%\UnDeploy.exe'
  $UninstallString = "$UninstallerPath `"$DeploymentLogPath`""
  $Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
  $Writes = @(
    [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = $Key; Name = 'DisplayName'; Value = $DisplayName; Type = 'REG_SZ' }
    [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = $Key; Name = 'UninstallString'; Value = $UninstallString; Type = 'REG_SZ' }
  )
  $TrackingWrite = [pscustomobject]@{
    Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\JGsoft\DeployIT'; Name = $ProductCode
    Value = $DeploymentLogPath; Type = 'REG_SZ'
  }
  return [pscustomobject]@{
    ProductCode                = $ProductCode
    Root                       = 'HKLM'
    RegistryView               = '32-bit'
    Scope                      = 'machine'
    Architecture               = 'x86'
    Key                        = $Key
    DisplayName                = $DisplayName
    DisplayVersion             = $null
    Publisher                  = $null
    InstallLocation            = $null
    UninstallerPath            = $UninstallerPath
    DeploymentLogPath          = $DeploymentLogPath
    UninstallString            = $UninstallString
    QuietUninstallString       = $null
    DisplayIcon                = $null
    NoModify                   = $null
    NoRepair                   = $null
    RegistryWrites             = $Writes
    DeploymentTrackingWrite    = $TrackingWrite
    RuntimeGeneratedValueNames = @('Stub')
    Evidence                   = 'Classic 2.5 runtime decompile plus controlled 2.5.3 HKLM 32-bit installed-state evidence'
  }
}

function ConvertTo-DeployMasterClassicInfo {
  <#
  .SYNOPSIS
    Compose provider-neutral parser evidence for a validated classic DeployMaster package.
  .PARAMETER File
    Resolved installer FileInfo object.
  .PARAMETER PackageData
    Classic package model returned by Read-DeployMasterClassicPackageData.
  .PARAMETER VersionInfo
    Trusted outer PE version information.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][Diagnostics.FileVersionInfo]$VersionInfo
  )

  $Identity = $PackageData.Identity
  $CustomRegistryWrites = @($PackageData.BehaviorMetadata.Registry.RegistryWrites)
  $DeletedRegistryKeys = @($PackageData.BehaviorMetadata.Registry.DeletedKeys)
  $FileAssociations = @($PackageData.BehaviorMetadata.FileAssociations)
  $InstalledFiles = @($PackageData.BehaviorMetadata.InstalledFiles)
  $Shortcuts = @($PackageData.BehaviorMetadata.Shortcuts)
  $UrlShortcuts = @($PackageData.BehaviorMetadata.UrlShortcuts)
  $InstallationItems = @($InstalledFiles) + @($Shortcuts) + @($UrlShortcuts)
  $InstallationFolderByPath = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in @($PackageData.BehaviorMetadata.InstallationFolders)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Folder.FullName) -and -not $InstallationFolderByPath.Contains([string]$Folder.FullName)) {
      $InstallationFolderByPath.Add([string]$Folder.FullName, $Folder)
    }
  }
  $BuiltInRegistration = Get-DeployMasterClassicBuiltInRegistration -PackageData $PackageData
  $BuiltInAppsAndFeaturesEntry = [pscustomobject]@{ ProductCode = $BuiltInRegistration.ProductCode; DisplayName = $BuiltInRegistration.DisplayName; InstallerType = 'exe' }
  $CustomAppsAndFeaturesEntries = @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $CustomRegistryWrites)
  $AppsAndFeaturesEntries = @(Merge-DeployMasterAppsAndFeaturesEntry -Entry (@($BuiltInAppsAndFeaturesEntry) + $CustomAppsAndFeaturesEntries))
  $RegistryWrites = @($BuiltInRegistration.RegistryWrites) + @($BuiltInRegistration.DeploymentTrackingWrite) + $CustomRegistryWrites
  $CustomAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $CustomRegistryWrites
  $FileExtensions = @((@($FileAssociations | Select-Object -ExpandProperty FileExtension) + @($CustomAssociationInfo.FileExtensions)) | Sort-Object -Unique)
  $RegistryAssociationInfo = [pscustomobject]@{
    Protocols                 = @($CustomAssociationInfo.Protocols)
    FileExtensions            = $FileExtensions
    ProtocolAssociations      = @($CustomAssociationInfo.ProtocolAssociations)
    FileExtensionAssociations = @($FileAssociations) + @($CustomAssociationInfo.FileExtensionAssociations)
    RegistryWrites            = @($CustomAssociationInfo.RegistryWrites)
    Diagnostics               = @($CustomAssociationInfo.Diagnostics)
  }
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.ClassicInteractiveOnly' -Source 'DeployMaster' -Message 'The classic DeployMaster 2.5 runtime has no unattended command-line route and is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $PackageData.Route))
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.ClassicEffectsPartial' -Source 'DeployMaster' -Message 'Classic components, recursive destination trees, files, shortcuts, URL shortcuts, registry operations, and file associations are decoded. Prerequisites and completion records remain unresolved.' -Kind Incomplete -Areas Metadata -AffectedFields Prerequisites, ExecutedPayloads -Evidence $PackageData.Route))
  foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  $UnresolvedFields.Add('Prerequisites')
  $SupportDlls = @(
    if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll32FileName)) {
      [pscustomobject]@{ Architecture = 'x86'; FileName = $Identity.SupportDll32FileName }
    }
  )
  if ($SupportDlls.Count) {
    # The classic runtime invokes the packaged support DLL the same way modern media does, so its
    # custom validation and post-install effects need the same manual-validation warning.
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.SupportDllEffectsOpaque' -Source 'DeployMaster' -Message 'The installer invokes one or more DeployMaster support DLLs. Their custom validation, folder, registry, and post-install effects require separate static inspection or VM validation.' -Kind ManualValidation -Areas Metadata, Installability, Security -Evidence $SupportDlls))
    $UnresolvedFields.Add('SupportDllEffects')
  }
  return [pscustomobject][ordered]@{
    Path                                  = $File.FullName
    InstallerType                         = 'exe'
    ProductCode                           = $BuiltInRegistration.ProductCode
    UpgradeCode                           = $null
    DisplayName                           = $Identity.DisplayName
    DisplayVersion                        = $Identity.DisplayVersion
    Publisher                             = $Identity.Publisher
    Scope                                 = 'machine'
    DefaultInstallLocation                = $Identity.MachineInstallLocation
    WritesAppsAndFeaturesEntry            = $true
    AppsAndFeaturesProductCode            = $BuiltInRegistration.ProductCode
    AppsAndFeaturesInstallerType          = 'exe'
    AppsAndFeaturesEntries                = $AppsAndFeaturesEntries
    UninstallString                       = $BuiltInRegistration.UninstallString
    QuietUninstallString                  = $null
    DisplayIcon                           = $null
    HelpLink                              = $null
    URLInfoUpdate                         = $null
    URLInfoAbout                          = $null
    Diagnostics                           = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    UnresolvedFields                      = $UnresolvedFields.ToArray()
    Family                                = 'DeployMaster'
    ProductCodeEvidence                   = $BuiltInRegistration.Evidence
    PublisherUrl                          = $Identity.PublisherUrl
    PackageUrl                            = $Identity.PackageUrl
    Copyright                             = $Identity.Copyright
    Description                           = $Identity.Description
    ReadmeFileName                        = $Identity.ReadmeFileName
    LicenseFileName                       = $Identity.LicenseFileName
    LicenseRequiredEveryInstall           = $false
    SupportDlls                           = $SupportDlls
    ReleaseDate                           = $Identity.ReleaseDate
    MachineInstallLocation                = $Identity.MachineInstallLocation
    UserInstallLocation                   = $Identity.UserInstallLocation
    RawMachineInstallLocation             = $Identity.RawMachineInstallLocation
    RawUserInstallLocation                = $Identity.RawUserInstallLocation
    CommonFilesLocation                   = $null
    CommonPublisherLocation               = $null
    MachineMenuLocation                   = $Identity.MachineMenuLocation
    UserMenuLocation                      = $Identity.UserMenuLocation
    RawMachineMenuLocation                = $Identity.RawMachineMenuLocation
    RawUserMenuLocation                   = $Identity.RawUserMenuLocation
    CommonDataLocation                    = $null
    UserDataLocation                      = $null
    RuntimeProductName                    = ([string]$VersionInfo.ProductName).Trim()
    FileDescription                       = ([string]$VersionInfo.FileDescription).Trim()
    DefaultScope                          = 'machine'
    SupportedScopes                       = @('machine')
    SupportsDualScope                     = $false
    RequiresAdministrativeRights          = $true
    InstallerArchitecture                 = $PackageData.Runtime.Architecture
    ApplicationArchitectureMode           = $null
    ApplicationArchitectures              = @()
    SupportedArchitectures                = @()
    SupportedOperatingSystemArchitectures = @()
    RegistryView                          = '32-bit'
    SupportedWindowsVersions              = @()
    SupportsFutureWindowsVersions         = $null
    MinimumWindows10VersionCode           = $null
    MaximumWindows10VersionCode           = $null
    MinimumWindows11VersionCode           = $null
    MaximumWindows11VersionCode           = $null
    RequestedExecutionLevel               = Get-PERequestedExecutionLevel -Path $File.FullName
    InstallerSwitches                     = [ordered]@{}
    InstallModes                          = @('interactive')
    CommandLineSwitches                   = [pscustomobject]@{}
    UninstallerSwitches                   = [ordered]@{}
    BuiltInRegistration                   = $BuiltInRegistration
    BuiltInRegistrationVariants           = @($BuiltInRegistration)
    DeploymentLogPath                     = $BuiltInRegistration.DeploymentLogPath
    RuntimeGeneratedArpFields             = @()
    RegistryWrites                        = $RegistryWrites
    CustomRegistryWrites                  = $CustomRegistryWrites
    DeletedRegistryKeys                   = $DeletedRegistryKeys
    RegistryAssociationInfo               = $RegistryAssociationInfo
    Protocols                             = $RegistryAssociationInfo.Protocols
    FileExtensions                        = $RegistryAssociationInfo.FileExtensions
    FileAssociations                      = $FileAssociations
    Components                            = @($PackageData.Components)
    InstallationItemGroups                = @($PackageData.BehaviorMetadata.InstallItemGroups)
    InstallationItems                     = $InstallationItems
    InstallationFolders                   = @($InstallationFolderByPath.Values)
    InstalledFiles                        = $InstalledFiles
    Shortcuts                             = $Shortcuts
    UrlShortcuts                          = $UrlShortcuts
    ExecutedPayloads                      = @()
    Prerequisites                         = @()
    DotNetFrameworkRequirement            = $null
    CompletionActions                     = $null
    UninstallConfiguration                = $null
    UpdatePolicy                          = $null
    ExpirationPolicy                      = $null
    PackageSettings                       = $null
    RuntimeFeatures                       = [pscustomobject]@{ PortableSwitch = $false }
    FileEntries                           = $PackageData.FileEntries
    ExtractedFiles                        = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
    ClassicFileCatalog                    = [pscustomobject]@{
      CatalogOffset       = $PackageData.FileCatalog.CatalogOffset
      CatalogLength       = $PackageData.FileCatalog.CatalogLength
      EntryCount          = $PackageData.FileEntries.Count
      AuxiliaryEntryCount = $PackageData.FileCatalog.AuxiliaryCount
      ObservedTailBytes   = $PackageData.FileCatalog.ObservedTailBytes
      DestinationRoot     = $PackageData.FileCatalog.DestinationRoot
    }
    OverlayInfo                           = [pscustomobject]@{
      OverlayOffset         = $PackageData.OverlayOffset
      OverlayLength         = $PackageData.LogicalEnd - $PackageData.OverlayOffset
      PhysicalFileSize      = $File.Length
      LogicalFileSize       = $PackageData.LogicalEnd
      HasSignedEnvelope     = $PackageData.LogicalEnd -lt $File.Length
      RuntimeCompressedSize = $PackageData.Runtime.CompressedSize
      RuntimeExpandedSize   = $PackageData.Runtime.UncompressedSize
      HeaderSize            = $null
      FormatProfile         = $PackageData.Route.Id
      FormatVersion         = 2
      ObservedRuntimeRange  = $PackageData.Route.ObservedRuntimeRange
      ProfileEvidence       = $PackageData.Route.Evidence
      PackageDataOffset     = $PackageData.Runtime.MarkerOffset + 4
    }
    CanExpand                             = $true
    ParserVersionInfo                     = [pscustomobject]@{
      Parser         = 'Dumplings.PackageModule.DeployMaster'
      ParserMajor    = 7
      CatalogVersion = [int]$Script:DeployMasterFormatCatalog.CatalogVersion
      FormatProfile  = $PackageData.Route.Id
      Sources        = @('DeployMaster 2.x BZip2 runtime member', 'length-prefixed zlib metadata and payload records', 'classic component descriptors', 'classic offset, expanded-size, CRC32, and destination-root file catalog', 'flat classic file and shortcut streams', 'classic null-terminated registry stream', 'classic form-feed file-association stream', 'archived DeployMaster 2.5.x media')
    }
  }
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
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $RuntimeIdentity = "$($VersionInfo.ProductName)`n$($VersionInfo.FileDescription)`n$($VersionInfo.Comments)"
    $ClassicPackageData = $null
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $ClassicRoute = Get-DeployMasterClassicRoute -Stream $Stream -RuntimeIdentity $RuntimeIdentity
      if ($ClassicRoute) {
        $ClassicPackageData = Read-DeployMasterClassicPackageData -Stream $Stream -Route $ClassicRoute
      } else {
        # Parse the complete package model while one stream is open, then separately corroborate the
        # overlay location and PE runtime identity.
        $PackageData = Read-DeployMasterPackageData -Stream $Stream
        $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
        $PELayout = Get-PELayout -Stream $Stream
        $VersionStrings = Get-PEVersionStringTable -Path $File.FullName
      }
    } finally { $Stream.Dispose() }

    if ($ClassicPackageData) { return ConvertTo-DeployMasterClassicInfo -File $File -PackageData $ClassicPackageData -VersionInfo $VersionInfo }

    if ($OverlayOffset -ne $PackageData.Locator.PackageOffset) { throw 'The DeployMaster package locator does not point to the PE overlay.' }
    $RuntimeProductName = ([string]$VersionInfo.ProductName).Trim()
    $RuntimeComments = ([string]$VersionStrings.Comments).Trim()
    if ($RuntimeProductName -notmatch '(?i)DeployMaster' -and $RuntimeComments -notmatch '(?i)DeployMaster') { throw 'The validated package overlay is not paired with a DeployMaster runtime identity.' }

    $Identity = $PackageData.Identity
    $InstallerArchitecture = switch ($PELayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
    # Distinguish a pure x64 installer from an x86 bootstrapper that deploys a 64-bit application.
    $ApplicationArchitectureMode = if ($PackageData.Header.ApplicationArchitectureMode -eq 'x64Application') {
      if ($InstallerArchitecture -eq 'x86') { 'x64ApplicationWithX86InstallerStub' } else { 'x64ApplicationWithX64Installer' }
    } else { $PackageData.Header.ApplicationArchitectureMode }
    $RegistryView = switch ($ApplicationArchitectureMode) {
      { $_ -in 'x86ApplicationForX86WindowsOnly', 'x86ApplicationForX86AndX64Windows' } { '32-bit'; break }
      { $_ -in 'x64ApplicationWithX86InstallerStub', 'x64ApplicationWithX64Installer', 'x64Application' } { '64-bit'; break }
      'x86AndX64Application' { 'architecture-selected'; break }
      default { 'default' }
    }
    $InstallLocation = switch ($Identity.Scope) {
      'user' { $Identity.UserInstallLocation }
      'machine' { $Identity.MachineInstallLocation }
      default { $null }
    }
    # "Always" portable media bypasses every host-system effect, including the built-in ARP entry.
    # User-choice media retains both a normal installation route and a separate portable route.
    $NormalInstallSupported = $null -eq $PackageData.Settings -or $PackageData.Settings.PortableInstallationMode -ne 'Always'
    $BuiltInRegistrations = [Collections.Generic.List[object]]::new()
    if ($NormalInstallSupported) {
      $RegistrationArchitectures = switch ($ApplicationArchitectureMode) {
        'x86AndX64Application' {
          [pscustomobject]@{ Architecture = 'x86'; RegistryView = '32-bit' }
          [pscustomobject]@{ Architecture = 'x64'; RegistryView = '64-bit' }
        }
        { $_ -in 'x64ApplicationWithX86InstallerStub', 'x64ApplicationWithX64Installer', 'x64Application' } { [pscustomobject]@{ Architecture = 'x64'; RegistryView = '64-bit' }; break }
        default { [pscustomobject]@{ Architecture = 'x86'; RegistryView = '32-bit' } }
      }
      foreach ($RegistrationScope in $Identity.SupportedScopes) {
        $RegistrationLocation = $RegistrationScope -eq 'machine' ? $Identity.MachineInstallLocation : $Identity.UserInstallLocation
        if ([string]::IsNullOrWhiteSpace([string]$RegistrationLocation)) { continue }
        foreach ($RegistrationArchitecture in $RegistrationArchitectures) {
          $BuiltInRegistrations.Add((Get-DeployMasterBuiltInRegistration -PackageData $PackageData -Scope $RegistrationScope -InstallLocation $RegistrationLocation -RegistryView $RegistrationArchitecture.RegistryView -TargetArchitecture $RegistrationArchitecture.Architecture))
        }
      }
    }
    $PrimaryRegistration = if ($Identity.Scope -and $RegistrationArchitectures.Count -eq 1) { $BuiltInRegistrations | Where-Object Scope -EQ $Identity.Scope | Select-Object -First 1 } elseif ($BuiltInRegistrations.Count -eq 1) { $BuiltInRegistrations[0] } else { $null }
    $BuiltInRegistryWrites = @($BuiltInRegistrations | ForEach-Object { @($_.RegistryWrites) + $_.DeploymentTrackingWrite })
    $CustomRegistryWrites = if ($PackageData.StructuredMetadata) { @($PackageData.StructuredMetadata.Registry.RegistryWrites) } else { @() }
    $RegistryWrites = if ($NormalInstallSupported) { @($BuiltInRegistryWrites) + @($CustomRegistryWrites) } else { @() }
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
    $AppsAndFeaturesCandidates = [Collections.Generic.List[object]]::new()
    if ($NormalInstallSupported) {
      $AppsAndFeaturesCandidates.Add([pscustomobject]@{
          ProductCode = $Identity.DisplayName; DisplayName = $Identity.DisplayName; DisplayVersion = $Identity.DisplayVersion
          Publisher = $Identity.Publisher; InstallerType = 'exe'
        })
      foreach ($CustomEntry in @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $CustomRegistryWrites)) { $AppsAndFeaturesCandidates.Add($CustomEntry) }
    }
    [object[]]$AppsAndFeaturesEntries = if ($AppsAndFeaturesCandidates.Count) { @(Merge-DeployMasterAppsAndFeaturesEntry -Entry $AppsAndFeaturesCandidates.ToArray()) } else { @() }
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
    if (-not $NormalInstallSupported) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.PortableOnlyNoArp' -Source 'DeployMaster' -Message 'This package always creates a portable installation, so DeployMaster does not write its built-in Apps & Features entry or other host-system changes.' -Kind Information -Areas Metadata, Installability -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $PackageData.Settings))
    } elseif ($BuiltInRegistrations.Count -and -not $PrimaryRegistration -and -not $Identity.SupportsDualScope) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.ArpRegistrationUnresolved' -Source 'DeployMaster' -Message 'The built-in DeployMaster uninstall registration could not be resolved to a concrete supported scope.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $Identity))
    }
    if ($Identity.SupportsDualScope) { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Scope.Dual' -Source 'DeployMaster' -Message 'This DeployMaster package supports both user and machine scope; validate the default scope and any elevation-sensitive behavior in a VM.' -Kind ManualValidation -Areas Metadata, Installability -AffectedFields Scope -Evidence $Identity.SupportedScopes)) }
    if ($PackageData.FileAssociations.Actions | Where-Object { $_.Executable32FileIndex -lt 0 -and $_.Executable64FileIndex -lt 0 }) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Association.ExecutableUnresolved' -Source 'DeployMaster' -Message 'One or more DeployMaster file-type actions do not resolve to packaged executable indexes and will not create an open command.' -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions, Protocols -Evidence $PackageData.FileAssociations))
    }
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $PackageData.StructuredMetadata) {
      foreach ($Field in 'Components', 'InstallationItems', 'RegistryWrites', 'Prerequisites', 'CompletionActions', 'UpdatePolicy') { $UnresolvedFields.Add($Field) }
    }
    if ($SupportDlls.Count) { $UnresolvedFields.Add('SupportDllEffects') }
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
      ProductCode                           = $NormalInstallSupported ? $Identity.DisplayName : $null
      UpgradeCode                           = $null
      DisplayName                           = $Identity.DisplayName
      DisplayVersion                        = $Identity.DisplayVersion
      Publisher                             = $Identity.Publisher
      Scope                                 = $Identity.Scope
      DefaultInstallLocation                = $InstallLocation
      WritesAppsAndFeaturesEntry            = $NormalInstallSupported
      AppsAndFeaturesProductCode            = $NormalInstallSupported ? $Identity.DisplayName : $null
      AppsAndFeaturesInstallerType          = $NormalInstallSupported ? 'exe' : $null
      AppsAndFeaturesEntries                = $AppsAndFeaturesEntries
      UninstallString                       = $PrimaryRegistration ? $PrimaryRegistration.UninstallString : $null
      QuietUninstallString                  = $null
      DisplayIcon                           = $PrimaryRegistration ? $PrimaryRegistration.DisplayIcon : $null
      HelpLink                              = $NormalInstallSupported ? $Identity.PackageUrl : $null
      URLInfoUpdate                         = $NormalInstallSupported ? $Identity.PackageUrl : $null
      URLInfoAbout                          = $NormalInstallSupported ? $Identity.PublisherUrl : $null
      Diagnostics                           = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'DeployMaster' -Kind Incomplete -Areas Metadata))
      UnresolvedFields                      = $UnresolvedFields.ToArray()
      Family                                = 'DeployMaster'
      ProductCodeEvidence                   = $NormalInstallSupported ? 'DeployMaster structured identity and built-in uninstall-key convention' : $null
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
      RawMachineInstallLocation             = $Identity.RawMachineInstallLocation
      RawUserInstallLocation                = $Identity.RawUserInstallLocation
      CommonFilesLocation                   = $Identity.CommonFilesLocation
      CommonPublisherLocation               = $Identity.CommonPublisherLocation
      MachineMenuLocation                   = $Identity.MachineMenuLocation
      UserMenuLocation                      = $Identity.UserMenuLocation
      CommonDataLocation                    = $Identity.CommonDataLocation
      UserDataLocation                      = $Identity.UserDataLocation
      RawCommonFilesLocation                = $Identity.RawCommonFilesLocation
      RawCommonPublisherLocation            = $Identity.RawCommonPublisherLocation
      RawMachineMenuLocation                = $Identity.RawMachineMenuLocation
      RawUserMenuLocation                   = $Identity.RawUserMenuLocation
      RawCommonDataLocation                 = $Identity.RawCommonDataLocation
      RawUserDataLocation                   = $Identity.RawUserDataLocation
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
      RegistryView                          = $RegistryView
      SupportedWindowsVersions              = $PackageData.Header.SupportedWindowsVersions
      SupportsFutureWindowsVersions         = $PackageData.Header.SupportsFutureWindowsVersions
      MinimumWindows10VersionCode           = $PackageData.Header.MinimumWindows10VersionCode
      MaximumWindows10VersionCode           = $PackageData.Header.MaximumWindows10VersionCode
      MinimumWindows11VersionCode           = $PackageData.Header.MinimumWindows11VersionCode
      MaximumWindows11VersionCode           = $PackageData.Header.MaximumWindows11VersionCode
      RequestedExecutionLevel               = Get-PERequestedExecutionLevel -Path $File.FullName
      InstallerSwitches                     = [ordered]@{ Silent = '/silent'; InstallLocation = $PackageData.Settings.PortableInstallationMode -eq 'Always' ? '/portable "<INSTALLPATH>"' : '/appfolder "<INSTALLPATH>"' }
      InstallModes                          = @('interactive', 'silent')
      CommandLineSwitches                   = [pscustomobject]@{
        Silent                   = @('/s', '/silent')
        SuppressDesktopShortcuts = '/nodesktop'
        ForceX86                 = if ($ApplicationArchitectureMode -eq 'x86AndX64Application') { '/32' } else { $null }
        Portable                 = if ($PackageData.RuntimeFeatures.PortableSwitch) { '/portable "<PATH>"' } else { $null }
        InstallForAllUsers       = if ($PackageData.Header.HasInstallForAllUsersSwitch -and $Identity.SupportsDualScope) { '/userall' } else { $null }
        SkipElevation            = if ($PackageData.RuntimeFeatures.SkipElevationSwitch) { '/noadmin' } else { $null }
        TemporaryFolder          = '/temp "<PATH>"'
        InstallationFolders      = [ordered]@{
          Application = '/appfolder "<PATH>"'
          CommonFiles = '/appcommonfolder "<PATH>"'
          StartMenu   = '/appmenu "<PATH>"'
          UserData    = '/userdata "<PATH>"'
        }
      }
      UninstallerSwitches                   = [ordered]@{ Silent = '/silent' }
      BuiltInRegistration                   = $PrimaryRegistration
      BuiltInRegistrationVariants           = $BuiltInRegistrations.ToArray()
      DeploymentLogPath                     = $PrimaryRegistration ? $PrimaryRegistration.DeploymentLogPath : $null
      RuntimeGeneratedArpFields             = $NormalInstallSupported ? @('EstimatedSize', 'InstallDate') : @()
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
      RuntimeFeatures                       = $PackageData.RuntimeFeatures
      FileEntries                           = $PackageData.FileEntries
      ExtractedFiles                        = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
      OverlayInfo                           = [pscustomobject]@{
        OverlayOffset         = $PackageData.Locator.PackageOffset
        OverlayLength         = $File.Length - $PackageData.Locator.PackageOffset
        IntegrityLength       = $PackageData.Locator.IntegrityLength
        ExpectedCrc32         = $PackageData.Locator.ExpectedCrc32
        ActualCrc32           = $PackageData.Locator.ActualCrc32
        ExpectedFileSize      = $PackageData.Locator.ExpectedFileSize
        PhysicalFileSize      = $PackageData.Locator.PhysicalFileSize
        HasSignedEnvelope     = $PackageData.Locator.HasSignedEnvelope
        CertificateOffset     = $PackageData.Locator.CertificateOffset
        CertificateSize       = $PackageData.Locator.CertificateSize
        DictionarySize        = $PackageData.Header.DictionarySize
        HeaderSize            = $PackageData.Header.HeaderSize
        FormatProfile         = $PackageData.Header.FormatProfile
        FormatVersion         = $PackageData.Header.FormatVersion
        UninstallCommandRoute = $PackageData.Header.UninstallCommandRoute
        ObservedRuntimeRange  = $PackageData.Header.ObservedRuntimeRange
        ProfileEvidence       = $PackageData.Header.ProfileEvidence
        PackageDataOffset     = $PackageData.Locator.PackageDataOffset
      }
      CanExpand                             = $true
      ParserVersionInfo                     = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DeployMaster'; ParserMajor = 7; CatalogVersion = [int]$Script:DeployMasterFormatCatalog.CatalogVersion; FormatProfile = $PackageData.Header.FormatProfile; Sources = @('DeployMaster 0x80 package locator', 'CRC32-protected package-control header', 'stored and bounded LZMA data blocks', 'controlled builder outputs and installed-state evidence', 'DeployMaster builder help and version history') }
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
    [AllowEmptyCollection()][byte[]]$Properties = [byte[]]::new(0),
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumBytes
  )

  # A bounded source range prevents the decoder from consuming the next package record.
  $Output = [IO.File]::Open($DestinationPath, 'CreateNew', 'Write', 'None')
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Entry.Offset -Length $Entry.CompressedSize -LeaveOpen
  $Completed = $false
  try {
    if ($Entry.Compression -eq 'Store') {
      $CopyArguments = @{ Source = $InputStream; Destination = $Output; MaximumBytes = $MaximumBytes }
      if ($null -ne $Entry.UncompressedSize) { $CopyArguments.ExpectedBytes = [long]$Entry.UncompressedSize }
      $null = Copy-BoundedStream @CopyArguments
    } else {
      $ExpandArguments = @{
        Algorithm      = [string]$Entry.Compression
        Stream         = $InputStream
        Destination    = $Output
        MaximumBytes   = $MaximumBytes
        CompressedSize = [long]$Entry.CompressedSize
      }
      if ($Properties.Count) { $ExpandArguments.Properties = $Properties }
      if ($null -ne $Entry.UncompressedSize) { $ExpandArguments.UncompressedSize = [long]$Entry.UncompressedSize }
      $null = Expand-InstallerCompressedStream @ExpandArguments
    }
    $Completed = $true
  } finally {
    $InputStream.Dispose()
    $Output.Dispose()
    if (-not $Completed) { Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction Ignore }
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
      $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
      $RuntimeIdentity = "$($VersionInfo.ProductName)`n$($VersionInfo.FileDescription)`n$($VersionInfo.Comments)"
      $ClassicRoute = Get-DeployMasterClassicRoute -Stream $Stream -RuntimeIdentity $RuntimeIdentity
      $PackageData = $ClassicRoute ? (Read-DeployMasterClassicPackageData -Stream $Stream -Route $ClassicRoute) : (Read-DeployMasterPackageData -Stream $Stream)
      # Normalize runtime cores, decoded metadata blocks, and application files into one extraction
      # catalog so selection and accounting follow the same path.
      $Items = [Collections.Generic.List[object]]::new()
      foreach ($Core in $PackageData.Header.CoreEntries) {
        $Compression = $Core.PSObject.Properties['Compression'] ? [string]$Core.Compression : 'Lzma'
        $Items.Add([pscustomobject]@{ FullName = "Runtime/DeployMasterCore-$($Core.Architecture).exe"; Kind = 'Compressed'; Offset = $Core.Offset; CompressedSize = $Core.CompressedSize; UncompressedSize = $Core.UncompressedSize; Compression = $Compression })
      }
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Language.txt'; Kind = 'Bytes'; Bytes = $PackageData.LanguageBlock.Bytes; UncompressedSize = $PackageData.LanguageBlock.Bytes.Length })
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Identity.txt'; Kind = 'Bytes'; Bytes = $PackageData.IdentityBlock.Bytes; UncompressedSize = $PackageData.IdentityBlock.Bytes.Length })
      if ($PackageData.PSObject.Properties['FileNameBlock']) {
        $Items.Add([pscustomobject]@{ FullName = 'Metadata/FileNames.txt'; Kind = 'Bytes'; Bytes = $PackageData.FileNameBlock.Bytes; UncompressedSize = $PackageData.FileNameBlock.Bytes.Length })
      }
      foreach ($Entry in $PackageData.FileEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Payload/$($Entry.FullName)"; Kind = 'Compressed'; Offset = $Entry.Offset; CompressedSize = $Entry.CompressedSize; UncompressedSize = $Entry.UncompressedSize; Compression = $Entry.Compression })
      }

      # Check the aggregate uncompressed size and destination identity before writing each item.
      foreach ($Item in $Items) {
        if (-not (Test-ExtractionPattern -Path $Item.FullName -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.FullName `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($null -ne $Item.UncompressedSize -and $ExpandedBytes + [long]$Item.UncompressedSize -gt $MaximumExpandedBytes) { throw "The DeployMaster expansion exceeds the $MaximumExpandedBytes-byte output limit." }
        $OutputPath = $Target.Path
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if ($Item.Kind -eq 'Bytes') {
          [IO.File]::WriteAllBytes($OutputPath, $Item.Bytes)
          $Result = Get-Item -LiteralPath $OutputPath -Force
        } else {
          $Result = Export-DeployMasterRange -Stream $Stream -Entry $Item -Properties $PackageData.Header.LzmaProperties -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
        }
        $ExpandedBytes += $Result.Length
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
  process {
    try { $null = Get-DeployMasterInfo -Path $Path; return $true }
    catch { return $false }
  }
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
