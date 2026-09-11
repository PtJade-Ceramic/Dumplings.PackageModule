# SPDX-License-Identifier: Apache-2.0
# Paquet Builder parser independently derived from archived builder output, the
# shipped PBCore C ABI, controlled projects, and PE/7z/MSI specifications.
# References:
# - https://www.installpackbuilder.com/help/automation-command-line/package-installer-command-line
# - https://web.archive.org/web/*/https://download.installpackbuilder.com/pbinst.exe
# - https://web.archive.org/web/*/http://www.installpackbuilder.com/files/pbinst.exe
# - https://web.archive.org/web/*/http://www.gdgsoft.com/files/pbinst.exe
# - https://web.archive.org/web/*/https://download.gdgsoftware.com/pb/pbinst.exe
# - https://web.archive.org/web/*/https://files.gdgsoft.com/pb/pbinst.exe
# - https://web.archive.org/web/*/https://download.gdgsoftware.com/pb/pbinst64.exe
#
# Structural generations consumed here:
#
#   Classic2 (observed 2.6.x)
#   PE image
#   +-- .rsrc/RCDATA: DESCRIPTION, DVCLAL, PACKAGEINFO
#   `-- overlay
#       +-- 20-byte envelope + @GDG GPacker/LZHUF control block
#       `-- ZIP package: SETUP*.GAF records + setup runtime
#
#   Cabinet2 (observed 2.7.x)
#   PE image
#   +-- .rsrc/RCDATA/ENG: MZ cabinet runtime
#   +-- .rsrc/RCDATA/ISFX: exact package and payload offsets
#   `-- proprietary cabinet/configuration payload
#
#   Legacy2 / Resource2 (observed 2.8.x / 2.9.x)
#   PE image
#   +-- .rsrc/RCDATA/ENG: MZ runtime or GP-framed raw-LZMA runtime
#   +-- .rsrc/RCDATA/ISFX: optional launcher descriptor
#   `-- overlay: one independent 7z payload archive
#
#   Split3 (observed 3.x-current)
#   PE image importing PBCore[64].dll!SetVar
#   `-- overlay
#       +-- application payload 7z
#       `-- runtime 7z
#           +-- pbfprop.dat: repeated five-line payload records
#           +-- pbdlg.dat / pblng.dat: UI and locale records
#           +-- pbremove.dat: generated-uninstaller template
#           `-- PBCore*.dll: native package runtime

# Apply default function parameters supplied by the Dumplings runner.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:PaquetBuilderMaximumArchiveBytes = 17179869184L
$Script:PaquetBuilderMaximumMappedPeBytes = 268435456
$Script:PaquetBuilderMaximumRuntimeMetadataBytes = 4194304
$Script:PaquetBuilderMaximumClassicControlBytes = 67108864
$Script:PaquetBuilderFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'PaquetBuilderFormatCatalog.psd1')
$Script:PaquetBuilderScannerSource = Join-Path $PSScriptRoot '..\..\Assets\Source\PaquetBuilder\PaquetBuilderPeScanner.cs'
$Script:PaquetBuilderClassicDecoderSource = Join-Path $PSScriptRoot '..\..\Assets\Source\PaquetBuilder\PaquetBuilderClassicDecoder.cs'
$null = Import-InstallerManagedSource -Path $Script:PaquetBuilderScannerSource -TypeName 'Dumplings.PaquetBuilder.PaquetBuilderPeScanner'
$null = Import-InstallerManagedSource -Path $Script:PaquetBuilderClassicDecoderSource -TypeName 'Dumplings.PaquetBuilder.PaquetBuilderClassicDecoder'

function Get-PaquetBuilderFormatProfile {
  <#
  .SYNOPSIS
    Return one data-driven Paquet Builder structural profile.
  .PARAMETER Id
    Stable profile identifier from PaquetBuilderFormatCatalog.psd1.
  #>
  param ([Parameter(Mandatory)][string]$Id)

  $FormatProfile = @($Script:PaquetBuilderFormatCatalog.Profiles | Where-Object Id -CEQ $Id)[0]
  if (-not $FormatProfile) { throw "Unknown Paquet Builder format profile '$Id'." }
  return $FormatProfile
}

function ConvertTo-PaquetBuilderDiagnostic {
  <#
  .SYNOPSIS
    Create one context-neutral Paquet Builder parser diagnostic.
  .PARAMETER Id
    Stable condition identifier without the PaquetBuilder prefix.
  .PARAMETER Message
    Human-readable explanation of the evidence or limitation.
  .PARAMETER Kind
    Context-neutral diagnostic kind resolved later by the workflow.
  .PARAMETER Areas
    Parser areas affected by the condition.
  .PARAMETER AffectedFields
    Manifest metadata fields affected by the condition.
  .PARAMETER Evidence
    Optional structured source evidence.
  #>
  param (
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][ValidateSet('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')][string]$Kind,
    [Parameter(Mandatory)][string[]]$Areas,
    [string[]]$AffectedFields = @(),
    [AllowNull()][object]$Evidence
  )

  New-InstallerDiagnostic -Id "PaquetBuilder.$Id" -Source 'PaquetBuilder' -Message $Message -Kind $Kind -Areas $Areas -AffectedFields $AffectedFields -Evidence $Evidence
}

function Read-PaquetBuilderResourceData {
  <#
  .SYNOPSIS
    Read one bounded PE resource from the parser-owned installer stream.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    Resource range returned by Get-PEResourceInfo.
  .PARAMETER MaximumBytes
    Maximum accepted resource size in bytes.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes
  )

  if ($Resource.Size -lt 0 -or $Resource.Size -gt $MaximumBytes) { throw "Paquet Builder resource '$($Resource.Name)' exceeds the $MaximumBytes-byte limit." }
  return , (Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count ([int]$Resource.Size))
}

function Read-PaquetBuilderIsfxDescriptor {
  <#
  .SYNOPSIS
    Parse the fixed RCDATA/ISFX descriptor used by Paquet Builder 2.7 and 2.8 media.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    ISFX resource range returned by Get-PEResourceInfo.
  .PARAMETER FileLength
    Complete installer length used to validate the absolute package offsets.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$FileLength
  )

  if ($Resource.Size -ne 24) { throw 'The Paquet Builder ISFX descriptor does not have the expected 24-byte size.' }
  $Bytes = Read-PaquetBuilderResourceData -Stream $Stream -Resource $Resource -MaximumBytes 24
  if ($Bytes[0] -ne 3 -or [Text.Encoding]::ASCII.GetString($Bytes, 1, 3) -cne 'GDG') { throw 'The Paquet Builder ISFX descriptor magic is invalid.' }
  $PackageOffset = [long][BitConverter]::ToUInt32($Bytes, 8)
  $PayloadOffset = [long][BitConverter]::ToUInt32($Bytes, 12)
  if ($PackageOffset -le 0 -or $PayloadOffset -le $PackageOffset -or $PayloadOffset -ge $FileLength) { throw 'The Paquet Builder ISFX package offsets are outside the installer.' }

  [pscustomobject][ordered]@{
    Version           = [int]$Bytes[0]
    PackageOffset     = $PackageOffset
    PayloadOffset     = $PayloadOffset
    ConfigurationSize = $PayloadOffset - $PackageOffset
    PayloadSize       = $FileLength - $PayloadOffset
    ObservedField     = [BitConverter]::ToUInt32($Bytes, 4)
    Reserved          = [Convert]::ToHexString($Bytes[16..23])
  }
}

function Read-PaquetBuilderGpRuntime {
  <#
  .SYNOPSIS
    Decode the GP-framed raw-LZMA runtime resource used by Paquet Builder 2.9.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    RCDATA/ENG resource range returned by Get-PEResourceInfo.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Resource)

  if ($Resource.Size -lt 20 -or $Resource.Size -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder GP runtime resource has an invalid bounded size.' }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count 19
  if ($Header[0] -ne 0x47 -or $Header[1] -ne 0x50) { throw 'The Paquet Builder GP runtime resource magic is invalid.' }
  $UncompressedSize = [long][BitConverter]::ToUInt32($Header, 2)
  $TrailingSize = [long][BitConverter]::ToUInt32($Header, 6)
  $CompressedSize = [long]$Resource.Size - 19 - $TrailingSize
  if ($UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumMappedPeBytes) { throw 'The Paquet Builder GP runtime output exceeds the bounded PE limit.' }
  if ($TrailingSize -lt 0 -or $CompressedSize -le 0) { throw 'The Paquet Builder GP runtime framing is malformed.' }

  $Properties = [byte[]]$Header[14..18]
  $Compressed = New-BoundedReadStream -Stream $Stream -Offset ($Resource.Offset + 19) -Length $CompressedSize -LeaveOpen
  $Output = [IO.MemoryStream]::new([int]$UncompressedSize)
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $Compressed -Destination $Output -MaximumBytes $UncompressedSize -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
    $RuntimeBytes = $Output.ToArray()
  } finally {
    $Output.Dispose()
    $Compressed.Dispose()
  }
  if ($RuntimeBytes.Length -ne $UncompressedSize -or $RuntimeBytes.Length -lt 2 -or $RuntimeBytes[0] -ne 0x4D -or $RuntimeBytes[1] -ne 0x5A) { throw 'The decoded Paquet Builder GP runtime is not the declared PE image.' }

  $RuntimeStream = [IO.MemoryStream]::new($RuntimeBytes, $false)
  try {
    $Layout = Get-PELayout -Stream $RuntimeStream
    $VersionStrings = try { Get-PEVersionStringTable -Stream $RuntimeStream -Layout $Layout } catch { $null }
    $Resources = @(Get-PEResourceInfo -Stream $RuntimeStream -Layout $Layout)
  } finally {
    $RuntimeStream.Dispose()
  }

  [pscustomobject][ordered]@{
    HeaderSize         = 19
    CompressedOffset   = [long]$Resource.Offset + 19
    CompressedSize     = $CompressedSize
    UncompressedSize   = $UncompressedSize
    TrailingOffset     = [long]$Resource.Offset + 19 + $CompressedSize
    TrailingSize       = $TrailingSize
    ObservedField      = [BitConverter]::ToUInt32($Header, 10)
    LzmaProperties     = $Properties
    RuntimeBytes       = $RuntimeBytes
    RuntimeLayout      = $Layout
    RuntimeResources   = $Resources
    RuntimeVersionInfo = $VersionStrings
  }
}

function Read-PaquetBuilderClassicEnvelope {
  <#
  .SYNOPSIS
    Validate the Classic 2.6 envelope and decode its GPacker/LZHUF control block.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER OverlayOffset
    Absolute start of the PE overlay.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$OverlayOffset
  )

  if ($OverlayOffset + 32 -gt $Stream.Length) { throw 'The Classic Paquet Builder envelope is truncated.' }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 32
  if ($Header[0] -ne 3 -or [Text.Encoding]::ASCII.GetString($Header, 20, 4) -cne '@GDG') { throw 'The Classic Paquet Builder envelope magic is invalid.' }
  $PackedBlockSize = [long][BitConverter]::ToUInt32($Header, 12)
  $UncompressedSize = [long][BitConverter]::ToUInt32($Header, 24)
  $ExpectedCrc32 = [uint32][BitConverter]::ToUInt32($Header, 28)
  if ($PackedBlockSize -le 12 -or $UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumClassicControlBytes) { throw 'The Classic Paquet Builder GPacker bounds are invalid.' }
  $ArchiveOffset = $OverlayOffset + 20 + $PackedBlockSize
  if ($ArchiveOffset -gt $Stream.Length) { throw 'The Classic Paquet Builder package offset is outside the installer.' }

  $CompressedSize = $PackedBlockSize - 12
  # The historical bit reader prefetches one byte beyond the encoded block. The
  # envelope remains authoritative for the following ZIP boundary.
  $MaximumDecodeBytes = [Math]::Min($CompressedSize + 1, $Stream.Length - ($OverlayOffset + 32))
  $Decoded = [Dumplings.PaquetBuilder.PaquetBuilderClassicDecoder]::Decode($Stream, $OverlayOffset + 32, $MaximumDecodeBytes, [int]$UncompressedSize)
  $ActualCrc32 = Get-BinaryCrc32 -Bytes $Decoded.Data
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw ('The Classic Paquet Builder GPacker CRC32 is invalid: expected {0:X8}, got {1:X8}.' -f $ExpectedCrc32, $ActualCrc32) }
  if ($Decoded.BytesConsumed -gt $CompressedSize + 1) { throw 'The Classic Paquet Builder GPacker decoder crossed the declared block boundary.' }

  [pscustomobject][ordered]@{
    EnvelopeOffset      = $OverlayOffset
    EnvelopeVersion     = [int]$Header[0]
    PackedBlockOffset   = $OverlayOffset + 20
    PackedBlockSize     = $PackedBlockSize
    CompressedOffset    = $OverlayOffset + 32
    CompressedSize      = $CompressedSize
    DecoderBytesRead    = [long]$Decoded.BytesConsumed
    UncompressedSize    = $UncompressedSize
    ExpectedCrc32       = $ExpectedCrc32
    ArchiveOffset       = $ArchiveOffset
    ControlBytes        = $Decoded.Data
    ObservedPrefix      = [Convert]::ToHexString($Header[1..11])
    ObservedTrailerWord = [BitConverter]::ToUInt32($Header, 16)
  }
}

function Get-PaquetBuilderRequestedExecutionLevel {
  <#
  .SYNOPSIS
    Read requestedExecutionLevel from already-enumerated PE resources.
  .PARAMETER Stream
    Parser-owned installer stream.
  .PARAMETER Resources
    PE resource catalog from the same stream.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][object[]]$Resources)

  $Manifest = @($Resources | Where-Object { $_.TypeId -eq 24 -and $_.Id -eq 1 })[0]
  if (-not $Manifest -or $Manifest.Size -gt 1048576) { return $null }
  $Bytes = Read-PaquetBuilderResourceData -Stream $Stream -Resource $Manifest -MaximumBytes 1048576
  $Text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) } else { [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xFEFF) }
  $Match = [regex]::Match($Text, 'requestedExecutionLevel[^>]+level\s*=\s*["''](?<Level>asInvoker|highestAvailable|requireAdministrator)["'']', 'IgnoreCase')
  if ($Match.Success) { return $Match.Groups['Level'].Value }
  return $null
}

function Get-PaquetBuilderPeScriptEvidence {
  <#
  .SYNOPSIS
    Recover literal PBCore.SetVar calls and uninstall-key identities from mapped PE bytes.
  .DESCRIPTION
    Only PE headers and file-backed sections are materialized. The potentially large installer overlay is excluded.
  .PARAMETER Stream
    Parser-owned installer stream. Its position is restored.
  .PARAMETER Layout
    Parsed PE layout for Stream.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Layout)

  $MappedLength = [long]$Layout.SizeOfHeaders
  foreach ($Section in $Layout.Sections) { $MappedLength = [Math]::Max($MappedLength, [long]$Section.RawOffset + [long]$Section.RawSize) }
  if ($MappedLength -le 0 -or $MappedLength -gt $Script:PaquetBuilderMaximumMappedPeBytes -or $MappedLength -gt $Stream.Length) {
    throw "The mapped Paquet Builder PE exceeds the $($Script:PaquetBuilderMaximumMappedPeBytes)-byte analysis limit."
  }

  $Image = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$MappedLength)
  $ExecutableSectionIndexes = [Collections.Generic.List[uint32]]::new()
  for ($Index = 0; $Index -lt $Layout.Sections.Count; $Index++) {
    if (([uint32]$Layout.Sections[$Index].Characteristics -band 0x20000000) -ne 0) { $ExecutableSectionIndexes.Add([uint32]$Index) }
  }
  $Import = $Layout.DataDirectories['Import']
  $DelayImport = $Layout.DataDirectories['DelayImport']
  $Evidence = [Dumplings.PaquetBuilder.PaquetBuilderPeScanner]::Scan(
    $Image,
    [uint64]$Layout.ImageBase,
    ($Layout.OptionalHeaderFormat -eq 'PE32+'),
    [uint32]$Layout.SizeOfHeaders,
    [uint32[]]@($Layout.Sections.VirtualAddress),
    [uint32[]]@($Layout.Sections.VirtualSize),
    [uint32[]]@($Layout.Sections.RawOffset),
    [uint32[]]@($Layout.Sections.RawSize),
    [uint32]$Import.Rva,
    [uint32]$Import.Size,
    [uint32]$DelayImport.Rva,
    [uint32]$DelayImport.Size,
    $ExecutableSectionIndexes.ToArray())

  [pscustomobject]@{
    MappedBytes           = $Image
    SetVarImportFound     = [bool]$Evidence.SetVarImportFound
    Assignments           = @($Evidence.Assignments)
    UninstallProductCodes = [string[]]@($Evidence.UninstallProductCodes)
  }
}

function Read-PaquetBuilderRuntimeCatalog {
  <#
  .SYNOPSIS
    Decode the bounded metadata files in a modern Paquet Builder runtime archive.
  .PARAMETER Entries
    Normalized entries from Archive.
  #>
  param ([Parameter(Mandatory)][object[]]$Entries)

  $PropertyEntry = @($Entries | Where-Object FullName -IEQ 'pbfprop.dat')[0]
  $DialogEntry = @($Entries | Where-Object FullName -IEQ 'pbdlg.dat')[0]
  $LanguageEntry = @($Entries | Where-Object FullName -IEQ 'pblng.dat')[0]
  $RemoveEntry = @($Entries | Where-Object FullName -IEQ 'pbremove.dat')[0]
  $Records = [Collections.Generic.List[object]]::new()
  $MalformedPropertyCatalog = $false

  # pbfprop.dat stores exactly five CRLF-delimited values per packaged item.
  if ($PropertyEntry) {
    $Text = Read-InstallerArchiveEntryText -Entry $PropertyEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    $Lines = [Collections.Generic.List[string]]::new()
    foreach ($Line in [regex]::Split($Text, '\r\n|\n|\r')) { $Lines.Add($Line) }
    while ($Lines.Count -gt 0 -and [string]::IsNullOrEmpty($Lines[$Lines.Count - 1])) { $Lines.RemoveAt($Lines.Count - 1) }
    if ($Lines.Count % 5 -ne 0) {
      $MalformedPropertyCatalog = $true
    } else {
      for ($Index = 0; $Index -lt $Lines.Count; $Index += 5) {
        $Flags = 0
        $HasFlags = [int]::TryParse($Lines[$Index + 4], [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Flags)
        $Records.Add([pscustomobject][ordered]@{
            Path              = $Lines[$Index]
            ObservedField1    = $Lines[$Index + 1]
            ObservedField2    = $Lines[$Index + 2]
            ComponentVariable = $Lines[$Index + 3]
            Flags             = $HasFlags ? $Flags : $null
          })
      }
    }
  }

  # pblng.dat repeats a small [PBLang], language-name, LCID tuple.
  $Languages = [Collections.Generic.List[object]]::new()
  if ($LanguageEntry) {
    $LanguageText = Read-InstallerArchiveEntryText -Entry $LanguageEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    $LanguageLines = [regex]::Split($LanguageText, '\r\n|\n|\r')
    for ($Index = 0; $Index + 2 -lt $LanguageLines.Count; $Index++) {
      if ($LanguageLines[$Index] -cne '[PBLang]') { continue }
      $Lcid = 0
      $null = [int]::TryParse($LanguageLines[$Index + 2], [ref]$Lcid)
      $Languages.Add([pscustomobject]@{ Name = $LanguageLines[$Index + 1]; Lcid = $Lcid })
      $Index += 2
    }
  }

  $Dialogs = [Collections.Generic.List[string]]::new()
  if ($DialogEntry) {
    $DialogText = Read-InstallerArchiveEntryText -Entry $DialogEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    foreach ($Match in [regex]::Matches($DialogText, '(?m)^\[(?<Name>[^\]\r\n]+)\]\s*$')) { $Dialogs.Add($Match.Groups['Name'].Value) }
  }

  [pscustomobject][ordered]@{
    PropertyRecords          = $Records.ToArray()
    PropertyCatalogMalformed = $MalformedPropertyCatalog
    Languages                = $Languages.ToArray()
    Dialogs                  = [string[]]@($Dialogs | Select-Object -Unique)
    HasUninstallerTemplate   = [bool]$RemoveEntry
    UninstallerTemplateSize  = $RemoveEntry ? [long]$RemoveEntry.Length : 0L
  }
}

function Get-PaquetBuilderNestedMsiInfo {
  <#
  .SYNOPSIS
    Parse the sole nested MSI from an already-open legacy payload archive.
  .PARAMETER Entries
    Normalized payload entries.
  #>
  param ([Parameter(Mandatory)][object[]]$Entries)

  $MsiEntries = @($Entries | Where-Object FullName -Match '(?i)\.msi$')
  if ($MsiEntries.Count -ne 1) { return [pscustomobject]@{ Entry = $null; Info = $null; Error = $null; CandidateCount = $MsiEntries.Count } }
  $TempFolder = New-TempFolder
  try {
    $TempPath = Join-Path $TempFolder ([IO.Path]::GetFileName($MsiEntries[0].FullName))
    $null = Export-InstallerArchiveEntry -Entry $MsiEntries[0] -DestinationPath $TempPath -MaximumBytes 2147483648 -CollisionAction Overwrite
    try {
      $Info = Get-MsiInstallerInfo -Path $TempPath
      return [pscustomobject]@{ Entry = $MsiEntries[0].FullName; Info = $Info; Error = $null; CandidateCount = 1 }
    } catch {
      return [pscustomobject]@{ Entry = $MsiEntries[0].FullName; Info = $null; Error = $_.Exception.Message; CandidateCount = 1 }
    }
  } finally {
    Remove-Item -LiteralPath $TempFolder -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-PaquetBuilderCabinetData {
  <#
  .SYNOPSIS
    Enumerate the exact Microsoft cabinet referenced by a Paquet Builder ISFX descriptor.
  .PARAMETER Path
    Resolved path to the complete installer.
  .PARAMETER Descriptor
    Validated ISFX descriptor containing the absolute cabinet offset.
  .PARAMETER IncludeMetadata
    Parse a sole nested MSI while the temporary bounded cabinet is available.
  #>
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Descriptor,
    [switch]$IncludeMetadata
  )

  $SourcePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($Descriptor.PayloadOffset + 36 -gt $Source.Length) { throw 'The Paquet Builder cabinet header is truncated.' }
    $Header = Read-BinaryBytes -Stream $Source -Offset $Descriptor.PayloadOffset -Count 36
    if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'MSCF') { throw 'The Paquet Builder ISFX payload is not a Microsoft cabinet.' }
    $CabinetSize = [long][BitConverter]::ToUInt32($Header, 8)
    if ($CabinetSize -lt 36 -or $CabinetSize -gt $Script:PaquetBuilderMaximumArchiveBytes -or $CabinetSize -gt $Source.Length - $Descriptor.PayloadOffset) { throw 'The Paquet Builder cabinet declares an invalid bounded size.' }
  } finally {
    $Source.Dispose()
  }

  $CabinetPath = New-TempFile
  try {
    $null = Export-InstallerArchiveRange -Path $SourcePath -Offset $Descriptor.PayloadOffset -Length $CabinetSize -DestinationPath $CabinetPath -CollisionAction Overwrite
    $Entries = @(Get-CabinetEntry -Path $CabinetPath -MaximumEntries 65536)
    if ($Entries.Count -eq 0) { throw 'The Paquet Builder cabinet contains no files.' }
    $NestedMsi = [pscustomobject]@{ Entry = $null; Info = $null; Error = $null; CandidateCount = @($Entries | Where-Object FullName -Match '(?i)\.msi$').Count }
    if ($IncludeMetadata -and $NestedMsi.CandidateCount -eq 1) {
      $MsiEntry = @($Entries | Where-Object FullName -Match '(?i)\.msi$')[0]
      $MsiPath = New-TempFile
      try {
        $null = Export-CabinetSelection -Path $CabinetPath -Selection @([pscustomobject]@{ SourceName = $MsiEntry.SourceName; DestinationPath = $MsiPath; Length = $MsiEntry.Length }) -MaximumEntries 1 -MaximumExpandedBytes 2147483648
        try {
          $NestedMsi = [pscustomobject]@{ Entry = $MsiEntry.FullName; Info = Get-MsiInstallerInfo -Path $MsiPath; Error = $null; CandidateCount = 1 }
        } catch {
          $NestedMsi = [pscustomobject]@{ Entry = $MsiEntry.FullName; Info = $null; Error = $_.Exception.Message; CandidateCount = 1 }
        }
      } finally {
        Remove-Item -LiteralPath $MsiPath -Force -ErrorAction SilentlyContinue
      }
    }

    [pscustomobject]@{
      SourcePath     = $SourcePath
      Range          = [pscustomobject]@{ Offset = [long]$Descriptor.PayloadOffset; Length = $CabinetSize; Format = 'Cabinet' }
      Entries        = $Entries
      Kind           = 'Payload'
      RuntimeCatalog = $null
      NestedMsi      = $NestedMsi
    }
  } finally {
    Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-PaquetBuilderArchiveData {
  <#
  .SYNOPSIS
    Parse and structurally classify Paquet Builder PE resources and archive ranges.
  .PARAMETER Path
    Path to a Paquet Builder installer. The file is opened once by this operation.
  .PARAMETER IncludeMetadata
    Decode modern runtime catalogs and a sole legacy nested MSI while archives are open.
  #>
  param ([Parameter(Mandatory)][string]$Path, [switch]$IncludeMetadata)

  $SourcePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $File = Get-Item -LiteralPath $SourcePath -Force
  $Stream = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The file is not a supported PE image.' }
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    $Resources = @(Get-PEResourceInfo -Stream $Stream -Layout $Layout | ForEach-Object {
        [pscustomobject]@{ Path = $SourcePath; TypeName = $_.TypeName; TypeId = $_.TypeId; Name = $_.Name; Id = $_.Id; LanguageId = $_.LanguageId; CodePage = $_.CodePage; Offset = $_.Offset; Size = $_.Size }
      })
    try {
      $VersionStrings = Get-PEVersionStringTable -Stream $Stream -Layout $Layout
      $VersionResourceError = $null
    } catch {
      # Some historical Delphi launchers contain version-resource padding that
      # the strict shared decoder rejects. FileVersionInfo is a safe metadata
      # fallback and does not weaken structural family detection.
      $FallbackVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($SourcePath)
      $VersionStrings = [pscustomobject]@{
        ProductName     = $FallbackVersion.ProductName
        ProductVersion  = $FallbackVersion.ProductVersion
        CompanyName     = $FallbackVersion.CompanyName
        FileDescription = $FallbackVersion.FileDescription
        Comments        = $FallbackVersion.Comments
      }
      $VersionResourceError = $_.Exception.Message
    }
    $ExecutionLevel = Get-PaquetBuilderRequestedExecutionLevel -Stream $Stream -Resources $Resources
    try {
      $ScriptEvidence = Get-PaquetBuilderPeScriptEvidence -Stream $Stream -Layout $Layout
      $ScriptScanError = $null
    } catch {
      # Script scanning is additive metadata analysis. A historical import-table
      # shape must not invalidate an otherwise proven Paquet Builder container.
      $ScriptEvidence = [pscustomobject]@{ MappedBytes = $null; SetVarImportFound = $false; Assignments = @(); UninstallProductCodes = @() }
      $ScriptScanError = $_.Exception.Message
    }

    $ResourceNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Resource in $Resources) { if ($Resource.TypeId -eq 10 -and -not [string]::IsNullOrWhiteSpace($Resource.Name)) { $null = $ResourceNames.Add($Resource.Name) } }
    $EngResource = @($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'ENG' })[0]
    $IsfxResource = @($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'ISFX' })[0]
    $EngMagic = $null
    if ($EngResource -and $EngResource.Size -ge 2) { $EngMagic = [Convert]::ToHexString((Read-BinaryBytes -Stream $Stream -Offset $EngResource.Offset -Count 2)) }

    $IdentityText = @($VersionStrings.ProductName, $VersionStrings.FileDescription, $VersionStrings.CompanyName, $VersionStrings.Comments) -join "`n"
    $HasPaquetIdentity = $IdentityText -match '(?i)Paquet\s*Builder|G\.?D\.?G\.?\s*Software|installpackbuilder'
    $IsfxDescriptor = if ($IsfxResource -and $HasPaquetIdentity) { Read-PaquetBuilderIsfxDescriptor -Stream $Stream -Resource $IsfxResource -FileLength $File.Length } else { $null }
    $GpRuntime = if ($EngResource -and $EngMagic -ceq '4750' -and $HasPaquetIdentity) { Read-PaquetBuilderGpRuntime -Stream $Stream -Resource $EngResource } else { $null }
    $MissingClassicResource = @('DESCRIPTION', 'DVCLAL', 'PACKAGEINFO') | Where-Object { -not $ResourceNames.Contains($_) }
    $ClassicEnvelope = if (-not $MissingClassicResource -and $HasPaquetIdentity) { Read-PaquetBuilderClassicEnvelope -Stream $Stream -OverlayOffset $OverlayOffset } else { $null }
  } finally {
    $Stream.Dispose()
  }

  # Archive ranges are independently validated so an incidental 7z signature is not accepted.
  $Candidates = [Collections.Generic.List[object]]::new()
  if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $File.Length) {
    foreach ($Range in @(Get-EmbeddedSevenZipArchiveRange -Path $SourcePath -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:PaquetBuilderMaximumArchiveBytes)) {
      $Context = $null
      try {
        $Context = Open-InstallerArchiveRange -Path $SourcePath -Range $Range
        $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive)
        if ($Entries.Count -eq 0) { continue }
        $RuntimeMarkers = @($Entries | Where-Object { $_.FullName -ieq 'pbfprop.dat' -or $_.FullName -match '(?i)^PBCore(?:64|A64)?\.dll$' })
        $Kind = $RuntimeMarkers.Count -gt 0 ? 'Runtime' : 'Payload'
        $RuntimeCatalog = $null
        $NestedMsi = $null
        if ($IncludeMetadata -and $Kind -eq 'Runtime') { $RuntimeCatalog = Read-PaquetBuilderRuntimeCatalog -Entries $Entries }
        if ($IncludeMetadata -and $Kind -eq 'Payload') { $NestedMsi = Get-PaquetBuilderNestedMsiInfo -Entries $Entries }
        $Candidates.Add([pscustomobject]@{ SourcePath = $SourcePath; Range = $Range; Entries = $Entries; Kind = $Kind; RuntimeCatalog = $RuntimeCatalog; NestedMsi = $NestedMsi })
      } catch {
        continue
      } finally {
        if ($Context) { Close-InstallerArchiveRange -Context $Context }
      }
    }
  }

  $Runtime = @($Candidates | Where-Object Kind -EQ 'Runtime' | Sort-Object { $_.Range.Offset })[0]
  $Payloads = @($Candidates | Where-Object Kind -EQ 'Payload' | Sort-Object { $_.Range.Length } -Descending)
  $Payload = $Payloads.Count -gt 0 ? $Payloads[0] : $null
  $CabinetPackage = if ($Candidates.Count -eq 0 -and $EngMagic -ceq '4D5A' -and $IsfxDescriptor -and $HasPaquetIdentity) { Get-PaquetBuilderCabinetData -Path $SourcePath -Descriptor $IsfxDescriptor -IncludeMetadata:$IncludeMetadata } else { $null }
  $ClassicPackage = $null
  $ClassicPackageError = $null
  if ($ClassicEnvelope) {
    $ClassicRange = @(Get-EmbeddedZipArchiveRange -Path $SourcePath -MaximumArchives 16 | Where-Object Offset -EQ $ClassicEnvelope.ArchiveOffset)[0]
    if ($ClassicRange) {
      $Context = $null
      try {
        $Context = Open-InstallerArchiveRange -Path $SourcePath -Range $ClassicRange
        $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive)
        if ($Entries.Count -eq 0) { throw 'The Classic Paquet Builder package archive contains no entries.' }
        $ClassicPackage = [pscustomobject]@{ SourcePath = $SourcePath; Range = $ClassicRange; Entries = $Entries; Kind = 'ClassicPackage'; RuntimeCatalog = $null; NestedMsi = $null }
      } catch {
        $ClassicPackageError = $_.Exception.Message
      } finally {
        if ($Context) { Close-InstallerArchiveRange -Context $Context }
      }
    } elseif ($ClassicEnvelope.ArchiveOffset -lt $File.Length) {
      $ClassicPackageError = 'No complete ZIP central directory was found at the Classic package boundary.'
    }
  }

  $ProfileId = $null
  if ($Runtime -and $Payload) {
    $ProfileId = 'SplitArchiveRuntime'
  } elseif ($Candidates.Count -eq 1 -and $Payload -and $EngMagic -ceq '4D5A' -and $HasPaquetIdentity) {
    $ProfileId = 'LegacyEmbeddedPeRuntime'
  } elseif ($Candidates.Count -eq 1 -and $Payload -and $EngMagic -ceq '4750' -and $HasPaquetIdentity) {
    $ProfileId = 'CompressedResourceRuntime'
  } elseif ($CabinetPackage) {
    $ProfileId = 'CabinetPackageRuntime'
  } elseif ($Candidates.Count -eq 0 -and $ClassicEnvelope -and $HasPaquetIdentity) {
    $ProfileId = 'ClassicResourcePackage'
  }
  if (-not $ProfileId) { throw 'The PE does not contain a supported Paquet Builder structural layout.' }
  if ($ProfileId -eq 'ClassicResourcePackage' -and $ClassicPackage) { $Payload = $ClassicPackage }
  if ($ProfileId -eq 'CabinetPackageRuntime') { $Payload = $CabinetPackage }

  $AllArchives = [Collections.Generic.List[object]]::new()
  foreach ($Archive in $Candidates) { $AllArchives.Add($Archive) }
  if ($CabinetPackage) { $AllArchives.Add($CabinetPackage) }
  if ($ClassicPackage) { $AllArchives.Add($ClassicPackage) }

  [pscustomobject][ordered]@{
    Path                    = $SourcePath
    File                    = $File
    Layout                  = $Layout
    OverlayOffset           = $OverlayOffset
    Profile                 = Get-PaquetBuilderFormatProfile -Id $ProfileId
    Resources               = $Resources
    EngResource             = $EngResource
    EngMagic                = $EngMagic
    IsfxDescriptor          = $IsfxDescriptor
    GpRuntime               = $GpRuntime
    ClassicEnvelope         = $ClassicEnvelope
    ClassicPackageError     = $ClassicPackageError
    VersionStrings          = $VersionStrings
    RequestedExecutionLevel = $ExecutionLevel
    ScriptEvidence          = $ScriptEvidence
    ScriptScanError         = $ScriptScanError
    VersionResourceError    = $VersionResourceError
    Archives                = $AllArchives.ToArray()
    Payload                 = $Payload
    Runtime                 = $Runtime
  }
}

function Get-PaquetBuilderAssignmentValue {
  <#
  .SYNOPSIS
    Return distinct values assigned to a compiled PBCore variable.
  .PARAMETER Assignments
    Literal assignments recovered by the native PE scanner.
  .PARAMETER Name
    Case-insensitive PBCore variable name.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Assignments, [Parameter(Mandatory)][string]$Name)

  return [string[]]@($Assignments | Where-Object Name -IEQ $Name | Select-Object -ExpandProperty Value -Unique)
}

function ConvertFrom-PaquetBuilderRuntimePath {
  <#
  .SYNOPSIS
    Convert a literal Paquet Builder destination expression to a manifest-safe path.
  .PARAMETER Path
    Literal runtime path expression.
  .PARAMETER Scope
    Singular proven installation scope used to resolve PBINSTALLSCOPEDIR.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Path, [string]$Scope)

  $Result = $Path.Trim()
  if ([string]::IsNullOrWhiteSpace($Result)) { return $null }
  $ScopeRoot = $Scope -eq 'user' ? '%LOCALAPPDATA%\Programs' : ($Scope -eq 'machine' ? '%ProgramFiles%' : $null)
  if ($Result -match '(?i)%PBINSTALLSCOPEDIR%' -and -not $ScopeRoot) { return $null }
  $Result = $Result -ireplace '%PBINSTALLSCOPEDIR%', $ScopeRoot
  $Result = $Result -ireplace '%PROGFILESDIR%', '%ProgramFiles%'
  $Result = $Result -ireplace '%LOCALAPPDATADIR%', '%LOCALAPPDATA%'
  $Result = $Result -ireplace '%APPDATADIR%', '%APPDATA%'
  $AllowedManifestVariables = @('ProgramFiles', 'LOCALAPPDATA', 'APPDATA')
  foreach ($Match in [regex]::Matches($Result, '%(?<Name>[A-Za-z0-9_]+)%')) {
    if ($Match.Groups['Name'].Value -notin $AllowedManifestVariables) { return $null }
  }
  return $Result
}

function ConvertTo-PaquetBuilderVersionString {
  <#
  .SYNOPSIS
    Normalize historical comma-separated numeric PE version strings.
  .PARAMETER Version
    Version-resource text. Non-numeric formats are preserved verbatim.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Version)

  $Value = $Version.Trim()
  if ($Value -match '^\d+(?:,\s*\d+)+$') { return $Value -replace ',\s*', '.' }
  return $Value
}

function Get-PaquetBuilderInfo {
  <#
  .SYNOPSIS
    Read source-backed Paquet Builder metadata, scope, ARP, switch, and payload evidence.
  .PARAMETER Path
    Path to a Paquet Builder installer. No installer or payload is executed.
  .OUTPUTS
    Common installer parser fields plus FormatGeneration, StructuralRoute, archives, runtime catalogs, compiled assignments, switches, modes, diagnostics, and unresolved fields.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Data = Get-PaquetBuilderArchiveData -Path $Path -IncludeMetadata
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $Assignments = @($Data.ScriptEvidence.Assignments)
    # The verified 2.7 and 2.8 routes can be MSI bootstrappers. Later payload
    # archives can contain MSI files as ordinary application data and are not projected.
    $NestedMsi = $Data.Profile.Id -in @('CabinetPackageRuntime', 'LegacyEmbeddedPeRuntime') -and $Data.Payload ? $Data.Payload.NestedMsi : $null
    $NestedMsiInfo = $NestedMsi ? $NestedMsi.Info : $null
    if ($Data.ScriptScanError) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Script.ScanIncomplete' -Message "Compiled PBCore metadata analysis was incomplete: $($Data.ScriptScanError)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'DefaultInstallLocation', 'InstallerSwitches')))
    }
    if ($Data.VersionResourceError) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'VersionResource.Fallback' -Message 'The strict PE version-resource decoder rejected the historical layout; Windows FileVersionInfo supplied identity metadata.' -Kind Fallback -Areas Metadata -Evidence $Data.VersionResourceError))
    }
    $ScopeValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'PBINSTALLSCOPE' | Where-Object { $_ -cin @('0', '1') })
    $SupportedScopes = [Collections.Generic.List[string]]::new()
    if ($ScopeValues -ccontains '0') { $SupportedScopes.Add('user') }
    if ($ScopeValues -ccontains '1') { $SupportedScopes.Add('machine') }
    $Scope = $SupportedScopes.Count -eq 1 ? $SupportedScopes[0] : $null
    if ($SupportedScopes.Count -eq 0 -and $Data.RequestedExecutionLevel -ieq 'requireAdministrator') { $Scope = 'machine'; $SupportedScopes.Add('machine') }
    if ($SupportedScopes.Count -eq 0 -and $NestedMsiInfo -and $NestedMsiInfo.Scope) { $Scope = [string]$NestedMsiInfo.Scope; $SupportedScopes.Add($Scope) }

    if ($SupportedScopes.Count -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Scope.Conditional' -Message 'Compiled PBCore assignments contain both user and machine installation-scope routes.' -Kind Ambiguous -Areas Metadata -AffectedFields Scope -Evidence $ScopeValues))
      $UnresolvedFields.Add('Scope')
    } elseif ($SupportedScopes.Count -eq 0) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Scope.Unresolved' -Message 'No exact compiled installation-scope assignment or requireAdministrator manifest proves the package scope.' -Kind Incomplete -Areas Metadata -AffectedFields Scope))
      $UnresolvedFields.Add('Scope')
    }

    $ElevationRequirement = $Data.RequestedExecutionLevel -ieq 'requireAdministrator' ? 'elevationRequired' : $null
    $ProductCodes = @($Data.ScriptEvidence.UninstallProductCodes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($NestedMsi -and $NestedMsi.Error) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'NestedMsi.ParseFailed' -Message "The sole nested MSI could not be parsed: $($NestedMsi.Error)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'UpgradeCode', 'AppsAndFeaturesEntries') -Evidence $NestedMsi.Entry))
    } elseif ($NestedMsi -and $NestedMsi.CandidateCount -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'NestedMsi.Ambiguous' -Message 'The legacy payload contains multiple MSI files, so no nested package was selected without architecture evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'UpgradeCode', 'AppsAndFeaturesEntries') -Evidence $NestedMsi.CandidateCount))
    }

    $ProductCode = if ($NestedMsiInfo -and $NestedMsiInfo.ProductCode) { $NestedMsiInfo.ProductCode } elseif ($ProductCodes.Count -eq 1) { $ProductCodes[0] } else { $null }
    $UpgradeCode = $NestedMsiInfo ? $NestedMsiInfo.UpgradeCode : $null
    if ($ProductCodes.Count -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Arp.MultipleLiteralKeys' -Message 'The package contains multiple literal uninstall-key identities; conditional runtime evidence is required to select one.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence $ProductCodes))
    }
    if (-not $ProductCode) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Arp.Unresolved' -Message 'The package contains no unique source-backed visible uninstall identity.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
      $UnresolvedFields.Add('ProductCode')
      $UnresolvedFields.Add('AppsAndFeaturesEntries')
    }

    $VersionStrings = $Data.VersionStrings
    $DisplayName = if ($NestedMsiInfo -and $NestedMsiInfo.DisplayName) { [string]$NestedMsiInfo.DisplayName } else { [string]$VersionStrings.ProductName }
    $DisplayVersion = if ($NestedMsiInfo -and $NestedMsiInfo.DisplayVersion) { [string]$NestedMsiInfo.DisplayVersion } else { ConvertTo-PaquetBuilderVersionString -Version ([string]$VersionStrings.ProductVersion) }
    $Publisher = if ($NestedMsiInfo -and $NestedMsiInfo.Publisher) { [string]$NestedMsiInfo.Publisher } else { [string]$VersionStrings.CompanyName }
    $DisplayName = $DisplayName.Trim()
    $DisplayVersion = $DisplayVersion.Trim()
    $Publisher = $Publisher.Trim()

    $DestinationValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'DESTPATH' | Where-Object { $_ -match '^(?:%[A-Za-z0-9_]+%|[A-Za-z]:[\\/])' })
    $ResolvedDestinationValues = @($DestinationValues | ForEach-Object { ConvertFrom-PaquetBuilderRuntimePath -Path $_ -Scope $Scope } | Where-Object { $_ } | Select-Object -Unique)
    $DefaultInstallLocation = $ResolvedDestinationValues.Count -eq 1 ? $ResolvedDestinationValues[0] : $null
    if ($DestinationValues.Count -gt 0 -and $ResolvedDestinationValues.Count -ne 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'InstallLocation.Dynamic' -Message 'The compiled destination path is conditional or contains unresolved runtime variables.' -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation -Evidence $DestinationValues))
      $UnresolvedFields.Add('DefaultInstallLocation')
    }

    $SilentValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'SILENT' | Where-Object { $_ -ceq '1' })
    $SupportsSilentInstallation = $Data.Profile.Id -eq 'SplitArchiveRuntime' -and $SilentValues.Count -gt 0
    $InstallerSwitches = $SupportsSilentInstallation ? [ordered]@{ Silent = '/s' } : $null
    $InstallModes = $SupportsSilentInstallation ? @('interactive', 'silent') : @('interactive')
    if ($Data.Profile.Id -ne 'SplitArchiveRuntime') {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Installability.GenerationSpecific' -Message 'Silent-install support is not projected for this historical structural route without exact compiled switch evidence.' -Kind ManualValidation -Areas Installability -AffectedFields @('InstallerSwitches', 'InstallModes') -Evidence $Data.Profile.Id))
    }

    if ($Data.Profile.Id -eq 'ClassicResourcePackage') {
      if ($Data.Payload) {
        $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Extraction.ClassicInstalledPathsUnresolved' -Message 'The Classic ZIP package and its GAF records can be expanded, but the compressed control catalog does not yet provide source-backed installed destination paths.' -Kind Incomplete -Areas Extraction -Evidence $Data.Payload.Entries.FullName))
      } else {
        $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Extraction.ClassicArchiveIncomplete' -Message "The Classic GPacker control block is valid, but its following ZIP package is absent or incomplete: $($Data.ClassicPackageError)" -Kind Invalid -Areas Extraction))
      }
    } elseif ($Data.Profile.Id -eq 'CabinetPackageRuntime') {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Metadata.CabinetConfigurationOpaque' -Message 'The 2.7-generation Microsoft cabinet can be expanded, while the configuration bytes preceding it remain structurally unresolved.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'InstallerSwitches') -Evidence $Data.IsfxDescriptor))
    } elseif ($Data.Profile.Id -eq 'CompressedResourceRuntime' -and $Data.GpRuntime.TrailingSize -gt 0) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Runtime.GpTrailingDataOpaque' -Message 'The GP-framed 2.9 runtime PE is decoded, while its separately sized package-specific trailing data remains structurally unresolved.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'Scope') -Evidence ([pscustomobject]@{ Offset = $Data.GpRuntime.TrailingOffset; Size = $Data.GpRuntime.TrailingSize })))
    }
    $RuntimeCatalog = $Data.Runtime ? $Data.Runtime.RuntimeCatalog : $null
    if ($RuntimeCatalog -and $RuntimeCatalog.PropertyCatalogMalformed) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Runtime.PropertyCatalogMalformed' -Message 'The pbfprop.dat catalog does not contain complete five-line records.' -Kind Invalid -Areas Extraction))
    }

    $WritesAppsAndFeaturesEntry = if ($NestedMsiInfo) { $true } elseif ($ProductCode -and $RuntimeCatalog -and $RuntimeCatalog.HasUninstallerTemplate) { $true } else { $null }
    $AppsAndFeaturesInstallerType = $NestedMsiInfo ? $NestedMsiInfo.InstallerType : $null
    $AppsAndFeaturesEntries = @()
    if ($ProductCode) {
      $ArpEntry = [ordered]@{ ProductCode = $ProductCode }
      if ($DisplayName) { $ArpEntry.DisplayName = $DisplayName }
      if ($DisplayVersion) { $ArpEntry.DisplayVersion = $DisplayVersion }
      if ($Publisher) { $ArpEntry.Publisher = $Publisher }
      $AppsAndFeaturesEntries = @($ArpEntry)
    }
    $NestedInstallerFiles = if ($Data.Payload) { @($Data.Payload.Entries | Where-Object FullName -Match '(?i)\.(?:exe|msi|msp|msix|appx)$' | Select-Object -ExpandProperty FullName) } else { @() }
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $LauncherArchitecture = switch ([uint16]$Data.Layout.Machine) { 0x014C { 'x86' }; 0x8664 { 'x64' }; 0xAA64 { 'arm64' }; default { $null } }

    [pscustomobject][ordered]@{
      Path                         = $Data.Path
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $UpgradeCode
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $DefaultInstallLocation
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $ProductCode
      AppsAndFeaturesInstallerType = $AppsAndFeaturesInstallerType
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Select-Object -Unique)
      Family                       = 'Paquet Builder'
      FormatGeneration             = $Data.Profile.Generation
      StructuralRoute              = $Data.Profile.Id
      ObservedBuilderRange         = $Data.Profile.ObservedBuilders
      FileDescription              = ([string]$VersionStrings.FileDescription).Trim()
      LauncherArchitecture         = $LauncherArchitecture
      RequestedExecutionLevel      = $Data.RequestedExecutionLevel
      ElevationRequirement         = $ElevationRequirement
      SupportedScopes              = $SupportedScopes.ToArray()
      SupportsSilentInstallation   = $SupportsSilentInstallation
      InstallModes                 = [string[]]$InstallModes
      InstallerSwitches            = $InstallerSwitches
      InstallerSuccessCodes        = @()
      CompiledVariableAssignments  = $Assignments
      RuntimeCatalog               = $RuntimeCatalog
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      PayloadFiles                 = $Data.Payload ? [string[]]@($Data.Payload.Entries.FullName) : @()
      RuntimeFiles                 = if ($Data.Runtime) { [string[]]@($Data.Runtime.Entries.FullName) } elseif ($Data.GpRuntime) { [string[]]@('ENG.exe', $(if ($Data.GpRuntime.TrailingSize -gt 0) { 'ENG.tail.bin' })) } else { @() }
      NestedInstallerFiles         = [string[]]$NestedInstallerFiles
      NestedMsiPath                = $NestedMsi ? $NestedMsi.Entry : $null
      PayloadArchiveRange          = $Data.Payload ? $Data.Payload.Range : $null
      RuntimeArchiveRange          = $Data.Runtime ? $Data.Runtime.Range : $null
      RuntimeResource              = $Data.EngResource
      RuntimeResourceInfo          = if ($Data.GpRuntime) { [pscustomobject][ordered]@{ HeaderSize = $Data.GpRuntime.HeaderSize; CompressedOffset = $Data.GpRuntime.CompressedOffset; CompressedSize = $Data.GpRuntime.CompressedSize; UncompressedSize = $Data.GpRuntime.UncompressedSize; TrailingOffset = $Data.GpRuntime.TrailingOffset; TrailingSize = $Data.GpRuntime.TrailingSize; ObservedField = $Data.GpRuntime.ObservedField; RuntimeVersionInfo = $Data.GpRuntime.RuntimeVersionInfo } } else { $null }
      IsfxDescriptor               = $Data.IsfxDescriptor
      ClassicEnvelope              = if ($Data.ClassicEnvelope) { [pscustomobject][ordered]@{ EnvelopeOffset = $Data.ClassicEnvelope.EnvelopeOffset; EnvelopeVersion = $Data.ClassicEnvelope.EnvelopeVersion; PackedBlockOffset = $Data.ClassicEnvelope.PackedBlockOffset; PackedBlockSize = $Data.ClassicEnvelope.PackedBlockSize; CompressedOffset = $Data.ClassicEnvelope.CompressedOffset; CompressedSize = $Data.ClassicEnvelope.CompressedSize; DecoderBytesRead = $Data.ClassicEnvelope.DecoderBytesRead; UncompressedSize = $Data.ClassicEnvelope.UncompressedSize; ExpectedCrc32 = $Data.ClassicEnvelope.ExpectedCrc32; ArchiveOffset = $Data.ClassicEnvelope.ArchiveOffset } } else { $null }
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.PaquetBuilder'; ParserMajor = 3; FormatCatalogVersion = $Script:PaquetBuilderFormatCatalog.CatalogVersion; Sources = @('PE resources', 'validated ZIP and 7z ranges', 'GPacker/LZHUF control records', 'GP/LZMA runtime records', 'PBCore.SetVar call sites', 'nested MSI metadata') }
    }
  }
}

function Export-PaquetBuilderResourceSelection {
  <#
  .SYNOPSIS
    Export selected Paquet Builder PE resources with collision and aggregate limits.
  .PARAMETER Data
    Parsed Paquet Builder layout.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Wildcard matching resource output names.
  .PARAMETER CollisionAction
    Output collision behavior.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER Prefix
    Optional relative output directory.
  #>
  param ($Data, [string]$DestinationPath, [string]$Name, [string]$CollisionAction, [long]$MaximumExpandedBytes, [string]$Prefix)

  $Results = [Collections.Generic.List[IO.FileInfo]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Written = 0L
  foreach ($Resource in @($Data.Resources | Where-Object TypeId -EQ 10)) {
    $ResourceName = if ($Resource.Name) { [string]$Resource.Name } else { "RCDATA-$($Resource.Id)" }
    if ($ResourceName -ieq 'ENG' -and $Data.GpRuntime) {
      # The GP resource contains two physical outputs: a decoded PE and a
      # separately sized package tail. Exporting the raw wrapper would conceal
      # the useful runtime and force callers to repeat the transform.
      $GpOutputs = [Collections.Generic.List[object]]::new()
      $GpOutputs.Add([pscustomobject]@{ Name = 'ENG.exe'; Length = [long]$Data.GpRuntime.RuntimeBytes.Length; Bytes = $Data.GpRuntime.RuntimeBytes; Offset = 0L })
      if ($Data.GpRuntime.TrailingSize -gt 0) { $GpOutputs.Add([pscustomobject]@{ Name = 'ENG.tail.bin'; Length = [long]$Data.GpRuntime.TrailingSize; Bytes = $null; Offset = [long]$Data.GpRuntime.TrailingOffset }) }
      foreach ($GpOutput in $GpOutputs) {
        if (-not (Test-ExtractionPattern -Path $GpOutput.Name -Pattern $Name)) { continue }
        $RelativePath = $Prefix ? (Join-Path $Prefix $GpOutput.Name) : $GpOutput.Name
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($GpOutput.Length -gt $MaximumExpandedBytes - $Written) { throw 'Paquet Builder resource extraction exceeds the configured output limit.' }
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if ($GpOutput.Bytes) {
          [IO.File]::WriteAllBytes($Target.Path, $GpOutput.Bytes)
        } else {
          $Source = [IO.File]::Open($Data.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try { Copy-BinaryStreamRange -Source $Source -Destination $Destination -Offset $GpOutput.Offset -Length $GpOutput.Length } finally { $Destination.Dispose(); $Source.Dispose() }
        }
        $File = Get-Item -LiteralPath $Target.Path -Force
        $Written += $File.Length
        $Results.Add($File)
      }
      continue
    }
    $Extension = if ($ResourceName -ieq 'ENG' -and $Data.EngMagic -ceq '4D5A') { '.exe' } else { '.bin' }
    $RelativePath = "$ResourceName$Extension"
    if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
    if ($Prefix) { $RelativePath = Join-Path $Prefix $RelativePath }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    if ($Resource.Size -gt $MaximumExpandedBytes - $Written) { throw 'Paquet Builder resource extraction exceeds the configured output limit.' }
    $File = Export-PEResourceData -Resource $Resource -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Written) -CollisionAction Overwrite
    $Written += $File.Length
    $Results.Add($File)
  }
  return $Results.ToArray()
}

function Expand-PaquetBuilderInstaller {
  <#
  .SYNOPSIS
    Extract Paquet Builder payload or runtime files without executing them.
  .PARAMETER Path
    Path to the installer.
  .PARAMETER DestinationPath
    Extraction root. A temporary directory is created when omitted.
  .PARAMETER Name
    Optional exact name or wildcard. Every file is selected when omitted.
  .PARAMETER ArchiveKind
    Payload, runtime resources, or both physical groups.
  .PARAMETER CollisionAction
    Behavior when an output path collides. Prompt asks only after a collision occurs.
  .PARAMETER MaximumExpandedBytes
    Aggregate maximum output bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Payload', 'Runtime', 'All')][string]$ArchiveKind = 'Payload',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184L
  )

  process {
    $Data = Get-PaquetBuilderArchiveData -Path $Path
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-PaquetBuilder-$([guid]::NewGuid().ToString('N'))" }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Results = [Collections.Generic.List[IO.FileInfo]]::new()
    $Written = 0L

    if ($ArchiveKind -in @('Payload', 'All')) {
      if (-not $Data.Payload) { throw "Paquet Builder payload extraction is unsupported for structural route '$($Data.Profile.Id)'." }
      $TargetRoot = $ArchiveKind -eq 'All' ? (Join-Path $DestinationPath 'Payload') : $DestinationPath
      if ($Data.Profile.Id -eq 'CabinetPackageRuntime') {
        # The cabinet API requires a filesystem path, so materialize only the
        # exact ISFX-declared range and remove it immediately after extraction.
        $CabinetPath = New-TempFile
        try {
          $null = Export-InstallerArchiveRange -Path $Data.Path -Offset $Data.Payload.Range.Offset -Length $Data.Payload.Range.Length -DestinationPath $CabinetPath -CollisionAction Overwrite
          foreach ($ExtractedPath in @(Export-CabinetEntry -Path $CabinetPath -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumEntries 65536 -MaximumExpandedBytes ($MaximumExpandedBytes - $Written))) {
            $File = Get-Item -LiteralPath $ExtractedPath -Force
            $Results.Add($File)
            $Written += $File.Length
          }
        } finally {
          Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
        }
      } else {
        $Context = Open-InstallerArchiveRange -Path $Data.Path -Range $Data.Payload.Range
        try {
          $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written)
          foreach ($File in $Selection.Files) { $Results.Add($File) }
          $Written += $Selection.ExpandedBytes
        } finally { Close-InstallerArchiveRange -Context $Context }
      }
    }

    if ($ArchiveKind -in @('Runtime', 'All')) {
      $TargetRoot = $ArchiveKind -eq 'All' ? (Join-Path $DestinationPath 'Runtime') : $DestinationPath
      if ($Data.Runtime) {
        $Context = Open-InstallerArchiveRange -Path $Data.Path -Range $Data.Runtime.Range
        try {
          $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written)
          foreach ($File in $Selection.Files) { $Results.Add($File) }
          $Written += $Selection.ExpandedBytes
        } finally { Close-InstallerArchiveRange -Context $Context }
      } else {
        $Prefix = $ArchiveKind -eq 'All' ? 'Runtime' : ''
        foreach ($File in @(Export-PaquetBuilderResourceSelection -Data $Data -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written) -Prefix $Prefix)) {
          $Results.Add($File)
          $Written += $File.Length
        }
      }
    }

    if ($Results.Count -eq 0) { throw "No Paquet Builder files matched '$Name'." }
    return $Results.ToArray()
  }
}

function Test-PaquetBuilder {
  <#
  .SYNOPSIS
    Test whether a file contains a supported structural Paquet Builder layout.
  .PARAMETER Path
    Path to the candidate installer.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-PaquetBuilderArchiveData -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads literal protocols from Paquet Builder registry evidence.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String[]. Literal protocol names, or an empty array when none are proven.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads literal file extensions from Paquet Builder registry evidence.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String[]. Literal file extensions, or an empty array when none are proven.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package display version from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed display version, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package display name from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed display name, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayName }
}

function Read-PublisherFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package publisher from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed publisher, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads a source-backed uninstall key or nested MSI ProductCode.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The literal uninstall identity, nested MSI ProductCode, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).ProductCode }
}

function Read-ScopeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the source-backed Paquet Builder installation scope.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. User or machine when one scope is proven, otherwise null.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-PaquetBuilderInfo, Expand-PaquetBuilderInstaller, Test-PaquetBuilder, Read-ProtocolsFromPaquetBuilder, Read-FileExtensionsFromPaquetBuilder, Read-ProductVersionFromPaquetBuilder, Read-ProductNameFromPaquetBuilder, Read-PublisherFromPaquetBuilder, Read-ProductCodeFromPaquetBuilder, Read-ScopeFromPaquetBuilder
