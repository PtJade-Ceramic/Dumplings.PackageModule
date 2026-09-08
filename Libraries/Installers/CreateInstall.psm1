# SPDX-License-Identifier: Apache-2.0
# Static CreateInstall parser for Gentee launcher programs and GEA v1/v2 archives.
# Format references:
# - https://www.createinstall.com/help/index.html
# - https://www.createinstall.com/history.html
# - https://www.gentee.com/source/src/projects/gea/index.htm
# CreateInstallFormatCatalog.psd1 separates physical GEA widths from the independently evolving
# addremove/addremoveex/addremoveext routine signatures. Observed release labels never dispatch code.
# The container logic is PowerShell; the adaptive-Huffman LZGE decoder is an
# attributed MIT asset. Binary structures consumed here use LE integers:
#
#   PE setup
#     +-- .gentee section
#     |   +-- optional embedded runtime DLL
#     |   `-- [expanded-size:u32][LZGE-compressed GE program]
#     `-- GEA overlay
#     +00 47 45 41 00 ("GEA\0")
#     +04 volume:u16, +06 id:u32, +0A/+0B version bytes
#     +14 flags:u32, +1A header-size:u32, +1E summary-size:i64
#     +26 info-size:u32, +2A/+32/+3A archive/volume sizes:i64
#     +42 moved-size:u32, +46 memory/block/solid multipliers
#     `-- catalog -> [order:u8][packed-size:u32/u64][packed data]*
#         +-- type 0: stored bytes
#         +-- type 1: LZGE adaptive-Huffman stream
#         `-- type 2: modified PPMd-I range stream + end marker
#
# Integers are LE. GEA v1 uses 32-bit file/block sizes; v2 uses 64-bit sizes.
# The launcher header is identified by "Gentee Launcher\0" and records the
# runtime/program sizes and the header's own file offset. The decoded GE program
# is a sequence of bounded object records; direct calls to CreateInstall's
# source-backed addremove family provide visible uninstall-key evidence.
# Password-protected records are never bypassed. PPMd is decoded by the bounded,
# source-shipped SharpCompress.Gentee managed provider, which preserves GEA's solid
# model state. SharpCompress's public PpmdStream implements standard H/H7Z/I1 models;
# it cannot decode GEA because Gentee changes I1 model behavior, allocator scheduling,
# and per-block framing.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'CreateInstallFormatCatalog.psd1')
if ([int]$Script:CreateInstallFormatCatalog.CatalogVersion -ne 2) { throw "Unsupported CreateInstall format catalog version '$($Script:CreateInstallFormatCatalog.CatalogVersion)'." }

$Script:CreateInstallMaximumHeaderBytes = 268435456
$Script:CreateInstallMaximumInfoBytes = 268435456
$Script:CreateInstallMaximumEntries = 1000000
$Script:CreateInstallMaximumBlockBytes = 268435456
$Script:CreateInstallMaximumGenteeBytes = 67108864
$Script:CreateInstallMaximumAnalysisBytes = 268435456
$Script:CreateInstallFlagPassword = 0x0001
$Script:CreateInstallFlagCompressedInfo = 0x0002
$Script:CreateInstallFileFlagAttribute = 0x0001
$Script:CreateInstallFileFlagFolder = 0x0010
$Script:CreateInstallFileFlagVersion = 0x0020
$Script:CreateInstallFileFlagGroup = 0x0040
$Script:CreateInstallFileFlagProtect = 0x0080
$Script:CreateInstallFileFlagSolid = 0x0100
# Gentee 4.0 stores VM command operands according to this 218-entry shift table.
# Values 3/5/8 consume one BWD operand and 7/11 consume two; other values have
# no generic operand. Commands with raw or length-delimited operands are handled
# separately by Read-CreateInstallGenteeCommands.
$Script:CreateInstallGenteeCommandShift = [byte[]](
  6, 5, 5, 5, 3, 5, 3, 6, 6, 8, 8, 8, 11, 6, 8, 8, 6, 4, 6, 4, 9, 10, 9, 4, 6, 6, 6, 6, 6, 9, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 9, 4, 8, 5, 5, 5, 6, 5, 7, 6, 5, 4, 2, 4, 4, 4, 4, 4, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 6, 9, 6, 9, 9, 6, 9, 6, 4, 4, 9, 6, 9, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
  1, 6, 9, 9, 9, 9, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 6, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 6, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 2, 2, 2, 2, 6, 1, 1, 1, 9, 9, 9, 9, 4, 4, 4, 4, 6, 6, 6,
  6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5
)

function Import-CreateInstallLzgeDecoder {
  <#
  .SYNOPSIS
    Load the MIT-licensed managed Gentee LZGE decoder once
  #>
  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'CreateInstall', 'GenteeLzgeDecoder.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.Gentee.LzgeDecoder'
}

function Import-CreateInstallPpmdDecoder {
  <#
  .SYNOPSIS
    Load the source-shipped SharpCompress Gentee PPMd provider once.
  .DESCRIPTION
    Loads an AnyCPU managed companion provider. No native architecture selection or
    external CreateInstall/GEA executable is involved.
  #>
  param ()

  if (-not ([Management.Automation.PSTypeName]'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder').Type) {
    Use-InstallerRuntimeLoadLock {
      # Add-Type publishes assemblies process-wide. Recheck under the shared loader lock so
      # concurrent parser runspaces cannot race to load the same provider twice.
      if (([Management.Automation.PSTypeName]'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder').Type) { return }
      $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Providers', 'SharpCompress.Gentee', 'SharpCompress.Gentee.dll'
      if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) { throw "The SharpCompress Gentee PPMd provider is missing: $AssemblyPath" }
      Add-Type -Path $AssemblyPath -ErrorAction Stop
    }
  }
}

function Read-CreateInstallGenteeBwd {
  <#
  .SYNOPSIS
    Read one bounded Gentee variable-width unsigned integer.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  if ($Cursor.Value -lt 0 -or $Cursor.Value -ge $Limit -or $Limit -gt $Bytes.Length) { throw 'The Gentee BWD value is outside its record' }
  $Lead = $Bytes[$Cursor.Value]
  $Cursor.Value++
  if ($Lead -le 187) { return [uint32]$Lead }
  if ($Lead -eq 254) {
    if ($Cursor.Value + 2 -gt $Limit) { throw 'The Gentee BWD uint16 is truncated' }
    $Value = [BitConverter]::ToUInt16($Bytes, $Cursor.Value)
    $Cursor.Value += 2
    return [uint32]$Value
  }
  if ($Lead -eq 255) {
    if ($Cursor.Value + 4 -gt $Limit) { throw 'The Gentee BWD uint32 is truncated' }
    $Value = [BitConverter]::ToUInt32($Bytes, $Cursor.Value)
    $Cursor.Value += 4
    return $Value
  }
  if ($Cursor.Value -ge $Limit) { throw 'The Gentee two-byte BWD value is truncated' }
  $Value = (255 * ($Lead - 188)) + $Bytes[$Cursor.Value]
  $Cursor.Value++
  return [uint32]$Value
}

function Read-CreateInstallGenteeString {
  <#
  .SYNOPSIS
    Read one bounded null-terminated UTF-8 string from a GE object record.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  if ($Cursor.Value -lt 0 -or $Cursor.Value -ge $Limit -or $Limit -gt $Bytes.Length) { throw 'The Gentee string is outside its record' }
  $End = [Array]::IndexOf($Bytes, [byte]0, $Cursor.Value, $Limit - $Cursor.Value)
  if ($End -lt 0) { throw 'The Gentee object contains an unterminated string' }
  $Value = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor.Value, $End - $Cursor.Value)
  $Cursor.Value = $End + 1
  return $Value
}

function Move-CreateInstallGenteeVariable {
  <#
  .SYNOPSIS
    Advance over one serialized Gentee variable descriptor.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  $null = Read-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Limit
}

function Read-CreateInstallGenteeVariable {
  <#
  .SYNOPSIS
    Decode one serialized Gentee variable descriptor and its optional initial value.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing object record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  $Type = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit
  if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable flags are truncated' }
  $Flags = $Bytes[$Cursor.Value]
  $Cursor.Value++
  $Name = if (($Flags -band 0x01) -ne 0) { Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit } else { $null }
  $OfType = if (($Flags -band 0x02) -ne 0) { Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit } else { $null }
  $Dimensions = [System.Collections.Generic.List[uint32]]::new()
  if (($Flags -band 0x04) -ne 0) {
    if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable dimensions are truncated' }
    $DimensionCount = $Bytes[$Cursor.Value]
    $Cursor.Value++
    for ($Index = 0; $Index -lt $DimensionCount; $Index++) { $Dimensions.Add((Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit)) }
  }

  $DataOffset = $null
  $Data = $null
  $Value = $null
  if (($Flags -band 0x20) -ne 0) {
    # GE stores stack primitives inline, strings as NUL-terminated UTF-8, and non-stack values
    # such as buf with a BWD byte length. Preserve the raw bytes for structured project lists.
    $PrimitiveSize = switch ($Type) {
      { $_ -in @(1, 2, 7, 11) } { 4; break }
      { $_ -in @(3, 4) } { 1; break }
      { $_ -in @(5, 6) } { 2; break }
      { $_ -in @(8, 9, 10) } { 8; break }
      default { $null }
    }
    if ($Type -eq 13) {
      $DataOffset = $Cursor.Value
      $Value = Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit
      $Data = [Text.Encoding]::UTF8.GetBytes($Value)
    } else {
      $DataSize = if ($null -ne $PrimitiveSize) { [uint32]$PrimitiveSize } else { Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit }
      if ($DataSize -gt $Limit - $Cursor.Value) { throw 'The Gentee variable data exceeds its record' }
      $DataOffset = $Cursor.Value
      $Data = [byte[]]::new([int]$DataSize)
      if ($DataSize -gt 0) { [Array]::Copy($Bytes, $Cursor.Value, $Data, 0, [int]$DataSize) }
      $Cursor.Value += [int]$DataSize
      $Value = switch ($Type) {
        1 { [BitConverter]::ToInt32($Data, 0); break }
        2 { [BitConverter]::ToUInt32($Data, 0); break }
        3 { [sbyte]$Data[0]; break }
        4 { [byte]$Data[0]; break }
        5 { [BitConverter]::ToInt16($Data, 0); break }
        6 { [BitConverter]::ToUInt16($Data, 0); break }
        7 { [BitConverter]::ToSingle($Data, 0); break }
        8 { [BitConverter]::ToDouble($Data, 0); break }
        9 { [BitConverter]::ToInt64($Data, 0); break }
        10 { [BitConverter]::ToUInt64($Data, 0); break }
        default { $null }
      }
    }
  }

  return [pscustomobject]@{
    Type       = [uint32]$Type
    Flags      = [byte]$Flags
    Name       = $Name
    OfType     = $OfType
    Dimensions = $Dimensions.ToArray()
    HasData    = ($Flags -band 0x20) -ne 0
    DataOffset = $DataOffset
    Data       = $Data
    Value      = $Value
  }
}

function Get-CreateInstallGenteeRecord {
  <#
  .SYNOPSIS
    Enumerate bounded objects in a decoded Gentee 4.0 program.
  .PARAMETER Bytes
    Complete decoded GE program beginning with the GE header.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -lt 22 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x00004547) { throw 'The decoded CreateInstall program does not have a Gentee GE header' }
  $HeaderSize = [BitConverter]::ToUInt32($Bytes, 12)
  $ProgramSize = [BitConverter]::ToUInt32($Bytes, 16)
  if ($HeaderSize -lt 22 -or $HeaderSize -gt $ProgramSize -or $ProgramSize -gt $Bytes.Length -or $ProgramSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The Gentee GE header declares invalid bounds' }
  $ProgramProfile = @($Script:CreateInstallFormatCatalog.ProgramProfiles | Where-Object { [int]$_.MajorVersion -eq [int]$Bytes[20] })
  if ($ProgramProfile.Count -ne 1) { throw "Unsupported Gentee GE major version '$($Bytes[20])'" }

  $Records = [System.Collections.Generic.List[object]]::new()
  $Offset = [int]$HeaderSize
  $NextObjectId = 1024
  while ($Offset -lt $ProgramSize) {
    if ($Records.Count -ge $Script:CreateInstallMaximumEntries -or $Offset + 6 -gt $ProgramSize) { throw 'The Gentee object table is truncated or excessive' }
    $Type = $Bytes[$Offset]
    $Flags = [BitConverter]::ToUInt32($Bytes, $Offset + 1)
    $Cursor = [pscustomobject]@{ Value = $Offset + 5 }
    $RecordSize = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $ProgramSize
    if ($RecordSize -lt $Cursor.Value - $Offset -or $RecordSize -gt $ProgramSize - $Offset) { throw 'A Gentee object record exceeds the GE program' }
    $EndOffset = $Offset + [int]$RecordSize
    $Name = if (($Flags -band 0x0001) -ne 0) { Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $EndOffset } else { $null }
    # The leading resource record is serialized outside the VM object table. All following records
    # retain their VM identifiers beginning at KERNEL_COUNT (1024).
    $ObjectId = if ($Type -eq 9) { $null } else { $CurrentId = $NextObjectId; $NextObjectId++; $CurrentId }
    $Records.Add([pscustomobject]@{
        Id            = $ObjectId
        Type          = [int]$Type
        Flags         = [uint32]$Flags
        Name          = $Name
        Offset        = $Offset
        PayloadOffset = [int]$Cursor.Value
        EndOffset     = $EndOffset
        Size          = [int]$RecordSize
      })
    $Offset = $EndOffset
  }
  if ($Offset -ne $ProgramSize) { throw 'The Gentee object records do not end at the declared program size' }
  return $Records.ToArray()
}

function Get-CreateInstallGenteeProgram {
  <#
  .SYNOPSIS
    Decode the bounded Gentee program embedded in a CreateInstall PE section.
  .PARAMETER Path
    Path to a CreateInstall setup executable. The file is opened read-only and never executed.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  Import-CreateInstallLzgeDecoder
  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName
  $Section = @($Layout.Sections | Where-Object Name -EQ '.gentee')
  if ($Section.Count -ne 1) { throw 'The CreateInstall PE does not contain one .gentee section' }
  $LauncherSignature = [Text.Encoding]::ASCII.GetBytes("Gentee Launcher`0")
  $SearchLength = [Math]::Min(131072L, $File.Length)
  $HeaderOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $LauncherSignature -Length $SearchLength -Maximum 4)
  if ($HeaderOffsets.Count -ne 1) { throw 'The Gentee launcher header could not be identified uniquely' }

  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # linkhead is packed: three byte fields precede an unaligned ushort and uint fields.
    $Header = Read-BinaryBytes -Stream $Stream -Offset $HeaderOffsets[0] -Count 113
    $Packed = $Header[26] -ne 0
    $RuntimeSize = [BitConverter]::ToUInt32($Header, 29)
    $ProgramRangeSize = [BitConverter]::ToUInt32($Header, 33)
    $RecordedHeaderOffset = [BitConverter]::ToUInt32($Header, 45)
    if ($RecordedHeaderOffset -ne $HeaderOffsets[0] -or $ProgramRangeSize -le 0 -or $ProgramRangeSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The Gentee launcher header has invalid program bounds' }
    if ($RuntimeSize -gt $Section[0].RawSize -or $ProgramRangeSize -gt $Section[0].RawSize - $RuntimeSize) { throw 'The Gentee launcher program exceeds the .gentee section' }
    $ProgramRange = Read-BinaryBytes -Stream $Stream -Offset ($Section[0].RawOffset + $RuntimeSize) -Count ([int]$ProgramRangeSize)
  } finally { $Stream.Dispose() }

  if ($Packed) {
    if ($ProgramRange.Length -lt 5) { throw 'The packed Gentee program is truncated' }
    $ExpandedSize = [BitConverter]::ToUInt32($ProgramRange, 0)
    if ($ExpandedSize -lt 22 -or $ExpandedSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The packed Gentee program declares an invalid expanded size' }
    $Compressed = [byte[]]::new($ProgramRange.Length - 4)
    [Array]::Copy($ProgramRange, 4, $Compressed, 0, $Compressed.Length)
    $ProgramBytes = [Dumplings.Gentee.LzgeDecoder]::Decode($Compressed, [int]$ExpandedSize)
  } else {
    $ProgramBytes = $ProgramRange
  }
  $Records = @(Get-CreateInstallGenteeRecord -Bytes $ProgramBytes)
  $ProgramProfile = @($Script:CreateInstallFormatCatalog.ProgramProfiles | Where-Object { [int]$_.MajorVersion -eq [int]$ProgramBytes[20] })[0]
  return [pscustomobject]@{
    Bytes             = $ProgramBytes
    Records           = $Records
    LauncherOffset    = [long]$HeaderOffsets[0]
    SectionOffset     = [long]$Section[0].RawOffset
    RuntimeSize       = [long]$RuntimeSize
    StoredProgramSize = [long]$ProgramRangeSize
    ProgramSize       = [long]$ProgramBytes.Length
    Packed            = $Packed
    VersionMajor      = [int]$ProgramBytes[20]
    VersionMinor      = [int]$ProgramBytes[21]
    ProgramProfile    = [string]$ProgramProfile.Id
    CommandCache      = [System.Collections.Generic.Dictionary[uint32, object]]::new()
    FunctionIndex     = $null
  }
}

function Get-CreateInstallGenteeCommand {
  <#
  .SYNOPSIS
    Decode command boundaries and literal operands from one GE bytecode record.
  .PARAMETER Program
    Decoded Gentee program and object records returned by Get-CreateInstallGenteeProgram.
  .PARAMETER Record
    One OVM_BYTECODE record from the decoded GE program.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$Record
  )

  if ($Record.Type -ne 3) { return @() }
  if ($null -ne $Record.Id -and $Program.PSObject.Properties['CommandCache'] -and $Program.CommandCache.ContainsKey([uint32]$Record.Id)) {
    return $Program.CommandCache[[uint32]$Record.Id]
  }
  $Bytes = $Program.Bytes
  $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
  # A bytecode object begins with its return descriptor, parameter descriptors, and grouped local
  # descriptors. Commands occupy the remaining bytes in the record.
  Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  $ParameterCount = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  for ($Index = 0; $Index -lt $ParameterCount; $Index++) { Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }
  $SetCount = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  $VariableCount = 0L
  for ($Index = 0; $Index -lt $SetCount; $Index++) { $VariableCount += Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }
  if ($VariableCount -gt 1000000) { throw 'The Gentee bytecode declares excessive local variables' }
  for ($Index = 0; $Index -lt $VariableCount; $Index++) { Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }

  $Commands = [System.Collections.Generic.List[object]]::new()
  while ($Cursor.Value -lt $Record.EndOffset) {
    $CommandOffset = $Cursor.Value
    $Command = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
    $Operand = $null
    if ($Command -ge 18 -and $Command -lt 236) {
      switch ($Command) {
        25 { if ($Cursor.Value + 1 -gt $Record.EndOffset) { throw 'A Gentee byte literal is truncated' }; $Operand = [uint32]$Bytes[$Cursor.Value]; $Cursor.Value++; break }
        26 { if ($Cursor.Value + 2 -gt $Record.EndOffset) { throw 'A Gentee ushort literal is truncated' }; $Operand = [uint32][BitConverter]::ToUInt16($Bytes, $Cursor.Value); $Cursor.Value += 2; break }
        27 { if ($Cursor.Value + 4 -gt $Record.EndOffset) { throw 'A Gentee uint literal is truncated' }; $Operand = [BitConverter]::ToUInt32($Bytes, $Cursor.Value); $Cursor.Value += 4; break }
        30 { if ($Cursor.Value + 8 -gt $Record.EndOffset) { throw 'A Gentee ulong literal is truncated' }; $Operand = [BitConverter]::ToUInt64($Bytes, $Cursor.Value); $Cursor.Value += 8; break }
        31 {
          $Count = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Count -gt ($Record.EndOffset - $Cursor.Value) / 4) { throw 'A Gentee command-list literal is truncated' }
          $Operand = [uint32]$Count
          $Cursor.Value += [int](4 * $Count)
          break
        }
        { $_ -in @(28, 29, 85) } { $Operand = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset; break }
        34 {
          $Length = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Length -gt $Record.EndOffset - $Cursor.Value) { throw 'A Gentee data literal exceeds its bytecode record' }
          $Operand = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor.Value, [int]$Length)
          $Cursor.Value += [int]$Length
          break
        }
        93 {
          $Count = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Count -gt ($Record.EndOffset - $Cursor.Value) / 4) { throw 'A Gentee assembler block is truncated' }
          $Operand = [uint32]$Count
          $Cursor.Value += [int](4 * $Count)
          break
        }
        default {
          $Shift = $Script:CreateInstallGenteeCommandShift[$Command - 18]
          if ($Shift -in @(7, 11)) {
            $Operand = @(
              Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
              Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
            )
          } elseif ($Shift -in @(3, 5, 8)) {
            $Operand = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          }
        }
      }
    }
    $Commands.Add([pscustomobject]@{ Index = $Commands.Count; Offset = $CommandOffset; Command = [uint32]$Command; Operand = $Operand })
  }
  $Result = $Commands.ToArray()
  if ($null -ne $Record.Id -and $Program.PSObject.Properties['CommandCache']) { $Program.CommandCache[[uint32]$Record.Id] = $Result }
  return $Result
}

function Get-CreateInstallGenteeParameterCount {
  <#
  .SYNOPSIS
    Read the declared parameter count from one Gentee bytecode object.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER Record
    Bytecode record whose function signature is inspected.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$Record
  )

  if ($Record.Type -ne 3) { throw 'Only Gentee bytecode records declare function parameters' }
  $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
  Move-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
  return Read-CreateInstallGenteeBwd -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
}

function ConvertFrom-CreateInstallGenteeList {
  <#
  .SYNOPSIS
    Decode one bounded, offset-addressed list from CreateInstall's generated g_list buffer.
  .PARAMETER Bytes
    Complete initialized Gentee buf value containing generated project lists.
  .PARAMETER Offset
    Zero-based offset in Bytes. The list starts with a uint32 LE row count.
  .PARAMETER FieldCount
    Number of NUL-terminated UTF-8 fields serialized for each row.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [Parameter(Mandatory)][ValidateRange(1, 64)][int]$FieldCount
  )

  if ($Offset -gt $Bytes.Length - 4) { throw 'The Gentee list offset is outside g_list' }
  $Count = [BitConverter]::ToUInt32($Bytes, $Offset)
  if ($Count -gt $Script:CreateInstallMaximumEntries) { throw 'The Gentee list exceeds the configured row-count limit' }
  $Cursor = $Offset + 4
  $Rows = [System.Collections.Generic.List[object]]::new([int]$Count)
  for ($RowIndex = 0; $RowIndex -lt $Count; $RowIndex++) {
    $Fields = [string[]]::new($FieldCount)
    for ($FieldIndex = 0; $FieldIndex -lt $FieldCount; $FieldIndex++) {
      if ($Cursor -ge $Bytes.Length) { throw 'The Gentee list is truncated' }
      $End = [Array]::IndexOf($Bytes, [byte]0, $Cursor, $Bytes.Length - $Cursor)
      if ($End -lt 0) { throw 'The Gentee list contains an unterminated UTF-8 field' }
      $Fields[$FieldIndex] = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor, $End - $Cursor)
      $Cursor = $End + 1
    }
    $Rows.Add([pscustomobject]@{ Index = $RowIndex; Fields = $Fields })
  }
  return $Rows.ToArray()
}

function Get-CreateInstallProjectVariableEvidence {
  <#
  .SYNOPSIS
    Recover the generated MAINVAR project list from a decoded CreateInstall GE program.
  .PARAMETER Program
    Decoded program returned by Get-CreateInstallGenteeProgram.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Program)

  # CreateInstall initializes g_list as a Gentee buf global. Optimized GE files omit the global
  # name, so candidate offsets come only from integer literals actually referenced by bytecode.
  $Buffers = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 6)) {
    $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
    $Variable = Read-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    if ($Cursor.Value -ne $Record.EndOffset) { throw 'A Gentee global record contains trailing data' }
    if ($Variable.Type -eq 12 -and $Variable.HasData -and $Variable.Data.Length -ge 4) {
      $Buffers.Add([pscustomobject]@{ ObjectId = $Record.Id; Data = $Variable.Data })
    }
  }

  $ReferencedOffsets = [System.Collections.Generic.HashSet[uint32]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    foreach ($Command in @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)) {
      if ($Command.Command -in @(25, 26, 27) -and $Command.Operand -is [ValueType]) { $null = $ReferencedOffsets.Add([uint32]$Command.Operand) }
    }
  }

  $Candidates = [System.Collections.Generic.List[object]]::new()
  foreach ($Buffer in $Buffers) {
    foreach ($Offset in $ReferencedOffsets) {
      if ($Offset -gt $Buffer.Data.Length - 4) { continue }
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $Buffer.Data -Offset ([int]$Offset) -FieldCount 2) } catch { continue }
      $Variables = [ordered]@{}
      $Valid = $true
      foreach ($Row in $Rows) {
        $Name = [string]$Row.Fields[0]
        if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains([char]0)) { $Valid = $false; break }
        $Variables[$Name] = [string]$Row.Fields[1]
      }
      if (-not $Valid) { continue }
      # These values are consumed directly by common_init and addremove*. Requiring all six
      # separates MAINVAR from command-specific two-column lists without relying on an object ID.
      $RequiredNames = @('progname', 'ver', 'compname', 'setuppath', 'uninstexe', 'silentpar')
      if (@($RequiredNames | Where-Object { -not $Variables.Contains($_) }).Count -eq 0) {
        $Candidates.Add([pscustomobject]@{ BufferObjectId = $Buffer.ObjectId; Offset = [uint32]$Offset; Variables = $Variables; Count = $Rows.Count; BufferData = $Buffer.Data })
      }
    }
  }
  if ($Candidates.Count -eq 0) { throw 'The compiled CreateInstall program does not expose one referenced MAINVAR list' }
  if ($Candidates.Count -gt 1) {
    $Distinct = @($Candidates | Group-Object { ($_.Variables.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join "`0" })
    if ($Distinct.Count -ne 1) { throw 'The compiled CreateInstall program exposes conflicting MAINVAR lists' }
  }
  return $Candidates[0]
}

function Resolve-CreateInstallMacroValue {
  <#
  .SYNOPSIS
    Resolve deterministic CreateInstall #macro# substitutions to manifest-safe values.
  .PARAMETER Value
    Compiled string expression to expand.
  .PARAMETER Variables
    Case-insensitive MAINVAR key/value dictionary recovered from the GE program.
  .PARAMETER Is32Bit
    Indicates that the CreateInstall process uses the 32-bit Windows folder view.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  if ($null -eq $Value) { return [pscustomobject]@{ Value = $null; UnresolvedMacros = [string[]]@() } }
  $Known = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $Variables.GetEnumerator()) { $Known[[string]$Entry.Key] = [string]$Entry.Value }
  $Known['progfiles'] = $Is32Bit ? '%ProgramFiles(x86)%' : '%ProgramFiles%'
  $Known['comprogfiles'] = $Is32Bit ? '%CommonProgramFiles(x86)%' : '%CommonProgramFiles%'
  $Known['appdata'] = '%APPDATA%'
  $Known['comappdata'] = '%ProgramData%'
  $Known['windows'] = '%WINDIR%'
  $Known['winpath'] = '%WINDIR%'
  $Known['temp'] = '%TEMP%'
  $Known['temppath'] = '%TEMP%'
  $Known['syspath'] = '%WINDIR%\System32'
  $Known['localpath'] = '%LOCALAPPDATA%'
  $Known['userpath'] = '%USERPROFILE%'
  $Known['progpath'] = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
  $Known['comprogpath'] = '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
  $Known['start'] = '%APPDATA%\Microsoft\Windows\Start Menu'
  $Known['comstart'] = '%ProgramData%\Microsoft\Windows\Start Menu'
  $Known['startup'] = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
  $Known['comstartup'] = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
  $Known['desktop'] = '%USERPROFILE%\Desktop'
  $Known['comdesktop'] = '%PUBLIC%\Desktop'
  $Known['quicklaunch'] = '%APPDATA%\Microsoft\Internet Explorer\Quick Launch'
  $Known['sendto'] = '%APPDATA%\Microsoft\Windows\SendTo'
  $Known['fontpath'] = '%WINDIR%\Fonts'
  $Known['docpath'] = '%USERPROFILE%\Documents'
  $Known['comdocpath'] = '%PUBLIC%\Documents'
  $Known['picpath'] = '%USERPROFILE%\Pictures'
  $Known['compicpath'] = '%PUBLIC%\Pictures'
  $Known['musicpath'] = '%USERPROFILE%\Music'
  $Known['commusicpath'] = '%PUBLIC%\Music'
  $Known['videopath'] = '%USERPROFILE%\Videos'
  $Known['comvideopath'] = '%PUBLIC%\Videos'
  $Known['iefavpath'] = '%USERPROFILE%\Favorites'
  $Known['cookies'] = '%LOCALAPPDATA%\Microsoft\Windows\INetCookies'
  $Known['history'] = '%LOCALAPPDATA%\Microsoft\Windows\History'

  $Resolved = $Value
  for ($Depth = 0; $Depth -lt 16; $Depth++) {
    $Previous = $Resolved
    $Resolved = [regex]::Replace($Previous, '#(?<Name>[^#]+)#', {
        param($Match)
        $Name = $Match.Groups['Name'].Value
        if ($Known.ContainsKey($Name)) { return $Known[$Name] }
        return $Match.Value
      })
    if ($Resolved -ceq $Previous) { break }
  }
  $Unresolved = @([regex]::Matches($Resolved, '#(?<Name>[^#]+)#') | ForEach-Object { $_.Groups['Name'].Value } | Sort-Object -Unique)
  return [pscustomobject]@{ Value = $Resolved; UnresolvedMacros = [string[]]$Unresolved }
}

function Join-CreateInstallMacroPath {
  <#
  .SYNOPSIS
    Join two compiled CreateInstall path operands before deterministic macro expansion.
  .PARAMETER Parent
    Parent path operand.
  .PARAMETER Child
    Optional file-name operand.
  .PARAMETER Variables
    MAINVAR key/value dictionary.
  .PARAMETER Is32Bit
    Indicates the 32-bit Windows folder view.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowEmptyString()][string]$Parent,
    [AllowEmptyString()][string]$Child,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Combined = if ([string]::IsNullOrWhiteSpace($Child)) { $Parent } elseif ([string]::IsNullOrWhiteSpace($Parent)) { $Child } else { $Parent.TrimEnd([char[]]'\/') + '\' + $Child.TrimStart([char[]]'\/') }
  return Resolve-CreateInstallMacroValue -Value $Combined -Variables $Variables -Is32Bit $Is32Bit
}

function Resolve-CreateInstallCondition {
  <#
  .SYNOPSIS
    Resolve the bounded Boolean subset accepted by CreateInstall's ifcondition routine.
  .PARAMETER Expression
    Literal condition string stored in a generated operation list.
  .PARAMETER Variables
    Compiled macro dictionary used by ifcondition for #name# expressions.
  #>
  [OutputType([Nullable[bool]])]
  param (
    [AllowNull()][string]$Expression,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables
  )

  if ([string]::IsNullOrWhiteSpace($Expression)) { return $true }
  $Condition = $Expression.Trim()
  $Negated = $Condition.StartsWith('!', [StringComparison]::Ordinal)
  if ($Negated) { $Condition = $Condition.Substring(1) }
  # @function conditions execute arbitrary project code and therefore cannot be evaluated safely.
  if ($Condition.StartsWith('@', [StringComparison]::Ordinal)) { return $null }
  $Name = $Condition.Trim('#')
  if (-not $Variables.Contains($Name)) { return $null }
  $Value = [string]$Variables[$Name]
  $Result = -not [string]::IsNullOrEmpty($Value) -and $Value -cne '0' -and $Value -cne 'false'
  return $Negated ? (-not $Result) : $Result
}

function Get-CreateInstallFunctionIndex {
  <#
  .SYNOPSIS
    Build one reusable index of Gentee function signatures, commands, and literal text.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  #>
  [OutputType([System.Collections.Generic.Dictionary[uint32, object]])]
  param ([Parameter(Mandatory)][psobject]$Program)

  if ($null -ne $Program.FunctionIndex) { return $Program.FunctionIndex }
  $Functions = [System.Collections.Generic.Dictionary[uint32, object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Functions[[uint32]$Record.Id] = [pscustomobject]@{
      Record         = $Record
      ParameterCount = Get-CreateInstallGenteeParameterCount -Program $Program -Record $Record
      Commands       = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
      LiteralText    = [Text.Encoding]::ASCII.GetString($Program.Bytes, $Record.PayloadOffset, $Record.EndOffset - $Record.PayloadOffset)
    }
  }
  $Program.FunctionIndex = $Functions
  return $Functions
}

function Get-CreateInstallGenteeExpressionEvidence {
  <#
  .SYNOPSIS
    Describe one unresolved CreateInstall condition and the bounded GE function it references.
  .PARAMETER Program
    Decoded GE program containing the function and command records.
  .PARAMETER Variables
    Compiled MAINVAR dictionary used to attach known values to referenced variable names.
  .PARAMETER Is32Bit
    Indicates the shell-folder view used when resolving known CreateInstall macros.
  .PARAMETER Operation
    Installer operation guarded by the expression, such as InstallGroup, Registry, Shortcut, or Run.
  .PARAMETER Expression
    Literal condition passed to CreateInstall's ifcondition routine.
  .PARAMETER CallerId
    GE object identifier of the function that invokes the guarded operation.
  .PARAMETER CallOffset
    GE-program-relative bytecode offset of the guarded operation call.
  .PARAMETER AffectedFields
    Metadata fields whose interpretation can change with the condition result.
  .PARAMETER Context
    Bounded operation-specific values needed to understand what the condition controls.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit,
    [Parameter(Mandatory)][string]$Operation,
    [Parameter(Mandatory)][string]$Expression,
    [AllowNull()][Nullable[uint32]]$CallerId,
    [AllowNull()][Nullable[int]]$CallOffset,
    [AllowNull()][string[]]$AffectedFields,
    [AllowNull()][object]$Context
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $ConditionText = $Expression.Trim()
  $Negated = $ConditionText.StartsWith('!', [StringComparison]::Ordinal)
  if ($Negated) { $ConditionText = $ConditionText.Substring(1) }
  $IsFunction = $ConditionText.StartsWith('@', [StringComparison]::Ordinal)
  $FunctionName = $IsFunction ? $ConditionText.Substring(1) : $null
  $FunctionMatches = if ($IsFunction) { @($Functions.Values | Where-Object { $_.Record.Name -ceq $FunctionName }) } else { @() }
  $Function = $FunctionMatches.Count -eq 1 ? $FunctionMatches[0] : $null

  # The command list is intentionally bounded. It gives an agent enough static evidence to trace
  # small generated if-functions without turning Get-*Info into an unbounded bytecode dump.
  $FunctionEvidence = $null
  $LiteralStrings = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  if ($null -ne $Function) {
    $CommandLimit = 256
    $Commands = [Collections.Generic.List[object]]::new([Math]::Min($Function.Commands.Count, $CommandLimit))
    $CalledFunctions = [Collections.Generic.List[object]]::new()
    $CalledIds = [Collections.Generic.HashSet[uint32]]::new()
    for ($CommandIndex = 0; $CommandIndex -lt [Math]::Min($Function.Commands.Count, $CommandLimit); $CommandIndex++) {
      $Command = $Function.Commands[$CommandIndex]
      $Commands.Add([pscustomobject]@{ Index = $Command.Index; Offset = $Command.Offset; Opcode = $Command.Command; Operand = $Command.Operand })
      if ($Command.Command -eq 34 -and $Command.Operand -is [string]) { $null = $LiteralStrings.Add([string]$Command.Operand) }
      $TargetId = [uint32]$Command.Command
      if ($Functions.ContainsKey($TargetId) -and $CalledIds.Add($TargetId)) {
        $Target = $Functions[$TargetId]
        $CalledFunctions.Add([pscustomobject]@{ ObjectId = $TargetId; Name = $Target.Record.Name; ParameterCount = $Target.ParameterCount })
      }
    }
    $FunctionEvidence = [pscustomobject][ordered]@{
      Name              = $FunctionName
      ObjectId          = [uint32]$Function.Record.Id
      ParameterCount    = [uint32]$Function.ParameterCount
      RecordOffset      = [int]$Function.Record.Offset
      RecordSize        = [int]$Function.Record.Size
      CommandCount      = [int]$Function.Commands.Count
      CommandsTruncated = $Function.Commands.Count -gt $CommandLimit
      LiteralStrings    = [string[]]@($LiteralStrings | Sort-Object)
      CalledFunctions   = $CalledFunctions.ToArray()
      Commands          = $Commands.ToArray()
    }
  }

  # Direct #name# conditions have one exact dependency. For @function conditions, identifier-like
  # string literals are candidate runtime variables because generated predicates commonly call
  # defmacro accessors with names such as oswindows. Candidate status is explicit to avoid assigning
  # semantics to unrelated function literals.
  $VariableNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Match in [regex]::Matches($Expression, '#(?<Name>[^#]+)#')) { $null = $VariableNames.Add($Match.Groups['Name'].Value) }
  if (-not $IsFunction) {
    $VariableName = $ConditionText.Trim('#')
    if (-not [string]::IsNullOrWhiteSpace($VariableName)) { $null = $VariableNames.Add($VariableName) }
  } else {
    foreach ($Literal in $LiteralStrings) {
      if ($Literal -match '^[A-Za-z_][A-Za-z0-9_.-]*$') { $null = $VariableNames.Add($Literal) }
      foreach ($Match in [regex]::Matches($Literal, '#(?<Name>[^#]+)#')) { $null = $VariableNames.Add($Match.Groups['Name'].Value) }
    }
  }

  # Follow macro references in known project values so the result contains the complete value chain
  # needed to judge a condition, while retaining runtime-only names as unknown evidence.
  $PendingNames = [Collections.Generic.Queue[string]]::new()
  foreach ($VariableName in $VariableNames) { $PendingNames.Enqueue($VariableName) }
  $VisitedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $VariableEvidence = [Collections.Generic.List[object]]::new()
  while ($PendingNames.Count -gt 0) {
    $VariableName = $PendingNames.Dequeue()
    if (-not $VisitedNames.Add($VariableName)) { continue }
    $Token = Resolve-CreateInstallMacroValue -Value "#$VariableName#" -Variables $Variables -Is32Bit $Is32Bit
    if ($Variables.Contains($VariableName)) {
      $RawValue = [string]$Variables[$VariableName]
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'ProjectVariable'; Value = $RawValue; ResolvedValue = $Token.Value; IsDefined = $true })
      foreach ($Match in [regex]::Matches($RawValue, '#(?<Name>[^#]+)#')) { $PendingNames.Enqueue($Match.Groups['Name'].Value) }
    } elseif ($Token.UnresolvedMacros -notcontains $VariableName) {
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'KnownMacro'; Value = $null; ResolvedValue = $Token.Value; IsDefined = $true })
    } else {
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'RuntimeOrUnknown'; Value = $null; ResolvedValue = $null; IsDefined = $false })
    }
  }

  return [pscustomobject][ordered]@{
    Operation          = $Operation
    Expression         = $Expression
    ExpressionKind     = $IsFunction ? 'FunctionCondition' : 'VariableCondition'
    Negated            = $Negated
    Evaluation         = $null
    RequiresReview     = $true
    CallerId           = $CallerId
    CallOffset         = $CallOffset
    AffectedFields     = [string[]]@($AffectedFields)
    Variables          = @($VariableEvidence | Sort-Object Name)
    ReferencedFunction = $FunctionEvidence
    FunctionFound      = $FunctionMatches.Count -eq 1
    Context            = $Context
  }
}

function Get-CreateInstallShortcutEvidence {
  <#
  .SYNOPSIS
    Recover direct shortcutex calls and compiled shlist table operations.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve paths, conditions, and list records.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  # shortcutex has eight parameters and delegates to a seven-parameter shortcut helper. shlist has
  # one parameter and names all eight source-backed row fields in its own bytecode. These structural
  # signatures survive stripped function names and avoid relying on link-time object identifiers.
  $CoreIds = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values) { if ($Function.ParameterCount -eq 7) { $null = $CoreIds.Add([uint32]$Function.Record.Id) } }
  $DirectTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object { $_.ParameterCount -eq 8 -and @($_.Commands | Where-Object { $CoreIds.Contains([uint32]$_.Command) }).Count -gt 0 })) { $null = $DirectTargets.Add([uint32]$Function.Record.Id) }
  $ListTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object {
        $_.ParameterCount -eq 1 -and $_.LiteralText.Contains('shpath', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('shfile', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('cmdline', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('defwork', [StringComparison]::Ordinal)
      })) { $null = $ListTargets.Add([uint32]$Function.Record.Id) }
  if ($DirectTargets.Count -eq 0 -and $ListTargets.Count -eq 0) { return [pscustomobject]@{ Calls = @(); Diagnostics = @() } }

  $Calls = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      if ($DirectTargets.Contains($TargetId)) {
        # The command generator starts from ten project fields: shortcut path/name, target
        # path/name, arguments, comment, icon, working path/name, and condition.
        $Start = [Math]::Max(0, $CommandIndex - 96)
        $Window = @($Commands[$Start..($CommandIndex - 1)])
        $Strings = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 10)
        $Integers = @($Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 1)
        if ($Strings.Count -ne 10 -or $Integers.Count -ne 1) { continue }
        $ConditionExpression = [string]$Strings[9].Operand
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Shortcut = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Target = Join-CreateInstallMacroPath -Parent ([string]$Strings[2].Operand) -Child ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Comment = Resolve-CreateInstallMacroValue -Value ([string]$Strings[5].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Icon = Resolve-CreateInstallMacroValue -Value ([string]$Strings[6].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Strings[7].Operand) -Child ([string]$Strings[8].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ShortcutPath = [string]$Shortcut.Value
        if ([IO.Path]::GetExtension($ShortcutPath) -notin '.lnk', '.pif') { $ShortcutPath += '.lnk' }
        $Calls.Add([pscustomobject][ordered]@{
            Route = 'Direct'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
            ShortcutPath = $ShortcutPath; TargetPath = $Target.Value; Arguments = $Arguments.Value
            Comment = $Comment.Value; Icon = $Icon.Value; WorkingDirectory = $WorkingDirectory.Value
            ShowCommand = [uint32]$Integers[0].Operand; ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Shortcut.UnresolvedMacros + $Target.UnresolvedMacros + $Arguments.UnresolvedMacros + $Comment.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros + $Icon.UnresolvedMacros | Sort-Object -Unique)
          })
        continue
      }
      if (-not $ListTargets.Contains($TargetId)) { continue }

      # shlist receives one g_list offset. Each row is ten NUL-terminated UTF-8 fields; the final
      # field is retained by the project format but ignored by the source runtime.
      $Start = [Math]::Max(0, $CommandIndex - 16)
      $OffsetCommands = @($Commands[$Start..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($OffsetCommands.Count -eq 0) { continue }
      $ListOffset = [uint32]$OffsetCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 10) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.ListMalformed' -Source CreateInstall -Message "A compiled CreateInstall shortcut list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Metadata -Evidence @{ CallerId = $Function.Record.Id; Offset = $ListOffset }))
        continue
      }
      foreach ($Row in $Rows) {
        $ConditionExpression = [string]$Row.Fields[8]
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Shortcut = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[0]) -Child ([string]$Row.Fields[1]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Target = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[2]) -Child ([string]$Row.Fields[3]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[4]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Icon = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[5]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[6]) -Child ([string]$Row.Fields[7]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ShortcutPath = [string]$Shortcut.Value
        if ([IO.Path]::GetExtension($ShortcutPath) -notin '.lnk', '.pif') { $ShortcutPath += '.lnk' }
        $Calls.Add([pscustomobject][ordered]@{
            Route = 'List'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset; ListOffset = $ListOffset; RowIndex = $Row.Index
            ShortcutPath = $ShortcutPath; TargetPath = $Target.Value; Arguments = $Arguments.Value
            Comment = ''; ConfiguredComment = [string]$Row.Fields[9]; Icon = $Icon.Value; WorkingDirectory = $WorkingDirectory.Value
            ShowCommand = [uint32]1; ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Shortcut.UnresolvedMacros + $Target.UnresolvedMacros + $Arguments.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros + $Icon.UnresolvedMacros | Sort-Object -Unique)
          })
      }
    }
  }
  $Conditional = @($Calls | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall shortcut operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata -Evidence $Conditional)) }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallRunEvidence {
  <#
  .SYNOPSIS
    Recover direct CreateInstall Run operations and their nested command lines.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve deterministic paths and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  # Both source routines have six parameters and publish runret/runok. The MSI route is separated
  # by its complete msiexec command template; link-time IDs and function names are not stable.
  $DirectTargets = [Collections.Generic.HashSet[uint32]]::new()
  $MsiTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object {
        $_.ParameterCount -eq 6 -and $_.LiteralText.Contains('runret', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('runok', [StringComparison]::Ordinal) -and
        -not $_.LiteralText.Contains('wscript.exe', [StringComparison]::OrdinalIgnoreCase) -and -not $_.LiteralText.Contains('cscript.exe', [StringComparison]::OrdinalIgnoreCase)
      })) {
    if ($Function.LiteralText.Contains('msiexec.exe', [StringComparison]::OrdinalIgnoreCase)) { $null = $MsiTargets.Add([uint32]$Function.Record.Id) } else { $null = $DirectTargets.Add([uint32]$Function.Record.Id) }
  }
  if ($DirectTargets.Count -eq 0 -and $MsiTargets.Count -eq 0) { return [pscustomobject]@{ Calls = @(); Diagnostics = @() } }
  $Calls = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()

  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($CommandIndex -eq 0) { continue }
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      $Segment = @($Commands[[Math]::Max(0, $CommandIndex - 96)..($CommandIndex - 1)])
      if ($DirectTargets.Contains($TargetId)) {
        $Strings = @($Segment | Where-Object Command -EQ 34 | Select-Object -Last 6)
        $Integers = @($Segment | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 2)
        if ($Strings.Count -ne 6 -or $Integers.Count -ne 2) { continue }
        $ConditionExpression = [string]$Strings[5].Operand
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Executable = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Strings[2].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Strings[3].Operand) -Child ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Calls.Add([pscustomobject][ordered]@{
            Kind = 'Executable'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
            Executable = $Executable.Value; Arguments = $Arguments.Value; WorkingDirectory = $WorkingDirectory.Value
            Wait = [bool][uint32]$Integers[0].Operand; RunAs = [uint32]$Integers[1].Operand
            ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Executable.UnresolvedMacros + $Arguments.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros | Sort-Object -Unique)
          })
        continue
      }
      if (-not $MsiTargets.Contains($TargetId)) { continue }

      # runmsiex is generated from path/name, five flag inputs, wait, condition, log, and UI mode.
      # The compiler may fold the flag OR expression, so all numeric literals between the MSI name
      # and condition are ORed except the final wait value.
      $Strings = @($Segment | Where-Object Command -EQ 34 | Select-Object -Last 5)
      if ($Strings.Count -ne 5 -or $Strings[1].Index + 1 -gt $Strings[2].Index - 1) { continue }
      $FlagCommands = @($Commands[($Strings[1].Index + 1)..($Strings[2].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($FlagCommands.Count -lt 2) { continue }
      $Wait = [uint32]$FlagCommands[-1].Operand
      $Flags = [uint32]0
      foreach ($FlagCommand in $FlagCommands[0..($FlagCommands.Count - 2)]) { $Flags = $Flags -bor [uint32]$FlagCommand.Operand }
      if (($Flags -band 0xFFFFFFE0) -ne 0 -or $Wait -notin 0, 1) { continue }
      $ConditionExpression = [string]$Strings[2].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Payload = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Log = Resolve-CreateInstallMacroValue -Value ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Interface = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $MsiAction = if (($Flags -band 0x10) -ne 0) { 'Uninstall' } elseif (($Flags -band 0x01) -ne 0) { 'AdministrativeInstall' } else { 'Install' }
      $ArgumentParts = [Collections.Generic.List[string]]::new()
      if (-not [string]::IsNullOrWhiteSpace([string]$Log.Value)) { $ArgumentParts.Add('/l*'); $ArgumentParts.Add('"' + ([string]$Log.Value).Trim('"') + '"') }
      $ArgumentParts.Add($(if ($MsiAction -eq 'Uninstall') { '/x' } elseif ($MsiAction -eq 'AdministrativeInstall') { '/a' } else { '/i' }))
      $ArgumentParts.Add('"' + ([string]$Payload.Value).Trim('"') + '"')
      if (($Flags -band 0x02) -ne 0) { $ArgumentParts.Add('/quiet') }
      if (($Flags -band 0x04) -ne 0) { $ArgumentParts.Add('/passive') }
      if (($Flags -band 0x08) -ne 0) { $ArgumentParts.Add('/norestart') }
      if (-not [string]::IsNullOrWhiteSpace([string]$Interface.Value)) { $ArgumentParts.Add(([string]$Interface.Value).Trim()) }
      $Calls.Add([pscustomobject][ordered]@{
          Kind = 'Msi'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
          Executable = '%WINDIR%\System32\msiexec.exe'; Arguments = $ArgumentParts -join ' '; WorkingDirectory = $null
          NestedInstallerPath = $Payload.Value; MsiAction = $MsiAction; MsiFlags = $Flags; MsiInterface = $Interface.Value; LogPath = $Log.Value
          Wait = [bool]$Wait; RunAs = $null; ConditionExpression = $ConditionExpression; Condition = $Condition
          UnresolvedMacros = [string[]]@($Payload.UnresolvedMacros + $Log.UnresolvedMacros + $Interface.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }
  $Conditional = @($Calls | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Run.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall child-process operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Installability -Evidence $Conditional)) }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallExtensionEvidence {
  <#
  .SYNOPSIS
    Recover literal file-association calls emitted by CreateInstall's Extension command.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Is32Bit
    Indicates that deterministic folder macros use the 32-bit Windows view.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  # extension() is identified by the complete group of class-registration strings in the
  # source-backed implementation. Link-time object IDs vary between generated installers.
  $Candidates = @($Program.Records | Where-Object Type -EQ 3 | Where-Object {
      $Text = [Text.Encoding]::ASCII.GetString($Program.Bytes, $_.PayloadOffset, $_.EndOffset - $_.PayloadOffset)
      $Text.Contains('AlwaysShowExt', [StringComparison]::Ordinal) -and
      $Text.Contains('EditFlags', [StringComparison]::Ordinal) -and
      $Text.Contains('UserChoice', [StringComparison]::Ordinal) -and
      $Text.Contains('DefaultIcon', [StringComparison]::Ordinal)
    })
  if ($Candidates.Count -eq 0) { return [pscustomobject]@{ Calls = @(); RegistryWrites = @(); Diagnostics = @() } }
  if ($Candidates.Count -ne 1) { throw 'The compiled CreateInstall program contains multiple candidate Extension routines' }

  $Calls = [System.Collections.Generic.List[object]]::new()
  $RegistryWrites = [System.Collections.Generic.List[object]]::new()
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $Candidates[0].Id -or $CommandIndex -eq 0) { continue }
      $Window = @($Commands[([Math]::Max(0, $CommandIndex - 64))..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 4)
      if ($StringCommands.Count -ne 4) { continue }
      if ($StringCommands[-1].Index + 1 -gt $CommandIndex - 1) { continue }
      $OffsetCommands = @($Commands[($StringCommands[-1].Index + 1)..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($OffsetCommands.Count -eq 0) { continue }
      $ListOffset = [uint32]$OffsetCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 2) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ListMalformed' -Source CreateInstall -Message "A compiled CreateInstall file-association list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Offset = $ListOffset }))
        continue
      }
      $Variables = [ordered]@{}
      foreach ($Entry in $ProjectVariableEvidence.Variables.GetEnumerator()) { $Variables[$Entry.Key] = $Entry.Value }
      foreach ($Row in $Rows) {
        $Name = [string]$Row.Fields[0]
        if (-not [string]::IsNullOrWhiteSpace($Name) -and -not $Name.Contains(':', [StringComparison]::Ordinal)) { $Variables[$Name] = [string]$Row.Fields[1] }
      }
      $Condition = Resolve-CreateInstallCondition -Expression ([string]$Variables['extif']) -Variables $Variables
      if ($Condition -eq $false) { continue }
      if ($null -eq $Condition) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ConditionDynamic' -Source CreateInstall -Message 'A CreateInstall file association depends on a runtime condition and is retained as conditional evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Expression = [string]$Variables['extif'] }))
      }

      $ExtensionName = ([string]$StringCommands[0].Operand).Trim().TrimStart('.')
      if ($ExtensionName -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ExtensionDynamic' -Source CreateInstall -Message "CreateInstall's Extension command has a non-literal extension '$ExtensionName'." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id }))
        continue
      }
      $ApplicationResult = Join-CreateInstallMacroPath -Parent ([string]$StringCommands[1].Operand) -Child ([string]$StringCommands[2].Operand) -Variables $Variables -Is32Bit $Is32Bit
      if ($ApplicationResult.UnresolvedMacros.Count -gt 0 -or [string]::IsNullOrWhiteSpace([string]$ApplicationResult.Value)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.CommandDynamic' -Source CreateInstall -Message "CreateInstall's '.$ExtensionName' association has an unresolved application command." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Macros = $ApplicationResult.UnresolvedMacros }))
        continue
      }
      $ApplicationPath = [string]$ApplicationResult.Value
      $Parameters = [string]$StringCommands[3].Operand
      if ([string]::IsNullOrWhiteSpace($Parameters)) { $Parameters = '"%1"' }
      $ProgId = [string]$Variables['extfile']
      if ([string]::IsNullOrWhiteSpace($ProgId)) { $ProgId = $ExtensionName + 'file' }
      $Description = [string]$Variables['extdesc']
      if ([string]::IsNullOrWhiteSpace($Description)) { $Description = $ExtensionName.ToUpperInvariant() + ' file' }
      $IconResult = Resolve-CreateInstallMacroValue -Value ([string]$Variables['exticon']) -Variables $Variables -Is32Bit $Is32Bit
      $Icon = if ([string]::IsNullOrWhiteSpace([string]$IconResult.Value)) { $ApplicationPath } elseif ($IconResult.UnresolvedMacros.Count -eq 0) { [string]$IconResult.Value } else { $null }
      $ExtensionKey = ".$ExtensionName"
      $OpenCommand = '"' + $ApplicationPath.Trim('"') + '" ' + $Parameters
      $Evidence = "Gentee extension call in object $($Record.Id)"
      foreach ($Write in @(
          @{ Root = 'HKCR'; Key = $ExtensionKey; Name = ''; Value = $ProgId; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = "$ProgId\DefaultIcon"; Name = ''; Value = $Icon; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = "$ProgId\Shell\Open\command"; Name = ''; Value = $OpenCommand; Type = 'REG_SZ' },
          @{ Root = 'HKCU'; Key = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ExtensionKey\UserChoice"; Name = 'Progid'; Value = $ProgId; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = ''; Value = $Description; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = 'AlwaysShowExt'; Value = ''; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = 'EditFlags'; Value = '00000000'; Type = 'REG_BINARY' }
        )) {
        if ($null -ne $Write.Value) { $RegistryWrites.Add([pscustomobject]@{ Root = $Write.Root; RegistryView = $Is32Bit ? '32-bit' : '64-bit'; Key = $Write.Key; Name = $Write.Name; Value = $Write.Value; Type = $Write.Type; Evidence = $Evidence }) }
      }
      $Calls.Add([pscustomobject]@{ CallerId = $Record.Id; CallOffset = $Commands[$CommandIndex].Offset; Extension = $ExtensionKey; ProgId = $ProgId; Application = $ApplicationPath; Parameters = $Parameters; Description = $Description; DefaultIcon = $Icon; ConditionExpression = [string]$Variables['extif']; Condition = $Condition; ListOffset = $ListOffset })
    }
  }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); RegistryWrites = $RegistryWrites.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallInstallFileEvidence {
  <#
  .SYNOPSIS
    Map GEA file groups to their compiled CreateInstall destination paths.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Layout
    Validated GEA archive layout whose group identifiers are projected.
  .PARAMETER Is32Bit
    Indicates that deterministic folder macros use the 32-bit Windows view.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  # Link-time object IDs and function names are unstable. Recover unpackgroup by its five-argument
  # signature and its call to a three-argument unpackfile routine; unpackgroupex is the six-argument
  # wrapper that calls that recovered group routine. The generated project may call either route.
  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $GroupRoutines = @($Functions.Values | Where-Object {
      $_.ParameterCount -eq 5 -and $_.Record.Size -lt 512 -and @($_.Commands | Where-Object { $Functions.ContainsKey([uint32]$_.Command) -and $Functions[[uint32]$_.Command].ParameterCount -eq 3 }).Count -gt 0
    })
  $ExtendedRoutines = @($Functions.Values | Where-Object {
      $_.ParameterCount -eq 6 -and @($_.Commands | Where-Object { $Target = [uint32]$_.Command; $GroupRoutines.Record.Id -contains $Target }).Count -gt 0
    })
  $ProjectCalls = [System.Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values) {
    foreach ($Command in $Function.Commands) { if ($Functions.ContainsKey([uint32]$Command.Command)) { $null = $ProjectCalls.Add([uint32]$Command.Command) } }
  }
  $RouteCandidates = @($ExtendedRoutines | Where-Object { $ProjectCalls.Contains([uint32]$_.Record.Id) })
  $RouteId = 'Extended6'
  if ($RouteCandidates.Count -eq 0) {
    $RouteCandidates = @($GroupRoutines | Where-Object { $ProjectCalls.Contains([uint32]$_.Record.Id) })
    $RouteId = 'Direct5'
  }
  if ($RouteCandidates.Count -eq 0) { return [pscustomobject]@{ RouteId = $null; Calls = @(); InstalledFiles = @(); Diagnostics = @() } }
  if ($RouteCandidates.Count -ne 1) { throw 'The compiled CreateInstall program contains multiple candidate install-group routines' }
  $TargetId = [uint32]$RouteCandidates[0].Record.Id

  $Calls = [System.Collections.Generic.List[object]]::new()
  $InstalledFiles = [System.Collections.Generic.List[object]]::new()
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  $DynamicConditions = [System.Collections.Generic.List[object]]::new()
  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    $PreviousCallIndex = -1
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $TargetId) { continue }
      $SegmentStart = $PreviousCallIndex + 1
      $PreviousCallIndex = $CommandIndex
      if ($SegmentStart -ge $CommandIndex) { continue }
      $Window = @($Commands[$SegmentStart..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 4)
      if ($StringCommands.Count -ne 4) { continue }
      if ($SegmentStart -gt $StringCommands[0].Index - 1 -or $StringCommands[1].Index + 1 -gt $StringCommands[2].Index - 1) { continue }
      $BeforeDestination = @($Commands[$SegmentStart..($StringCommands[0].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      $BeforeCondition = @($Commands[($StringCommands[1].Index + 1)..($StringCommands[2].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($BeforeDestination.Count -eq 0 -or $BeforeCondition.Count -eq 0) { continue }
      $GroupId = [uint32]$BeforeDestination[-1].Operand
      if ($GroupId -ne 0xFFFF -and -not ($Layout.Entries.GroupId -contains $GroupId)) { continue }
      $OverwriteMode = [uint32]$BeforeCondition[-1].Operand
      $ListOffset = $null
      $Options = @()
      if ($RouteId -eq 'Extended6') {
        if ($StringCommands[3].Index + 1 -gt $CommandIndex - 1) { continue }
        $AfterWildcard = @($Commands[($StringCommands[3].Index + 1)..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
        if ($AfterWildcard.Count -eq 0) { continue }
        $ListOffset = [uint32]$AfterWildcard[-1].Operand
        if ($ListOffset -ne [uint32]::MaxValue) {
          try { $Options = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 4) } catch {
            $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroup.OptionsMalformed' -Source CreateInstall -Message "A compiled CreateInstall install-group option list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Extraction -Evidence @{ CallerId = $Function.Record.Id; Offset = $ListOffset }))
            continue
          }
        }
      }

      $DestinationExpression = if ([string]::IsNullOrWhiteSpace([string]$StringCommands[0].Operand)) {
        [string]$StringCommands[1].Operand
      } elseif ([string]::IsNullOrWhiteSpace([string]$StringCommands[1].Operand)) {
        [string]$StringCommands[0].Operand
      } else {
        ([string]$StringCommands[0].Operand).TrimEnd([char[]]'\/') + '\' + ([string]$StringCommands[1].Operand).TrimStart([char[]]'\/')
      }
      if ($DestinationExpression.StartsWith('*', [StringComparison]::Ordinal)) { continue }
      $Destination = Resolve-CreateInstallMacroValue -Value $DestinationExpression -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $ConditionExpression = [string]$StringCommands[2].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      if ($null -eq $Condition) {
        $DynamicConditions.Add([pscustomobject]@{ CallerId = $Function.Record.Id; GroupId = $GroupId; Expression = $ConditionExpression })
      }
      $Wildcard = [string]$StringCommands[3].Operand
      $MatchedEntries = @($Layout.Entries | Where-Object {
          ($GroupId -eq 0xFFFF -or $_.GroupId -eq $GroupId) -and ([string]::IsNullOrWhiteSpace($Wildcard) -or $_.Name -like $Wildcard)
        })
      $Calls.Add([pscustomobject]@{ CallerId = $Function.Record.Id; CallOffset = $Commands[$CommandIndex].Offset; GroupId = $GroupId; DestinationExpression = $DestinationExpression; Destination = $Destination.Value; UnresolvedMacros = $Destination.UnresolvedMacros; OverwriteMode = $OverwriteMode; ConditionExpression = $ConditionExpression; Condition = $Condition; Wildcard = $Wildcard; ListOffset = $ListOffset; Options = $Options })
      foreach ($Entry in $MatchedEntries) {
        $RelativeName = if ([string]::IsNullOrWhiteSpace([string]$Entry.Folder)) { $Entry.Name } else { ([string]$Entry.Folder).TrimEnd([char[]]'\/') + '\' + $Entry.Name }
        $InstalledPath = if ($Destination.UnresolvedMacros.Count -eq 0) { ([string]$Destination.Value).TrimEnd([char[]]'\/') + '\' + $RelativeName.TrimStart([char[]]'\/') } else { $null }
        $InstalledFiles.Add([pscustomobject]@{ ArchiveIndex = $Entry.Index; ArchivePath = $Entry.FullName; GroupId = $Entry.GroupId; InstalledPath = $InstalledPath; Destination = $Destination.Value; Size = $Entry.Size; Crc32 = $Entry.Crc32; IsConditional = $null -eq $Condition; ConditionExpression = $ConditionExpression; OverwriteMode = $OverwriteMode })
      }
    }
  }
  if ($DynamicConditions.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroup.ConditionDynamic' -Source CreateInstall -Message "$($DynamicConditions.Count) CreateInstall install group(s) depend on runtime conditions; their files are retained as conditional evidence." -Kind Ambiguous -Areas Extraction, Installability -Evidence $DynamicConditions.ToArray()))
  }
  return [pscustomobject]@{ RouteId = $RouteId; RoutineId = $TargetId; Calls = $Calls.ToArray(); InstalledFiles = $InstalledFiles.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallRegistryEvidence {
  <#
  .SYNOPSIS
    Recover literal Registry command lists compiled through regsetsex.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Is32Bit
    Indicates the default registry view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $RootNames = @{
    ([uint32]2147483648) = 'HKCR'
    ([uint32]2147483649) = 'HKCU'
    ([uint32]2147483650) = 'HKLM'
    ([uint32]2147483651) = 'HKU'
    ([uint32]2147483653) = 'HKCC'
  }
  $TypeNames = @('REG_DWORD', 'REG_SZ', 'REG_BINARY', 'REG_MULTI_SZ', 'REG_EXPAND_SZ')
  $FunctionParameters = [System.Collections.Generic.Dictionary[uint32, uint32]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) { $FunctionParameters[[uint32]$Record.Id] = Get-CreateInstallGenteeParameterCount -Program $Program -Record $Record }
  $Calls = [System.Collections.Generic.List[object]]::new()
  $Writes = [System.Collections.Generic.List[object]]::new()
  $ConditionalWrites = [System.Collections.Generic.List[object]]::new()
  $DynamicConditions = [System.Collections.Generic.List[object]]::new()

  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    $PreviousTargetIndex = @{}
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      if (-not $FunctionParameters.ContainsKey($TargetId) -or $FunctionParameters[$TargetId] -ne 5) { continue }
      $TargetRecord = $Program.Records | Where-Object Id -EQ $TargetId | Select-Object -First 1
      if ($null -eq $TargetRecord -or $TargetRecord.Size -ge 128) { continue }
      # regsetsex is a small five-argument condition wrapper over regsets. Calls serialize one
      # root constant, one subkey string, list offset, WOW64 flag, and one outer condition string.
      $Start = $PreviousTargetIndex.ContainsKey($TargetId) ? ([int]$PreviousTargetIndex[$TargetId] + 1) : [Math]::Max(0, $CommandIndex - 48)
      $PreviousTargetIndex[$TargetId] = $CommandIndex
      if ($Start -ge $CommandIndex) { continue }
      $Window = @($Commands[$Start..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 2)
      if ($StringCommands.Count -ne 2) { continue }
      if ($Start -gt $StringCommands[0].Index - 1 -or $StringCommands[0].Index + 1 -gt $StringCommands[1].Index - 1) { continue }
      $RootCommands = @($Commands[$Start..($StringCommands[0].Index - 1)] | Where-Object { $_.Command -in @(27, 30) -and $RootNames.ContainsKey([uint32]$_.Operand) })
      $ListCommands = @($Commands[($StringCommands[0].Index + 1)..($StringCommands[1].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($RootCommands.Count -eq 0 -or $ListCommands.Count -lt 2) { continue }
      $RootValue = [uint32]$RootCommands[-1].Operand
      $ListOffset = [uint32]$ListCommands[-2].Operand
      $Wow64 = [bool][uint32]$ListCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 5) } catch { continue }
      if ($Rows.Count -eq 0 -or @($Rows | Where-Object { [string]$_.Fields[1] -notmatch '^[0-4]$' }).Count -gt 0) { continue }

      $Subkey = Resolve-CreateInstallMacroValue -Value ([string]$StringCommands[0].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $OuterExpression = [string]$StringCommands[1].Operand
      $OuterCondition = Resolve-CreateInstallCondition -Expression $OuterExpression -Variables $ProjectVariableEvidence.Variables
      $Call = [pscustomobject]@{ CallerId = $Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset; Root = $RootNames[$RootValue]; SubkeyExpression = [string]$StringCommands[0].Operand; Subkey = $Subkey.Value; UnresolvedMacros = $Subkey.UnresolvedMacros; ListOffset = $ListOffset; RegistryView = $Wow64 ? '64-bit' : ($Is32Bit ? '32-bit' : '64-bit'); ConditionExpression = $OuterExpression; Condition = $OuterCondition; ValueCount = $Rows.Count }
      $Calls.Add($Call)
      foreach ($Row in $Rows) {
        $RowExpression = [string]$Row.Fields[3]
        $RowCondition = Resolve-CreateInstallCondition -Expression $RowExpression -Variables $ProjectVariableEvidence.Variables
        if ($OuterCondition -eq $false -or $RowCondition -eq $false) { continue }
        $IsConditional = $null -eq $OuterCondition -or $null -eq $RowCondition -or $Subkey.UnresolvedMacros.Count -gt 0
        $NameResult = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[0]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ValueResult = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[2]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        if ($NameResult.UnresolvedMacros.Count -gt 0 -or $ValueResult.UnresolvedMacros.Count -gt 0) { $IsConditional = $true }
        $TypeCode = [int]$Row.Fields[1]
        $Value = switch ($TypeCode) {
          0 { $Number = 0L; [void][long]::TryParse([string]$ValueResult.Value, [ref]$Number); [uint32]($Number -band [uint32]::MaxValue); break }
          3 { [string[]]@(([string]$ValueResult.Value) -split '\|'); break }
          default { [string]$ValueResult.Value }
        }
        $Write = [pscustomobject]@{ Root = $RootNames[$RootValue]; RegistryView = $Call.RegistryView; Key = [string]$Subkey.Value; Name = [string]$NameResult.Value; Value = $Value; Type = $TypeNames[$TypeCode]; Evidence = "Gentee regsetsex call in object $($Record.Id)"; IsConditional = $IsConditional; ConditionExpression = @($OuterExpression, $RowExpression) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } }
        if ($IsConditional) {
          $ConditionalWrites.Add($Write)
          $DynamicConditions.Add([pscustomobject]@{ CallerId = $Record.Id; Root = $Write.Root; Key = $Write.Key; Name = $Write.Name; Conditions = $Write.ConditionExpression; UnresolvedMacros = @($Subkey.UnresolvedMacros + $NameResult.UnresolvedMacros + $ValueResult.UnresolvedMacros) })
        } else { $Writes.Add($Write) }
      }
    }
  }

  $Diagnostics = @(
    if ($DynamicConditions.Count) { New-InstallerDiagnostic -Id 'CreateInstall.Registry.Conditional' -Source CreateInstall -Message "$($DynamicConditions.Count) CreateInstall registry value(s) depend on runtime conditions or macros and are retained separately from deterministic registry writes." -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'Protocols', 'FileExtensions') -Evidence $DynamicConditions.ToArray() }
  )
  return [pscustomobject]@{ Calls = $Calls.ToArray(); RegistryWrites = $Writes.ToArray(); ConditionalRegistryWrites = $ConditionalWrites.ToArray(); Diagnostics = $Diagnostics }
}

function Get-CreateInstallArpEvidence {
  <#
  .SYNOPSIS
    Reconstruct visible and hidden uninstall entries from deterministic registry writes.
  .PARAMETER RegistryWrite
    Built-in and custom CreateInstall registry writes in execution order.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Entries = [System.Collections.Generic.List[object]]::new()
  $VisibleEntries = [System.Collections.Generic.List[object]]::new()
  $AppsAndFeaturesEntries = [System.Collections.Generic.List[object]]::new()
  $ProductCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Scopes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $HiddenCodes = [System.Collections.Generic.List[string]]::new()
  $UninstallKeyPattern = '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<Code>[^\\]+)$'
  $Groups = @($RegistryWrite | Where-Object { -not $_.IsConditional -and $_.Key -match $UninstallKeyPattern } | Group-Object Root, RegistryView, Key)
  foreach ($Group in $Groups) {
    $First = $Group.Group[0]
    $Code = [regex]::Match([string]$First.Key, $UninstallKeyPattern).Groups['Code'].Value
    $Values = [ordered]@{}
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    $SystemComponent = 0L
    if ($Values.Contains('SystemComponent')) { [void][long]::TryParse([string]$Values['SystemComponent'], [ref]$SystemComponent) }
    $Visible = $SystemComponent -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$Values['DisplayName'])
    $Entry = [pscustomobject][ordered]@{
      ProductCode          = $Code
      DisplayName          = $Values['DisplayName']
      DisplayVersion       = $Values['DisplayVersion']
      Publisher            = $Values['Publisher']
      InstallLocation      = $Values['InstallLocation']
      UninstallString      = $Values['UninstallString']
      QuietUninstallString = $Values['QuietUninstallString']
      DisplayIcon          = $Values['DisplayIcon']
      URLInfoAbout         = $Values['URLInfoAbout']
      HelpLink             = $Values['HelpLink']
      SystemComponent      = $SystemComponent
      IsVisible            = $Visible
      RegistryRoot         = $First.Root
      RegistryView         = $First.RegistryView
      RegistryKey          = $First.Key
      Values               = $Values
      Evidence             = [string[]]@($Group.Group.Evidence | Where-Object { $_ } | Select-Object -Unique)
    }
    $Entries.Add($Entry)
    if (-not $Visible) { $HiddenCodes.Add($Code); continue }
    $VisibleEntries.Add($Entry)
    $null = $ProductCodes.Add($Code)
    switch ($First.Root) {
      'HKCU' { $null = $Scopes.Add('user') }
      'HKLM' { $null = $Scopes.Add('machine') }
      'SHCTX' { $null = $Scopes.Add('user'); $null = $Scopes.Add('machine') }
    }
    $ManifestEntry = [ordered]@{ ProductCode = $Code }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if (-not [string]::IsNullOrWhiteSpace([string]$Entry.$Name)) { $ManifestEntry[$Name] = $Entry.$Name }
    }
    $ManifestEntry['InstallerType'] = 'exe'
    $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
  }
  $Diagnostics = @(
    if ($HiddenCodes.Count) { New-InstallerDiagnostic -Id 'CreateInstall.ARP.Hidden' -Source CreateInstall -Message "$($HiddenCodes.Count) CreateInstall uninstall key(s) are hidden or lack DisplayName and are excluded from visible Apps & Features evidence." -Kind Information -Areas Metadata -AffectedFields AppsAndFeaturesEntries -Evidence @($HiddenCodes) }
  )
  return [pscustomobject]@{ Entries = $Entries.ToArray(); VisibleEntries = $VisibleEntries.ToArray(); AppsAndFeaturesEntries = $AppsAndFeaturesEntries.ToArray(); ProductCodes = [string[]]@($ProductCodes); Scopes = [string[]]@($Scopes); Diagnostics = $Diagnostics }
}

function Get-CreateInstallUninstallEvidence {
  <#
  .SYNOPSIS
    Resolve source-verified CreateInstall Add/Remove calls from compiled GE bytecode.
  .PARAMETER Path
    Path to a CreateInstall setup executable. The file is opened read-only and never executed.
  .PARAMETER Program
    Previously decoded GE program. Supplying it avoids reopening and decoding the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Program')][psobject]$Program
  )

  if ($PSCmdlet.ParameterSetName -eq 'Path') { $Program = Get-CreateInstallGenteeProgram -Path $Path }
  $UninstallPath = [Text.Encoding]::ASCII.GetBytes('Software\Microsoft\Windows\CurrentVersion\Uninstall\')
  $PathRoutines = @($Program.Records | Where-Object Type -EQ 3 | Where-Object {
      @(Find-BinaryPattern -Bytes $Program.Bytes -Pattern $UninstallPath -StartOffset $_.PayloadOffset -Length ($_.EndOffset - $_.PayloadOffset) -Maximum 1).Count -eq 1
    })

  # The built-in routine evolved independently of the GEA archive version. Select the most
  # specific source-backed signature rather than guessing from PE ProductVersion.
  $AddRemoveProfile = $null
  $CandidateRoutine = $null
  foreach ($CatalogProfile in $Script:CreateInstallFormatCatalog.AddRemoveProfiles) {
    $ProfileRoutines = @($PathRoutines | Where-Object {
        $RecordText = [Text.Encoding]::ASCII.GetString($Program.Bytes, $_.PayloadOffset, $_.EndOffset - $_.PayloadOffset)
        foreach ($ValueName in $CatalogProfile.RequiredValueNames) {
          if (-not $RecordText.Contains([string]$ValueName, [StringComparison]::Ordinal)) { return $false }
        }
        foreach ($ValueName in @($CatalogProfile.ForbiddenValueNames)) {
          if ($RecordText.Contains([string]$ValueName, [StringComparison]::Ordinal)) { return $false }
        }
        return $true
      })
    if ($ProfileRoutines.Count -gt 1) { throw "The compiled CreateInstall program contains multiple '$($CatalogProfile.Id)' Add/Remove routines" }
    if ($ProfileRoutines.Count -eq 1) {
      $AddRemoveProfile = $CatalogProfile
      $CandidateRoutine = $ProfileRoutines[0]
      break
    }
  }
  if ($null -eq $CandidateRoutine) {
    # Dead-code elimination removes the complete addremove family when the project disables its
    # Add/Remove Programs command. Absence of the source-identifying registry path is therefore a
    # valid no-built-in-ARP state; an unrecognized routine that still contains that path is not.
    if ($PathRoutines.Count -gt 0) { throw 'The compiled CreateInstall program contains an unsupported built-in Add/Remove routine' }
    return [pscustomobject]@{
      Calls       = @()
      ProgramInfo = [pscustomobject]@{
        LauncherOffset = $Program.LauncherOffset; SectionOffset = $Program.SectionOffset; RuntimeSize = $Program.RuntimeSize
        StoredProgramSize = $Program.StoredProgramSize; ProgramSize = $Program.ProgramSize; Packed = $Program.Packed
        VersionMajor = $Program.VersionMajor; VersionMinor = $Program.VersionMinor; ProgramProfile = $Program.ProgramProfile
        ObjectCount = $Program.Records.Count; AddRemoveProfile = $null; AddRemoveRoutine = $null; AddRemoveRoutineId = $null
      }
    }
  }

  $Calls = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $CandidateRoutine.Id -or $CommandIndex -eq 0) { continue }

      # Generated project code places literal string arguments immediately before a direct call.
      # Legacy addremove has three strings, addremoveex adds the current-user Boolean, and
      # addremoveext appends a fourth estimated-size string after that Boolean.
      $StringCommands = @($Commands[([Math]::Max(0, $CommandIndex - 64))..($CommandIndex - 1)] | Where-Object Command -EQ 34 | Select-Object -Last ([int]$AddRemoveProfile.StringArgumentCount))
      if ($StringCommands.Count -ne [int]$AddRemoveProfile.StringArgumentCount) { continue }
      $ForCurrentUser = $false
      if ($AddRemoveProfile.HasCurrentUserArgument) {
        $BooleanStart = $StringCommands[2].Index + 1
        $BooleanEnd = if ($AddRemoveProfile.HasEstimatedSizeArgument) { $StringCommands[3].Index - 1 } else { $CommandIndex - 1 }
        if ($BooleanStart -gt $BooleanEnd) { continue }
        $CurrentUserCommands = @($Commands[$BooleanStart..$BooleanEnd] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -in @(0, 1) })
        if ($CurrentUserCommands.Count -eq 0) { continue }
        $ForCurrentUser = [bool]$CurrentUserCommands[-1].Operand
      }
      $Calls.Add([pscustomobject]@{
          ProfileId             = [string]$AddRemoveProfile.Id
          Routine               = [string]$AddRemoveProfile.Routine
          RoutineId             = [uint32]$CandidateRoutine.Id
          CallerId              = [uint32]$Record.Id
          CallerName            = $Record.Name
          CallOffset            = [int]$Commands[$CommandIndex].Offset
          UninstallKeyName      = [string]$StringCommands[0].Operand
          IconPath              = [string]$StringCommands[1].Operand
          IconFile              = [string]$StringCommands[2].Operand
          ForCurrentUser        = $ForCurrentUser
          EstimatedSizeText     = if ($AddRemoveProfile.HasEstimatedSizeArgument) { [string]$StringCommands[3].Operand } else { $null }
          WritesInstallLocation = [bool]$AddRemoveProfile.WritesInstallLocation
          WritesNoModify        = [bool]$AddRemoveProfile.WritesNoModify
          WritesNoRepair        = [bool]$AddRemoveProfile.WritesNoRepair
          WritesEstimatedSize   = [bool]$AddRemoveProfile.WritesEstimatedSize
        })
    }
  }
  return [pscustomobject]@{
    Calls       = $Calls.ToArray()
    ProgramInfo = [pscustomobject]@{
      LauncherOffset     = $Program.LauncherOffset
      SectionOffset      = $Program.SectionOffset
      RuntimeSize        = $Program.RuntimeSize
      StoredProgramSize  = $Program.StoredProgramSize
      ProgramSize        = $Program.ProgramSize
      Packed             = $Program.Packed
      VersionMajor       = $Program.VersionMajor
      VersionMinor       = $Program.VersionMinor
      ProgramProfile     = $Program.ProgramProfile
      ObjectCount        = $Program.Records.Count
      AddRemoveProfile   = [string]$AddRemoveProfile.Id
      AddRemoveRoutine   = [string]$AddRemoveProfile.Routine
      AddRemoveRoutineId = [uint32]$CandidateRoutine.Id
    }
  }
}

function Read-CreateInstallNullTerminatedString {
  <#
  .SYNOPSIS
    Read one bounded UTF-8 null-terminated string from a byte array
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset,
    [ValidateRange(1, 1048576)][int]$MaximumBytes = 65536
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { throw 'The GEA string offset is outside the metadata table' }
  $End = [Array]::IndexOf($Bytes, [byte]0, $Offset, [Math]::Min($MaximumBytes, $Bytes.Length - $Offset))
  if ($End -lt 0) { throw 'The GEA metadata contains an unterminated string' }
  [pscustomobject]@{ Value = [Text.Encoding]::UTF8.GetString($Bytes, $Offset, $End - $Offset); NextOffset = $End + 1 }
}

function Read-CreateInstallArchiveLogicalRange {
  <#
  .SYNOPSIS
    Read a logical GEA data range across normal and moved data regions
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Count
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER Stream
    Optional caller-owned seekable installer stream. Its position is restored by bounded reads and
    the helper never disposes it. When omitted, this function opens and closes the layout path.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count,
    [AllowNull()][System.IO.Stream]$Stream
  )

  if ($Offset -lt 0 -or $Offset + $Count -gt $Layout.SummarySize) { throw 'The requested GEA logical range is outside the compressed data stream' }
  # GEA exposes one logical compressed stream even though moved bytes are physically stored before
  # ordinary data. Translate each requested slice without joining the complete archive in memory.
  $Result = [byte[]]::new($Count)
  if ($Count -eq 0) { return , $Result }
  $OwnedStream = $null
  if ($null -eq $Stream) {
    $OwnedStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $Stream = $OwnedStream
  }
  try {
    $Remaining = $Count
    $LogicalOffset = $Offset
    $DestinationOffset = 0
    while ($Remaining -gt 0) {
      if ($LogicalOffset -lt $Layout.OrdinaryDataLength) {
        # Logical data starts in the ordinary region and wraps into the moved prefix at its end.
        $Available = $Layout.OrdinaryDataLength - $LogicalOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $Layout.MovedSize + $LogicalOffset
      } else {
        $MovedOffset = $LogicalOffset - $Layout.OrdinaryDataLength
        $Available = $Layout.MovedSize - $MovedOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $MovedOffset
      }
      $ReadCount = [int][Math]::Min($Remaining, $Available)
      if ($ReadCount -le 0) { throw 'The GEA logical range crosses an unavailable volume' }
      $Chunk = Read-BinaryBytes -Stream $Stream -Offset $PhysicalOffset -Count $ReadCount
      [Array]::Copy($Chunk, 0, $Result, $DestinationOffset, $ReadCount)
      $Remaining -= $ReadCount
      $DestinationOffset += $ReadCount
      $LogicalOffset += $ReadCount
    }
  } finally { if ($OwnedStream) { $OwnedStream.Dispose() } }
  return , $Result
}

function ConvertFrom-CreateInstallFileTable {
  <#
  .SYNOPSIS
    Parse packed GEA v1/v2 file descriptors from an expanded metadata table
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER MajorVersion
    Detected format variant controlling version-specific parsing rules.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateSet(1, 2)][int]$MajorVersion
  )

  $Offset = 0
  $LogicalOffset = 0L
  $CurrentAttribute = 0
  $CurrentGroup = 0
  $CurrentPassword = 0
  $CurrentFolder = ''
  $Entries = [System.Collections.Generic.List[object]]::new()
  # Descriptor flags make several fields stateful: omitted attributes, groups, passwords, and
  # folders inherit the most recently declared value.
  while ($Offset -lt $Bytes.Length) {
    if ($Entries.Count -ge $Script:CreateInstallMaximumEntries) { throw 'The GEA metadata exceeds the configured entry-count limit' }
    $BaseSize = if ($MajorVersion -ge 2) { 30 } else { 22 }
    if ($Offset + $BaseSize -gt $Bytes.Length) { throw 'The GEA file descriptor table is truncated' }
    $Flags = [BitConverter]::ToUInt16($Bytes, $Offset); $Offset += 2
    $FileTime = [BitConverter]::ToInt64($Bytes, $Offset); $Offset += 8
    # GEA v2 widens both file sizes to 64 bits; the surrounding descriptor remains the same.
    if ($MajorVersion -ge 2) {
      $Size = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
      $CompressedSize = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
    } else {
      $Size = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
      $CompressedSize = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    }
    $Crc32 = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    $VersionHigh = $null; $VersionLow = $null
    if (($Flags -band $Script:CreateInstallFileFlagAttribute) -ne 0) { $CurrentAttribute = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagVersion) -ne 0) { $VersionHigh = [BitConverter]::ToUInt32($Bytes, $Offset); $VersionLow = [BitConverter]::ToUInt32($Bytes, $Offset + 4); $Offset += 8 }
    if (($Flags -band $Script:CreateInstallFileFlagGroup) -ne 0) { $CurrentGroup = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagProtect) -ne 0) { $CurrentPassword = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    $NameData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $Name = $NameData.Value; $Offset = $NameData.NextOffset
    if (($Flags -band $Script:CreateInstallFileFlagFolder) -ne 0) { $FolderData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $CurrentFolder = $FolderData.Value; $Offset = $FolderData.NextOffset }
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'The GEA metadata contains an empty file name' }
    $RelativePath = if ($CurrentFolder) { Join-Path $CurrentFolder $Name } else { $Name }
    # DataOffset is in the logical compressed stream, not an absolute file position.
    $Entries.Add([pscustomobject]@{
        Index          = $Entries.Count
        Flags          = [uint16]$Flags
        FileTime       = [long]$FileTime
        Size           = [uint64]$Size
        CompressedSize = [uint64]$CompressedSize
        Crc32          = [uint32]$Crc32
        Attributes     = [uint32]$CurrentAttribute
        VersionHigh    = $VersionHigh
        VersionLow     = $VersionLow
        GroupId        = [uint32]$CurrentGroup
        PasswordId     = [uint32]$CurrentPassword
        IsSolid        = ($Flags -band $Script:CreateInstallFileFlagSolid) -ne 0
        Name           = $Name
        Folder         = $CurrentFolder
        FullName       = $RelativePath
        DataOffset     = [long]$LogicalOffset
      })
    $LogicalOffset += [long]$CompressedSize
  }
  return $Entries.ToArray()
}

function Get-CreateInstallArchiveLayout {
  <#
  .SYNOPSIS
    Locate and parse the self-extracting CreateInstall GEA archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  Import-CreateInstallLzgeDecoder
  $Signature = [byte[]](0x47, 0x45, 0x41, 0x00)
  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # SETUP_TEMP is stored as a standalone GEA resource inside CreateInstall's PE. Reuse this
    # layout parser for that bounded resource by recognizing GEA at offset zero; ordinary setup
    # executables continue scanning only after their validated PE image.
    $Prefix = if ($Stream.Length -ge $Signature.Length) { Read-BinaryBytes -Stream $Stream -Offset 0 -Count $Signature.Length } else { [byte[]]::new(0) }
    $OverlayOffset = if ($Prefix.Length -eq $Signature.Length -and (Test-BinarySequence -Left $Prefix -Right $Signature)) { 0L } else { Get-PEOverlayOffset -Stream $Stream }
  } finally { $Stream.Dispose() }
  # Search only after the PE image and validate every GEA candidate through its complete size map;
  # compiled signature strings in the setup stub are not archive evidence.
  foreach ($ArchiveOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Maximum 16)) {
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if ($ArchiveOffset + 73 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count 73
      $VolumeNumber = [BitConverter]::ToUInt16($Header, 4)
      $UniqueId = [BitConverter]::ToUInt32($Header, 6)
      $MajorVersion = $Header[10]
      $MinorVersion = $Header[11]
      $ArchiveProfile = @($Script:CreateInstallFormatCatalog.ArchiveProfiles | Where-Object { [int]$_.MajorVersion -eq [int]$MajorVersion })
      if ($VolumeNumber -ne 0 -or $ArchiveProfile.Count -ne 1) { continue }
      $Flags = [BitConverter]::ToUInt32($Header, 20)
      $VolumeCount = [BitConverter]::ToUInt16($Header, 24)
      $HeaderSize = [BitConverter]::ToUInt32($Header, 26)
      $SummarySize = [BitConverter]::ToInt64($Header, 30)
      $InfoSize = [BitConverter]::ToUInt32($Header, 38)
      $ArchiveFileSize = [BitConverter]::ToInt64($Header, 42)
      $VolumeSize = [BitConverter]::ToInt64($Header, 50)
      $LastVolumeSize = [BitConverter]::ToInt64($Header, 58)
      $MovedSize = [BitConverter]::ToUInt32($Header, 66)
      $Memory = $Header[70]
      $BlockMultiplier = $Header[71]
      $SolidMultiplier = $Header[72]
      # Dumplings supports self-contained single-volume SFX archives only. Multi-volume patterns
      # are reported by rejection rather than followed outside the installer.
      if ($VolumeCount -ne 1 -or $HeaderSize -lt 74 -or $HeaderSize -gt $Script:CreateInstallMaximumHeaderBytes -or $InfoSize -gt $Script:CreateInstallMaximumInfoBytes) { continue }
      if ($ArchiveFileSize -le $ArchiveOffset -or $ArchiveFileSize -gt $File.Length -or $HeaderSize -gt $ArchiveFileSize - $ArchiveOffset) { continue }
      if ($SummarySize -lt 0 -or $MovedSize -gt $SummarySize) { continue }
      $OrdinaryDataLength = $ArchiveFileSize - $MovedSize - $HeaderSize - $ArchiveOffset
      if ($OrdinaryDataLength -lt 0 -or $OrdinaryDataLength + $MovedSize -ne $SummarySize) { continue }

      # Variable header data starts with the volume pattern, then optional password IDs, then the
      # compressed or stored file descriptor table.
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count ([int]$HeaderSize)
      $PatternData = Read-CreateInstallNullTerminatedString -Bytes $HeaderBytes -Offset 73
      $MetadataOffset = $PatternData.NextOffset
      if (($Flags -band $Script:CreateInstallFlagPassword) -ne 0) {
        if ($MetadataOffset + 2 -gt $HeaderBytes.Length) { continue }
        $PasswordCount = [BitConverter]::ToUInt16($HeaderBytes, $MetadataOffset)
        $MetadataOffset += 2 + ($PasswordCount * 4)
      } else { $PasswordCount = 0 }
      if ($MetadataOffset -gt $HeaderBytes.Length) { continue }
      if (($Flags -band $Script:CreateInstallFlagCompressedInfo) -ne 0) {
        $CompressedInfo = [byte[]]::new($HeaderBytes.Length - $MetadataOffset)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $CompressedInfo, 0, $CompressedInfo.Length)
        $Metadata = [Dumplings.Gentee.LzgeDecoder]::Decode($CompressedInfo, [int]$InfoSize)
      } else {
        if ($MetadataOffset + $InfoSize -gt $HeaderBytes.Length) { continue }
        $Metadata = [byte[]]::new([int]$InfoSize)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $Metadata, 0, [int]$InfoSize)
      }
      # Require the catalog's final logical data extent to equal SummarySize before accepting the
      # candidate archive.
      $Entries = @(ConvertFrom-CreateInstallFileTable -Bytes $Metadata -MajorVersion $MajorVersion)
      if ($Entries.Count -eq 0 -or ($Entries[-1].DataOffset + [long]$Entries[-1].CompressedSize) -ne $SummarySize) { continue }
      return [pscustomobject]@{
        Path               = $File.FullName
        ArchiveOffset      = [long]$ArchiveOffset
        UniqueId           = [uint32]$UniqueId
        MajorVersion       = [byte]$MajorVersion
        MinorVersion       = [byte]$MinorVersion
        ArchiveProfile     = [string]$ArchiveProfile[0].Id
        Flags              = [uint32]$Flags
        VolumeCount        = [uint16]$VolumeCount
        HeaderSize         = [long]$HeaderSize
        SummarySize        = [long]$SummarySize
        InfoSize           = [long]$InfoSize
        ArchiveFileSize    = [long]$ArchiveFileSize
        VolumeSize         = [long]$VolumeSize
        LastVolumeSize     = [long]$LastVolumeSize
        MovedSize          = [long]$MovedSize
        OrdinaryDataLength = [long]$OrdinaryDataLength
        PasswordCount      = [int]$PasswordCount
        MemoryMegabytes    = [int]$Memory
        BlockSize          = [long]$BlockMultiplier * 0x40000
        SolidSize          = [long]$SolidMultiplier * 0x40000
        VolumePattern      = $PatternData.Value
        Entries            = $Entries
      }
    } catch {
      # A structurally invalid candidate may be payload data containing GEA\0; continue scanning.
      continue
    } finally { $Stream.Dispose() }
  }
  throw 'The PE overlay does not contain a supported CreateInstall GEA archive'
}

function Get-CreateInstallBlockInfo {
  <#
  .SYNOPSIS
    Enumerate compression block headers for one GEA file entry
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Stream
    Optional caller-owned stream reused for block-header reads.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][psobject]$Entry, [AllowNull()][System.IO.Stream]$Stream)

  $LogicalOffset = [long]$Entry.DataOffset
  $CompressedRemaining = [long]$Entry.CompressedSize
  $OutputRemaining = [long]$Entry.Size
  $HeaderSize = if ($Layout.MajorVersion -ge 2) { 9 } else { 5 }
  # Walk each entry's complete block stream and verify that compressed and expanded totals converge
  # exactly at the declared file boundaries.
  while ($OutputRemaining -gt 0) {
    if ($CompressedRemaining -lt $HeaderSize) { throw "The GEA data for '$($Entry.FullName)' is truncated" }
    $Header = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $LogicalOffset -Count $HeaderSize -Stream $Stream
    $RawOrder = $Header[0]
    $StoredOrder = $RawOrder -band 0x7F
    $CompressedSize = if ($Layout.MajorVersion -ge 2) { [uint64][BitConverter]::ToUInt64($Header, 1) } else { [uint64][BitConverter]::ToUInt32($Header, 1) }
    if ($CompressedSize -gt [long]::MaxValue -or $CompressedSize -gt $CompressedRemaining - $HeaderSize) { throw "The GEA block for '$($Entry.FullName)' exceeds its file data range" }
    # The high nibble selects Store/LZGE/PPMd; the low nibble carries the compression-order mode.
    $CompressionType = $StoredOrder -shr 4
    $CompressionOrder = ($StoredOrder -band 0x0F) + 1
    $OutputSize = if ($CompressionType -eq 0) { [long]$CompressedSize } else { [Math]::Min([long]$Layout.BlockSize, $OutputRemaining) }
    if ($OutputSize -le 0 -or $OutputSize -gt $OutputRemaining) { throw "The GEA block for '$($Entry.FullName)' has an invalid output size" }
    [pscustomobject]@{
      RawOrder         = [byte]$RawOrder
      CompressionType  = [int]$CompressionType
      CompressionName  = switch ($CompressionType) { 0 { 'Store' } 1 { 'LZGE' } 2 { 'PPMd' } default { 'Unknown' } }
      CompressionOrder = [int]$CompressionOrder
      HeaderOffset     = [long]$LogicalOffset
      DataOffset       = [long]($LogicalOffset + $HeaderSize)
      CompressedSize   = [long]$CompressedSize
      OutputSize       = [long]$OutputSize
    }
    $LogicalOffset += $HeaderSize + [long]$CompressedSize
    $CompressedRemaining -= $HeaderSize + [long]$CompressedSize
    $OutputRemaining -= $OutputSize
  }
  if ($CompressedRemaining -ne 0) { throw "The GEA file '$($Entry.FullName)' has trailing compressed data" }
}

function Export-CreateInstallArchiveSelection {
  <#
  .SYNOPSIS
    Expand selected entries from an already parsed CreateInstall archive layout.
  .PARAMETER Layout
    Validated layout returned by Get-CreateInstallArchiveLayout. The source file is not reparsed.
  .PARAMETER DestinationPath
    Resolved extraction root beneath which archive-relative paths are written.
  .PARAMETER Name
    One or more exact names or wildcard patterns. An entry is selected when any pattern matches.
  .PARAMETER CollisionAction
    Behavior applied only when a selected output path collides.
  .PARAMETER MaximumExpandedBytes
    Maximum total expanded size of selected output files.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Name,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  Import-CreateInstallLzgeDecoder
  if ($Layout.PasswordCount -gt 0) { throw 'Password-protected CreateInstall GEA archives are intentionally unsupported' }
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  $SolidHistory = [byte[]]::new(0)
  $PpmdDecoder = $null
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  # Resolve all output paths before decoding. Solid compression requires walking every physical
  # entry through the last selected index even when only a small analysis subset is written.
  $SelectedEntries = [bool[]]::new($Layout.Entries.Count)
  $OutputTargets = [object[]]::new($Layout.Entries.Count)
  $FirstSelectedIndex = -1
  $LastSelectedIndex = -1
  for ($EntryIndex = 0; $EntryIndex -lt $Layout.Entries.Count; $EntryIndex++) {
    $EntryMatches = $false
    foreach ($Pattern in $Name) {
      if (Test-ExtractionPattern -Path $Layout.Entries[$EntryIndex].FullName -Pattern $Pattern) { $EntryMatches = $true; break }
    }
    if (-not $EntryMatches) { continue }
    $SelectedEntries[$EntryIndex] = $true
    $OutputTargets[$EntryIndex] = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Layout.Entries[$EntryIndex].FullName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if ($FirstSelectedIndex -lt 0) { $FirstSelectedIndex = $EntryIndex }
    $LastSelectedIndex = $EntryIndex
  }
  if ($LastSelectedIndex -lt 0) { throw "No CreateInstall files matched '$($Name -join ', ')'" }

  $SourceStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # A solid entry only depends on the nearest preceding model reset, not the archive beginning.
    # Walk backward to a non-solid entry, stored block, or explicit compression order and start
    # there. Old builder archives otherwise decode hundreds of unrelated files for one selection.
    $FirstDecodeIndex = 0
    for ($EntryIndex = $FirstSelectedIndex; $EntryIndex -ge 0; $EntryIndex--) {
      $FirstBlock = @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Layout.Entries[$EntryIndex] -Stream $SourceStream)[0]
      if (-not $Layout.Entries[$EntryIndex].IsSolid -or $FirstBlock.CompressionType -eq 0 -or $FirstBlock.CompressionOrder -gt 1) { $FirstDecodeIndex = $EntryIndex; break }
    }
    for ($EntryIndex = $FirstDecodeIndex; $EntryIndex -le $LastSelectedIndex; $EntryIndex++) {
      $Entry = $Layout.Entries[$EntryIndex]
      if ($Entry.PasswordId -gt 0) { throw "The CreateInstall entry '$($Entry.FullName)' is password-protected and cannot be extracted" }
      if (-not $Entry.IsSolid) { $SolidHistory = [byte[]]::new(0) }
      $Selected = $SelectedEntries[$EntryIndex] -and $OutputTargets[$EntryIndex].ShouldWrite
      $OutputPath = $null
      if ($Selected) {
        $ExpandedBytes += [long]$Entry.Size
        if ($ExpandedBytes -gt $MaximumExpandedBytes) { throw 'CreateInstall extraction exceeds the configured output limit' }
        $OutputPath = $OutputTargets[$EntryIndex].Path
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      } else { $Output = $null }
      try {
        foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry -Stream $SourceStream)) {
          if ($Block.CompressedSize -gt $Script:CreateInstallMaximumBlockBytes -or $Block.OutputSize -gt $Script:CreateInstallMaximumBlockBytes) { throw "The CreateInstall block for '$($Entry.FullName)' exceeds the configured block limit" }
          $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize) -Stream $SourceStream
          switch ($Block.CompressionType) {
            0 { $Decoded = $InputBytes; $SolidHistory = [byte[]]::new(0) }
            1 {
              $Prefix = if ($Block.CompressionOrder -eq 1) { $SolidHistory } else { [byte[]]::new(0) }
              $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($InputBytes, [int]$Block.OutputSize, $Prefix)
              $Combined = if ($Prefix.Length -gt 0) { $Prefix + $Decoded } else { $Decoded }
              $Keep = [int][Math]::Min($Layout.SolidSize, $Combined.Length)
              $SolidHistory = [byte[]]::new($Keep)
              if ($Keep -gt 0) { [Array]::Copy($Combined, $Combined.Length - $Keep, $SolidHistory, 0, $Keep) }
            }
            2 {
              if (-not $PpmdDecoder) {
                if ($Layout.MemoryMegabytes -le 0) { throw 'The GEA header declares no PPMd model memory' }
                Import-CreateInstallPpmdDecoder
                $PpmdDecoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new([int]([uint32]$Layout.MemoryMegabytes * 1MB))
              }
              $InputStream = [IO.MemoryStream]::new($InputBytes, $false)
              try { $Decoded = $PpmdDecoder.DecodeBlock($InputStream, $InputBytes.Length, [int]$Block.OutputSize, $Block.CompressionOrder) } finally { $InputStream.Dispose() }
              $SolidHistory = [byte[]]::new(0)
            }
            default { throw "The CreateInstall entry '$($Entry.FullName)' uses an unknown compression method" }
          }
          if ($Output) { $Output.Write($Decoded, 0, $Decoded.Length) }
        }
      } catch {
        if ($Output) { $Output.Dispose(); $Output = $null }
        if ($OutputPath) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }
        throw
      } finally { if ($Output) { $Output.Dispose() } }
      if (-not $Selected) { continue }
      $OutputFile = Get-Item -LiteralPath $OutputPath -Force
      if ($OutputFile.Length -ne [long]$Entry.Size) {
        Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
        throw "The extracted CreateInstall file '$($Entry.FullName)' has an unexpected length"
      }
      $GenteeCrc32 = [uint32]((Get-BinaryCrc32 -Path $OutputFile.FullName -MaximumBytes $MaximumExpandedBytes) -bxor [uint32]::MaxValue)
      if ($GenteeCrc32 -ne [uint32]$Entry.Crc32) {
        Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
        throw "The extracted CreateInstall file '$($Entry.FullName)' failed its GEA CRC32 check"
      }
      $Result.Add($OutputFile)
    }
  } finally {
    if ($PpmdDecoder) { $PpmdDecoder.Dispose() }
    $SourceStream.Dispose()
  }
  return $Result.ToArray()
}

function Get-CreateInstallPayloadAnalysis {
  <#
  .SYNOPSIS
    Analyze source-proven installed application executables and bounded adjacent sidecars.
  .PARAMETER Layout
    Validated GEA layout reused for selected extraction.
  .PARAMETER InstalledFile
    Installed-file projection returned by Get-CreateInstallInstallFileEvidence.
  .PARAMETER ApplicationPath
    Application paths referenced by compiled file-association commands.
  .PARAMETER DefaultInstallLocation
    Resolved package install root used only for the unambiguous executable fallback.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][object[]]$InstalledFile,
    [AllowNull()][string[]]$ApplicationPath,
    [AllowNull()][string]$DefaultInstallLocation
  )

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Installed = @($InstalledFile | Where-Object { $_.InstalledPath -and -not $_.IsConditional })
  $Primary = @($Installed | Where-Object { $_.InstalledPath -in @($ApplicationPath | Where-Object { $_ }) } | Sort-Object ArchiveIndex -Unique)
  if ($Primary.Count -eq 0 -and $DefaultInstallLocation) {
    $Fallback = @($Installed | Where-Object { $_.InstalledPath -match '(?i)\.exe$' -and [IO.Path]::GetDirectoryName([string]$_.InstalledPath) -ieq $DefaultInstallLocation -and [IO.Path]::GetFileName([string]$_.InstalledPath) -notmatch '^(?:uninstall|update)\.exe$' })
    if ($Fallback.Count -eq 1) { $Primary = $Fallback }
  }
  if ($Primary.Count -eq 0) {
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = $null; InspectedFiles = @(); Diagnostics = @() }
  }

  # Limit primary applications and related files independently of the archive's total size. This
  # keeps metadata parsing bounded for SDKs and other packages containing many executable tools.
  $Primary = @($Primary | Select-Object -First 4)
  $Selected = [Collections.Generic.List[object]]::new()
  $SelectedIndexes = [Collections.Generic.HashSet[int]]::new()
  $AnalysisBytes = 0L
  foreach ($Item in $Primary) {
    if ($AnalysisBytes + [long]$Item.Size -gt $Script:CreateInstallMaximumAnalysisBytes) { continue }
    if ($SelectedIndexes.Add([int]$Item.ArchiveIndex)) { $Selected.Add($Item); $AnalysisBytes += [long]$Item.Size }
    $Directory = [IO.Path]::GetDirectoryName([string]$Item.InstalledPath)
    foreach ($Related in @($Installed | Where-Object { $_.ArchiveIndex -ne $Item.ArchiveIndex -and [IO.Path]::GetDirectoryName([string]$_.InstalledPath) -ieq $Directory -and $_.InstalledPath -match '(?i)\.(?:dll|deps\.json|runtimeconfig\.json)$' } | Select-Object -First 64)) {
      if ($AnalysisBytes + [long]$Related.Size -gt $Script:CreateInstallMaximumAnalysisBytes) { break }
      if ($SelectedIndexes.Add([int]$Related.ArchiveIndex)) { $Selected.Add($Related); $AnalysisBytes += [long]$Related.Size }
    }
  }
  if ($Selected.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.AnalysisLimit' -Source CreateInstall -Message 'Source-proven CreateInstall application payloads exceed the bounded static-analysis limit.' -Kind Unsupported -Areas Metadata -AffectedFields @('Architecture', 'Dependencies')))
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = $null; InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  }

  $TemporaryDirectory = New-TempFolder
  try {
    $Patterns = [string[]]@($Selected | Sort-Object ArchiveIndex | Select-Object -ExpandProperty ArchivePath -Unique)
    $Files = @(Export-CreateInstallArchiveSelection -Layout $Layout -DestinationPath $TemporaryDirectory -Name $Patterns -CollisionAction Rename -MaximumExpandedBytes $Script:CreateInstallMaximumAnalysisBytes)
    $ArchitectureInfo = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Primary) {
      # Match the exact archive-relative extraction path. Basename matching can select the wrong
      # executable when a package installs identically named files in several directories.
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Item.ArchivePath)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -ne 1) { continue }
      $RelatedFiles = @($Files | Where-Object { $_.FullName -cne $PrimaryFile[0].FullName })
      try { $ArchitectureInfo.Add((Get-PEArchitectureInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Where-Object Extension -IEQ '.dll' | Select-Object -ExpandProperty FullName))) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.ArchitectureUnavailable' -Source CreateInstall -Message "CreateInstall payload architecture analysis failed for '$($Item.ArchivePath)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
      }
    }
    $DependencyInfo = $null
    if ($Primary.Count -eq 1 -and $Files.Count -gt 0) {
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Primary[0].ArchivePath)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -eq 1) {
        try { $DependencyInfo = Get-PEDependencyInfo -Path $PrimaryFile[0].FullName -RelatedFile @($Files | Where-Object FullName -NE $PrimaryFile[0].FullName | Select-Object -ExpandProperty FullName) } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.DependenciesUnavailable' -Source CreateInstall -Message "CreateInstall payload dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
        }
      }
    }
    # Aggregate child parser diagnostics explicitly. Accessing a property through a null scalar or
    # a generic list is fragile under StrictMode and can hide otherwise valid payload evidence.
    foreach ($ArchitectureResult in $ArchitectureInfo) {
      foreach ($Diagnostic in @($ArchitectureResult.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    if ($null -ne $DependencyInfo) {
      foreach ($Diagnostic in @($DependencyInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    return [pscustomobject]@{
      ArchitectureInfo = $ArchitectureInfo.ToArray()
      Architectures    = [string[]]@($ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
      DependencyInfo   = $DependencyInfo
      InspectedFiles   = [string[]]@($Selected | Select-Object -ExpandProperty InstalledPath)
      Diagnostics      = $Diagnostics.ToArray()
    }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-CreateInstallInfo {
  <#
  .SYNOPSIS
    Read static CreateInstall identity and GEA payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    # Test fixtures may expose a standalone GEA payload behind a synthetic prefix. Real installers
    # provide PE architecture evidence; retaining the null case keeps archive inspection usable.
    try { $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $File.FullName } catch { $OuterArchitectureInfo = $null }
    $Is32Bit = $null -eq $OuterArchitectureInfo -or $OuterArchitectureInfo.NativeArchitecture -eq 'x86'
    $CompressionMethods = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $UnresolvedFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $RegistryWrites = [System.Collections.Generic.List[object]]::new()
    # Decode the GE program once. MAINVAR contains the exact generated project values consumed by
    # common_init; direct addremove* calls identify which of those values become visible ARP state.
    $Program = $null
    $ProjectVariableEvidence = $null
    $UninstallEvidence = $null
    $ExtensionEvidence = $null
    $InstallFileEvidence = $null
    $CustomRegistryEvidence = $null
    $PayloadAnalysis = $null
    $ShortcutEvidence = $null
    $RunEvidence = $null
    try { $Program = Get-CreateInstallGenteeProgram -Path $File.FullName } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Program.Unavailable' -Source CreateInstall -Message "The compiled CreateInstall project program could not be decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'DefaultInstallLocation', 'AppsAndFeaturesEntries')))
    }
    $Layout = $null
    $LayoutError = $null
    try { $Layout = Get-CreateInstallArchiveLayout -Path $File.FullName } catch { $LayoutError = $_ }
    if ($null -eq $Program -and $null -eq $Layout) { throw $LayoutError }
    if ($null -eq $Layout) {
      # CreateInstall permits projects without packaged files. Their compiled program remains fully
      # analyzable, but extraction and installed-file projection have no GEA source.
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Archive.Absent' -Source CreateInstall -Message 'The CreateInstall project contains no GEA payload archive.' -Kind Information -Areas Extraction))
    } else {
      # Enumerate block headers without expanding payloads so capability warnings remain inexpensive.
      $ArchiveStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        foreach ($Entry in $Layout.Entries) { foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry -Stream $ArchiveStream)) { $null = $CompressionMethods.Add($Block.CompressionName) } }
      } finally { $ArchiveStream.Dispose() }
    }
    if ($null -ne $Program) {
      try { $ProjectVariableEvidence = Get-CreateInstallProjectVariableEvidence -Program $Program } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ProjectVariables.Incomplete' -Source CreateInstall -Message "The compiled CreateInstall project variables could not be parsed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('DisplayName', 'DisplayVersion', 'Publisher', 'DefaultInstallLocation')))
      }
      try { $UninstallEvidence = Get-CreateInstallUninstallEvidence -Program $Program } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Incomplete' -Source CreateInstall -Message "The compiled CreateInstall Add/Remove routine could not be parsed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
      }
      if ($null -ne $ProjectVariableEvidence) {
        try { $ExtensionEvidence = Get-CreateInstallExtensionEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall file associations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions))
        }
        if ($null -ne $Layout) {
          try { $InstallFileEvidence = Get-CreateInstallInstallFileEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Layout $Layout -Is32Bit $Is32Bit } catch {
            $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroups.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall install groups could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Extraction -AffectedFields Architecture))
          }
        }
        try { $CustomRegistryEvidence = Get-CreateInstallRegistryEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Registry.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall registry operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions')))
        }
        try { $ShortcutEvidence = Get-CreateInstallShortcutEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall shortcut operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata))
        }
        try { $RunEvidence = Get-CreateInstallRunEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Run.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall child-process operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Installability))
        }
      }
    }
    $ProjectVariables = if ($null -ne $ProjectVariableEvidence) { $ProjectVariableEvidence.Variables } else { [ordered]@{} }
    $ResolveProjectVariable = {
      param([string]$Name)
      if (-not $ProjectVariables.Contains($Name)) { return $null }
      return Resolve-CreateInstallMacroValue -Value ([string]$ProjectVariables[$Name]) -Variables $ProjectVariables -Is32Bit $Is32Bit
    }
    $GetResolvedValue = {
      param([string]$Name, [string]$Fallback)
      $Resolved = & $ResolveProjectVariable $Name
      if ($null -ne $Resolved -and $Resolved.UnresolvedMacros.Count -eq 0) { return ([string]$Resolved.Value).Trim() }
      return $Fallback
    }
    $ProductName = & $GetResolvedValue 'progname' ([string]$VersionInfo.ProductName).Trim()
    $DisplayVersion = & $GetResolvedValue 'ver' ([string]$VersionInfo.ProductVersion).Trim()
    $Publisher = & $GetResolvedValue 'compname' ([string]$VersionInfo.CompanyName).Trim()
    $InstallLocationName = $ProjectVariables.Contains('instlocation') ? 'instlocation' : 'setuppath'
    $InstallLocationResult = & $ResolveProjectVariable $InstallLocationName
    $DefaultInstallLocation = if ($null -ne $InstallLocationResult -and $InstallLocationResult.UnresolvedMacros.Count -eq 0) { ([string]$InstallLocationResult.Value).TrimEnd([char]'\') } else { $null }
    if ($null -ne $InstallLocationResult -and $InstallLocationResult.UnresolvedMacros.Count -gt 0) {
      $null = $UnresolvedFields.Add('DefaultInstallLocation')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallLocation.Dynamic' -Source CreateInstall -Message "CreateInstall's installation path depends on unresolved runtime macro(s): $($InstallLocationResult.UnresolvedMacros -join ', ')." -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation -Evidence @{ Expression = [string]$ProjectVariables[$InstallLocationName]; Macros = $InstallLocationResult.UnresolvedMacros }))
    }
    $SilentResult = & $ResolveProjectVariable 'silentpar'
    $SilentSwitch = if ($null -ne $SilentResult -and $SilentResult.UnresolvedMacros.Count -eq 0) { ([string]$SilentResult.Value).Trim() } else { $null }

    if ($null -ne $InstallFileEvidence -and $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('Unknown')) {
      try {
        $PayloadAnalysis = Get-CreateInstallPayloadAnalysis -Layout $Layout -InstalledFile $InstallFileEvidence.InstalledFiles -ApplicationPath @($ExtensionEvidence.Calls.Application) -DefaultInstallLocation $DefaultInstallLocation
        foreach ($Diagnostic in $PayloadAnalysis.Diagnostics) { $Diagnostics.Add($Diagnostic) }
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.AnalysisFailed' -Source CreateInstall -Message "CreateInstall selected-payload analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('Architecture', 'Dependencies')))
      }
    }

    $UninstallCalls = if ($null -ne $UninstallEvidence) { @($UninstallEvidence.Calls) } else { @() }
    foreach ($Call in $UninstallCalls) {
      $UninstallKeyResult = Resolve-CreateInstallMacroValue -Value ([string]$Call.UninstallKeyName) -Variables $ProjectVariables -Is32Bit $Is32Bit
      $UninstallKeyName = ([string]$UninstallKeyResult.Value).Trim()
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName)) { $UninstallKeyName = $ProductName }
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.NameEmpty' -Source CreateInstall -Message 'CreateInstall invokes its Add/Remove command but the resolved program name is empty.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
        continue
      }
      if ($UninstallKeyResult.UnresolvedMacros.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.NameDynamic' -Source CreateInstall -Message "CreateInstall's uninstall key depends on unresolved runtime macro(s): $($UninstallKeyResult.UnresolvedMacros -join ', ')." -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence @{ Expression = $Call.UninstallKeyName; Macros = $UninstallKeyResult.UnresolvedMacros }))
        continue
      }
      $Root = if ($Call.ForCurrentUser) { 'HKCU' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'HKLM' } else { 'SHCTX' }
      $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKeyName"
      $CallEvidence = "Gentee $($Call.Routine) call"
      $RegistryView = $Is32Bit ? '32-bit' : '64-bit'
      $UninstallPathResult = & $ResolveProjectVariable 'uninstexe'
      $UninstallString = if ($null -ne $UninstallPathResult -and $UninstallPathResult.UnresolvedMacros.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$UninstallPathResult.Value)) {
        $ExpandedUninstaller = [string]$UninstallPathResult.Value
        $ExpandedUninstaller.StartsWith('"', [StringComparison]::Ordinal) ? $ExpandedUninstaller : '"' + $ExpandedUninstaller + '"'
      } else { $null }
      $DisplayIconResult = if ([string]::IsNullOrWhiteSpace([string]$Call.IconFile)) {
        $UninstallPathResult
      } else {
        Join-CreateInstallMacroPath -Parent ([string]$Call.IconPath) -Child ([string]$Call.IconFile) -Variables $ProjectVariables -Is32Bit $Is32Bit
      }
      $DisplayIcon = if ($null -ne $DisplayIconResult -and $DisplayIconResult.UnresolvedMacros.Count -eq 0) { ([string]$DisplayIconResult.Value).Trim() } else { $null }
      $HelpLink = & $GetResolvedValue 'supurl' $null
      $HelpTelephone = & $GetResolvedValue 'phone' $null
      $UrlInfoAbout = & $GetResolvedValue 'produrl' $null
      $UrlUpdateInfo = & $GetResolvedValue 'updurl' $null
      $EstimatedSize = $null
      if ($Call.WritesEstimatedSize -and $Call.EstimatedSizeText -match '^\d+$') {
        $EstimatedSize = if ([uint64]$Call.EstimatedSizeText -eq 1 -and $null -ne $Layout) {
          [uint32]((($Layout.Entries | Measure-Object -Property Size -Sum).Sum -shr 10) -band [uint32]::MaxValue)
        } elseif ([uint64]$Call.EstimatedSizeText -ne 1) { [uint32]([uint64]$Call.EstimatedSizeText -band [uint32]::MaxValue) }
      }

      # addremoveext iterates this exact source-defined value list. Emit only non-empty macro
      # values, then append the generation-specific DWORD policy values.
      foreach ($Value in @(
          @{ Name = 'UninstallString'; Value = $UninstallString },
          @{ Name = 'DisplayName'; Value = $UninstallKeyName },
          @{ Name = 'DisplayIcon'; Value = $DisplayIcon },
          @{ Name = 'DisplayVersion'; Value = $DisplayVersion },
          @{ Name = 'HelpLink'; Value = $HelpLink },
          @{ Name = 'HelpTelephone'; Value = $HelpTelephone },
          @{ Name = 'InstallLocation'; Value = $Call.WritesInstallLocation ? $DefaultInstallLocation : $null },
          @{ Name = 'Publisher'; Value = $Publisher },
          @{ Name = 'URLInfoAbout'; Value = $UrlInfoAbout },
          @{ Name = 'URLUpdateInfo'; Value = $UrlUpdateInfo }
        )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Value.Value)) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = $Value.Name; Value = $Value.Value; Type = 'REG_SZ'; Evidence = $CallEvidence }) }
      }
      if ($null -ne $EstimatedSize -and $EstimatedSize -gt 0) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'EstimatedSize'; Value = $EstimatedSize; Type = 'REG_DWORD'; Evidence = $CallEvidence }) }
      if ($Call.WritesNoModify) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'NoModify'; Value = 1; Type = 'REG_DWORD'; Evidence = "$CallEvidence implementation" }) }
      if ($Call.WritesNoRepair) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'NoRepair'; Value = 1; Type = 'REG_DWORD'; Evidence = "$CallEvidence implementation" }) }
    }

    if ($null -ne $ExtensionEvidence) {
      foreach ($Write in $ExtensionEvidence.RegistryWrites) { $RegistryWrites.Add($Write) }
      foreach ($Diagnostic in $ExtensionEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    }
    if ($null -ne $InstallFileEvidence) { foreach ($Diagnostic in $InstallFileEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ShortcutEvidence) { foreach ($Diagnostic in $ShortcutEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $RunEvidence) { foreach ($Diagnostic in $RunEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $CustomRegistryEvidence) {
      # Custom registry commands execute after the generated setup body and therefore override
      # built-in ARP values when both address the same uninstall key and value name.
      foreach ($Write in $CustomRegistryEvidence.RegistryWrites) { $RegistryWrites.Add($Write) }
      foreach ($Diagnostic in $CustomRegistryEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    }

    # Preserve every condition that the bounded evaluator could not decide. Each record includes
    # the guarded operation, known project values, and a compact bytecode view for @function
    # predicates so callers can inspect the evidence without reparsing the GE program.
    $GenteeExpressions = [Collections.Generic.List[object]]::new()
    if ($null -ne $Program -and $null -ne $ProjectVariableEvidence) {
      $AddGenteeExpression = {
        param ([string]$Operation, [object]$Item, [string[]]$AffectedFields, [object]$Context, [AllowNull()][string]$Expression)
        if (($Item.PSObject.Properties['Condition'] -and $null -ne $Item.Condition) -or [string]::IsNullOrWhiteSpace($Expression)) { return }
        $ExpressionArguments = @{
          Program        = $Program
          Variables      = $ProjectVariables
          Is32Bit        = $Is32Bit
          Operation      = $Operation
          Expression     = $Expression
          AffectedFields = $AffectedFields
          Context        = $Context
        }
        if ($Item.PSObject.Properties['CallerId'] -and $null -ne $Item.CallerId) { $ExpressionArguments['CallerId'] = [uint32]$Item.CallerId }
        if ($Item.PSObject.Properties['CallOffset'] -and $null -ne $Item.CallOffset) { $ExpressionArguments['CallOffset'] = [int]$Item.CallOffset }
        $null = $GenteeExpressions.Add((Get-CreateInstallGenteeExpressionEvidence @ExpressionArguments))
      }

      if ($null -ne $InstallFileEvidence) {
        foreach ($Call in @($InstallFileEvidence.Calls)) {
          & $AddGenteeExpression 'InstallGroup' $Call @('Architecture') ([pscustomobject]@{ GroupId = $Call.GroupId; Destination = $Call.Destination; Wildcard = $Call.Wildcard }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $ExtensionEvidence) {
        foreach ($Call in @($ExtensionEvidence.Calls)) {
          & $AddGenteeExpression 'FileAssociation' $Call @('FileExtensions') ([pscustomobject]@{ Extension = $Call.Extension; ProgId = $Call.ProgId; Application = $Call.Application }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $CustomRegistryEvidence) {
        foreach ($Call in @($CustomRegistryEvidence.Calls)) {
          & $AddGenteeExpression 'Registry' $Call @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') ([pscustomobject]@{ Root = $Call.Root; RegistryView = $Call.RegistryView; Key = $Call.Subkey }) ([string]$Call.ConditionExpression)
        }
        foreach ($Write in @($CustomRegistryEvidence.ConditionalRegistryWrites)) {
          foreach ($Expression in @($Write.ConditionExpression)) {
            & $AddGenteeExpression 'RegistryValue' $Write @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') ([pscustomobject]@{ Root = $Write.Root; RegistryView = $Write.RegistryView; Key = $Write.Key; Name = $Write.Name; Value = $Write.Value }) ([string]$Expression)
          }
        }
      }
      if ($null -ne $ShortcutEvidence) {
        foreach ($Call in @($ShortcutEvidence.Calls)) {
          & $AddGenteeExpression 'Shortcut' $Call @() ([pscustomobject]@{ ShortcutPath = $Call.ShortcutPath; TargetPath = $Call.TargetPath; Arguments = $Call.Arguments }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $RunEvidence) {
        foreach ($Call in @($RunEvidence.Calls)) {
          & $AddGenteeExpression 'Run' $Call @() ([pscustomobject]@{ Kind = $Call.Kind; Executable = $Call.Executable; NestedInstallerPath = $Call.PSObject.Properties['NestedInstallerPath'] ? $Call.NestedInstallerPath : $null; Arguments = $Call.Arguments }) ([string]$Call.ConditionExpression)
        }
      }
    }
    $RegistryWriteArray = $RegistryWrites.ToArray()
    $ArpEvidence = Get-CreateInstallArpEvidence -RegistryWrite $RegistryWriteArray
    foreach ($Diagnostic in $ArpEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    $ProductCodes = @($ArpEvidence.ProductCodes)
    $ProductCode = if ($ProductCodes.Count -eq 1) { $ProductCodes[0] } else { $null }
    if ($ProductCodes.Count -gt 1) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Multiple' -Source CreateInstall -Message "CreateInstall writes multiple visible uninstall keys: $(@($ProductCodes | Sort-Object) -join ', ')." -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries'))) }
    if ($ProductCodes.Count -eq 0) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Unproven' -Source CreateInstall -Message 'CreateInstall metadata identifies the package, but deterministic registry operations do not prove one visible uninstall key.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries'))) }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWriteArray
    if ($ExecutionLevel -ieq 'requireAdministrator' -and $ProductCodes.Count -eq 0) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Scope.ElevationInference' -Source CreateInstall -Message 'Machine scope is inferred from an explicit requireAdministrator application manifest.' -Kind Information -Areas Metadata -AffectedFields Scope)) }
    if ($null -ne $Layout -and ($Layout.PasswordCount -gt 0 -or ($Layout.Entries | Where-Object PasswordId -GT 0 | Select-Object -First 1))) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Archive.Encrypted' -Source CreateInstall -Message 'The GEA archive contains password-protected files; encrypted entries are intentionally unsupported.' -Kind Unsupported -Areas Extraction)) }
    # Compression capability is reported independently from identity evidence. Password-protected
    # entries and unknown method nibbles remain non-expandable; PPMd is supported statically.

    $DetectedScopes = @($ArpEvidence.Scopes)
    $Scope = if ($DetectedScopes.Count -eq 1) { $DetectedScopes[0] } elseif ($DetectedScopes.Count -gt 1) { $null } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }
    $SupportedScopes = if ($DetectedScopes.Count -gt 0) { @($DetectedScopes | Sort-Object) } elseif ($ExecutionLevel -ieq 'requireAdministrator') { @('machine') } else { @() }
    $PrimaryArp = $ArpEvidence.VisibleEntries.Count -eq 1 ? $ArpEvidence.VisibleEntries[0] : $null

    $WritesAppsAndFeaturesEntry = if ($ArpEvidence.VisibleEntries.Count -gt 0) { $true } elseif ($ArpEvidence.Entries.Count -gt 0) { $false } else { $null }
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.DisplayName) ? $PrimaryArp.DisplayName : $ProductName
      DisplayVersion               = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.DisplayVersion) ? $PrimaryArp.DisplayVersion : $DisplayVersion
      Publisher                    = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.Publisher) ? $PrimaryArp.Publisher : $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.InstallLocation) ? $PrimaryArp.InstallLocation : $DefaultInstallLocation
      InstallLocation              = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.InstallLocation) ? $PrimaryArp.InstallLocation : $DefaultInstallLocation
      UninstallString              = $PrimaryArp ? $PrimaryArp.UninstallString : $null
      QuietUninstallString         = $PrimaryArp ? $PrimaryArp.QuietUninstallString : $null
      DisplayIcon                  = $PrimaryArp ? $PrimaryArp.DisplayIcon : $null
      RegistryView                 = $PrimaryArp ? $PrimaryArp.RegistryView : ($Is32Bit ? '32-bit' : '64-bit')
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
      AppsAndFeaturesEntries       = $ArpEvidence.AppsAndFeaturesEntries
      ArpEntries                   = $ArpEvidence.Entries
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object)
      Family                       = 'CreateInstall'
      ProductCodeEvidence          = if ($ProductCode) { "Deterministic CreateInstall uninstall registry writes: $($PrimaryArp.Evidence -join '; ')" } else { $null }
      FileDescription              = ([string]$VersionInfo.FileDescription).Trim()
      SupportedScopes              = $SupportedScopes
      ScopeEvidence                = if ($ProductCode) { 'Deterministic uninstall registry hive and view' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'PE requestedExecutionLevel' } else { $null }
      RequestedExecutionLevel      = $ExecutionLevel
      InstallerSwitches            = if ($SilentSwitch) { [ordered]@{ Silent = $SilentSwitch; SilentWithProgress = $SilentSwitch } } else { [ordered]@{} }
      InstallModes                 = [string[]]@('interactive') + $(if ($SilentSwitch) { @('silent', 'silentWithProgress') } else { @() })
      RegistryWrites               = $RegistryWriteArray
      ConditionalRegistryWrites    = if ($null -ne $CustomRegistryEvidence) { $CustomRegistryEvidence.ConditionalRegistryWrites } else { @() }
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      ProjectVariables             = $ProjectVariables
      ProjectVariableEvidence      = if ($null -ne $ProjectVariableEvidence) { [pscustomobject]@{ BufferObjectId = $ProjectVariableEvidence.BufferObjectId; Offset = $ProjectVariableEvidence.Offset; Count = $ProjectVariableEvidence.Count } } else { $null }
      GenteeExpressions            = $GenteeExpressions.ToArray()
      FileAssociationCalls         = if ($null -ne $ExtensionEvidence) { $ExtensionEvidence.Calls } else { @() }
      CustomRegistryCalls          = if ($null -ne $CustomRegistryEvidence) { $CustomRegistryEvidence.Calls } else { @() }
      Shortcuts                    = if ($null -ne $ShortcutEvidence) { $ShortcutEvidence.Calls } else { @() }
      ExecutedPayloads             = if ($null -ne $RunEvidence) { $RunEvidence.Calls } else { @() }
      InstallGroupRoute            = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.RouteId } else { $null }
      InstallGroupCalls            = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.Calls } else { @() }
      InstalledFiles               = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.InstalledFiles } else { @() }
      GenteeProgram                = if ($null -ne $UninstallEvidence) { $UninstallEvidence.ProgramInfo } elseif ($null -ne $Program) { [pscustomobject]@{ LauncherOffset = $Program.LauncherOffset; SectionOffset = $Program.SectionOffset; RuntimeSize = $Program.RuntimeSize; StoredProgramSize = $Program.StoredProgramSize; ProgramSize = $Program.ProgramSize; Packed = $Program.Packed; VersionMajor = $Program.VersionMajor; VersionMinor = $Program.VersionMinor; ProgramProfile = $Program.ProgramProfile; ObjectCount = $Program.Records.Count; AddRemoveProfile = $null; AddRemoveRoutine = $null; AddRemoveRoutineId = $null } } else { $null }
      UninstallRegistrations       = $UninstallCalls
      OuterArchitectureInfo        = $OuterArchitectureInfo
      PayloadArchitectures         = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.Architectures } else { [string[]]@() }
      PayloadArchitectureInfo      = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.ArchitectureInfo } else { @() }
      PayloadDependencyInfo        = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.DependencyInfo } else { $null }
      PayloadAnalysisFiles         = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.InspectedFiles } else { @() }
      GEA                          = if ($null -ne $Layout) { [pscustomobject]@{ ArchiveProfile = $Layout.ArchiveProfile; MajorVersion = $Layout.MajorVersion; MinorVersion = $Layout.MinorVersion; ArchiveOffset = $Layout.ArchiveOffset; HeaderSize = $Layout.HeaderSize; SummarySize = $Layout.SummarySize; MovedSize = $Layout.MovedSize; BlockSize = $Layout.BlockSize; SolidSize = $Layout.SolidSize; EntryCount = $Layout.Entries.Count; CompressionMethods = @($CompressionMethods | Sort-Object); UnsupportedCompressionMethods = @($CompressionMethods | Where-Object { $_ -eq 'Unknown' } | Sort-Object); PasswordCount = $Layout.PasswordCount } } else { $null }
      ExtractedFiles               = if ($null -ne $Layout) { @($Layout.Entries.FullName) } else { @() }
      CanExpand                    = $null -ne $Layout -and $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('Unknown')
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.CreateInstall'; ParserMajor = 7; FormatCatalogVersion = [int]$Script:CreateInstallFormatCatalog.CatalogVersion; ArchiveProfile = if ($null -ne $Layout) { $Layout.ArchiveProfile } else { $null }; AddRemoveProfile = if ($null -ne $UninstallEvidence) { $UninstallEvidence.ProgramInfo.AddRemoveProfile } else { $null }; InstallGroupRoute = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.RouteId } else { $null }; Sources = @('PE version resource', 'PE application manifest', 'Gentee launcher/linkhead and GE 4.0 object serialization', 'CreateInstall generated MAINVAR/g_list data', 'CreateInstall addremove/addremoveex/addremoveext command source', 'CreateInstall regsetsex, extension, shortcut, and run command source', 'CreateInstall unpackgroup/unpackgroupex command source', 'Gentee GEA v1/v2 structures', 'Gentee LZGE decoder', 'Gentee-modified PPMd-I decoder') }
    }
  }
}

function Expand-CreateInstallInstaller {
  <#
  .SYNOPSIS
    Extract stored, LZGE-compressed, and PPMd-compressed files from a CreateInstall GEA archive
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
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string[]]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $Layout = Get-CreateInstallArchiveLayout -Path $Path
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-CreateInstall-$([guid]::NewGuid().ToString('N'))") }
    return Export-CreateInstallArchiveSelection -Layout $Layout -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
  }
}

function Test-CreateInstall {
  <#
  .SYNOPSIS
    Test whether a PE contains a parseable CreateInstall GE program and MAINVAR project table.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      $ResolvedPath = (Get-Item -LiteralPath $Path -Force).FullName
      # The compiled project program is authoritative and also covers valid no-payload setups.
      # Detection avoids full metadata and selected-payload analysis so a Boolean probe never
      # decompresses application binaries.
      $null = Get-PELayout -Path $ResolvedPath
      $Program = Get-CreateInstallGenteeProgram -Path $ResolvedPath
      $null = Get-CreateInstallProjectVariableEvidence -Program $Program
      return $true
    } catch { return $false }
  }
}

function Read-ProtocolsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal URL protocol names from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal file extensions from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayName }
}

function Read-PublisherFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromCreateInstall {
  <#
  .SYNOPSIS
    Read a literal CreateInstall uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).ProductCode }
}

function Read-ScopeFromCreateInstall {
  <#
  .SYNOPSIS
    Read CreateInstall scope from explicit elevation evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-CreateInstallInfo, Expand-CreateInstallInstaller, Test-CreateInstall, Read-ProtocolsFromCreateInstall, Read-FileExtensionsFromCreateInstall, Read-ProductVersionFromCreateInstall, Read-ProductNameFromCreateInstall, Read-PublisherFromCreateInstall, Read-ProductCodeFromCreateInstall, Read-ScopeFromCreateInstall
