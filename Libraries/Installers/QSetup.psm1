# SPDX-License-Identifier: Apache-2.0
# Static QSetup parser. QSetup EXE packages store length-prefixed zlib records
# after the PE image; Setup.txt contains explicit project and ARP directives.
# Binary structures consumed here (overlay-relative, LE integers):
#
#   releases 1-2: records begin directly at the PE overlay
#   releases 3-5: Version:u32, "||", PreambleLength:u32, UTF-8 preamble
#   releases 7+:  Version:u32, Format:u8, PreambleLength:u32, UTF-8 preamble
#   records:    [CompressedLength:u32 LE][zlib -> |Name[*]?|Stamp| + NUL + bytes]*
#   footer 1-2: RecordCount:u32, OverlayOffset:u32, Magic:0x4A3B2C1D
#   footer 3+:  Version:u32, OverlayOffset:u32, RecordCount:u32,
#               Magic:0x4A3B2C1D, generation fields, FooterLength:u32
#   signature:  optional zero alignment followed by the PE certificate table
#
# Every record advances by exactly 4 + CompressedLength. Setup.txt is interpreted
# only from a complete framed record. The footer identifies the record boundary,
# so its bytes and an Authenticode certificate are never offered to zlib. Preamble,
# count, header, input/output, next offset, and extraction path limits reject
# malformed packages.
#
# Format references:
# - https://www.pantaray.com/execute.html
# - https://www.pantaray.com/execution_cmd.html
# - https://www.panta-ray.com/pdf/qsetup_manual.pdf
# - https://web.archive.org/web/*/https://www.panta-ray.com/qstp.exe

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:QSetupMaximumRecordBytes = 2147483648
$Script:QSetupMaximumConfigurationBytes = 16777216
$Script:QSetupMaximumRecords = 100000
$Script:QSetupMaximumFooterBytes = 1048576
$Script:QSetupMaximumCertificateBytes = 67108864
$Script:QSetupFooterMagic = [uint32]0x4A3B2C1D
$Script:QSetupFooterMarker = [uint32]1234
$Script:QSetupFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'QSetupFormatCatalog.psd1')

function Test-QSetupZlibHeader {
  <#
  .SYNOPSIS
    Test the two-byte RFC 1950 header used by a QSetup record.
  .PARAMETER Header
    Two bytes beginning at the compressed member.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][ValidateCount(2, 2)][byte[]]$Header)

  $HeaderValue = ([int]$Header[0] -shl 8) -bor $Header[1]
  return ($Header[0] -band 0x0F) -eq 8 -and ($Header[0] -shr 4) -le 7 -and $HeaderValue % 31 -eq 0
}

function Test-QSetupPreambleText {
  <#
  .SYNOPSIS
    Validate the pipe-delimited update preamble used by QSetup 3 and later.
  .PARAMETER Value
    UTF-8 preamble text decoded from the overlay.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

  if ($Value.Length -gt 1048576 -or -not $Value.StartsWith('|') -or -not $Value.EndsWith('|')) { return $false }
  $Fields = $Value.Split('|')
  return $Fields.Count -ge 5 -and @($Fields | Where-Object { $_ -match '(?i)\.exe$' }).Count -gt 0
}

function Get-QSetupRecordStartOffset {
  <#
  .SYNOPSIS
    Validate the QSetup overlay preamble and return its first record offset
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. The helper does not dispose it.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 6 -gt $Stream.Length) { throw 'The QSetup PE has no valid package overlay' }
    $Prefix = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count ([int][Math]::Min(16, $Stream.Length - $OverlayOffset))

    # QSetup 1 and 2 place the first compressed record directly at the overlay.
    # Validate both its length and RFC 1950 header before selecting this route.
    $DirectLength = [uint32][BitConverter]::ToUInt32($Prefix, 0)
    if ($DirectLength -gt 2 -and $DirectLength -le $Script:QSetupMaximumRecordBytes -and $DirectLength -le $Stream.Length - $OverlayOffset - 4 -and
      (Test-QSetupZlibHeader -Header $Prefix[4..5])) {
      return [pscustomobject][ordered]@{
        OverlayOffset     = [long]$OverlayOffset
        RecordStartOffset = [long]$OverlayOffset
        FormatVersion     = $null
        CompressionFormat = 2
        Preamble          = $null
        StructuralRoute   = 'DirectRecords'
      }
    }

    $Version = [uint32](Read-BinaryInteger -Stream $Stream -Offset $OverlayOffset -Size 4)
    if ($Version -eq 0) { throw 'The QSetup overlay preamble is invalid' }

    # QSetup 3 through 5 insert a literal two-byte || marker before the length.
    if ($Prefix[4] -eq 0x7C -and $Prefix[5] -eq 0x7C) {
      if ($OverlayOffset + 10 -gt $Stream.Length) { throw 'The QSetup double-pipe preamble is truncated' }
      $PreambleLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 6) -Size 4)
      $PreambleOffset = $OverlayOffset + 10
      $Route = 'DoublePipePreamble'
      $Format = $null
    } else {
      # QSetup 7 and later carry an explicit compression-format byte.
      if ($OverlayOffset + 9 -gt $Stream.Length) { throw 'The QSetup versioned preamble is truncated' }
      $Format = [byte](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 4) -Size 1)
      $PreambleLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 5) -Size 4)
      $PreambleOffset = $OverlayOffset + 9
      $Route = 'VersionedPreamble'
    }

    if ($PreambleLength -eq 0 -or $PreambleLength -gt 1048576 -or $PreambleLength -gt $Stream.Length - $PreambleOffset) {
      throw 'The QSetup overlay preamble is invalid'
    }
    $Preamble = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset $PreambleOffset -Count ([int]$PreambleLength)))
    if (-not (Test-QSetupPreambleText -Value $Preamble)) { throw 'The QSetup overlay preamble marker is invalid' }
    [pscustomobject][ordered]@{
      OverlayOffset     = [long]$OverlayOffset
      RecordStartOffset = [long]($PreambleOffset + $PreambleLength)
      FormatVersion     = $Version
      CompressionFormat = $Format
      Preamble          = $Preamble
      StructuralRoute   = $Route
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Read-QSetupRecord {
  <#
  .SYNOPSIS
    Read one bounded QSetup zlib record header and optional content
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. The helper does not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER ReadContent
    Controls whether bounded entry content is decoded in addition to catalog metadata.
  .PARAMETER MaximumContentBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER EndOffset
    Exclusive absolute boundary of the record table. The default uses the physical file length for compatibility with direct calls.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [switch]$ReadContent,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumContentBytes = $Script:QSetupMaximumConfigurationBytes,
    [ValidateRange(-1, [long]::MaxValue)][long]$EndOffset = -1
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  try {
    $RecordTableEnd = if ($EndOffset -ge 0) { $EndOffset } else { $Stream.Length }
    if ($RecordTableEnd -gt $Stream.Length) { throw 'The QSetup record boundary exceeds the file length' }
    if ($Offset -lt 0 -or $Offset + 4 -gt $RecordTableEnd) { throw 'The QSetup record length is truncated' }
    # Each record is independently framed by a compressed length, so malformed
    # data cannot make the decoder consume the next record.
    $CompressedLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    if ($CompressedLength -eq 0 -or $CompressedLength -gt $Script:QSetupMaximumRecordBytes) { throw 'The QSetup record length is invalid' }
    if ($CompressedLength -gt $RecordTableEnd - $Offset - 4) { throw 'The QSetup record data is truncated' }
    $CompressedRange = New-BoundedReadStream -Stream $Stream -Offset ($Offset + 4) -Length $CompressedLength -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
    try {
      # Decode only through the third pipe delimiter to enumerate a record. The
      # potentially large body is materialized only when the caller requests it.
      $HeaderBytes = [System.Collections.Generic.List[byte]]::new()
      $PipeCount = 0
      while ($HeaderBytes.Count -lt 4096 -and $PipeCount -lt 3) {
        $Value = $Decoder.ReadByte()
        if ($Value -lt 0) { break }
        $HeaderBytes.Add([byte]$Value)
        if ($Value -eq 0x7C) { $PipeCount++ }
      }
      $Header = [Text.Encoding]::ASCII.GetString($HeaderBytes.ToArray())
      $Match = [regex]::Match($Header, '^\|(?<Name>[^|*]+)(?<Required>\*)?\|(?<Stamp>\d+)\|$')
      if (-not $Match.Success) { throw 'The QSetup record header is invalid' }
      # Every verified generation terminates catalog metadata with one NUL byte.
      # It is record framing and must not become the first byte of the payload.
      if ($Decoder.ReadByte() -ne 0) { throw 'The QSetup record body marker is invalid' }

      $Content = $null
      $ContentLength = $null
      if ($ReadContent) {
        # Setup.txt and other requested bodies are accumulated under an explicit
        # expanded-size limit to reject zlib bombs deterministically.
        $Output = [IO.MemoryStream]::new()
        try {
          $Buffer = [byte[]]::new(1048576)
          $Written = 0L
          while (($Read = $Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
            $Written += $Read
            if ($Written -gt $MaximumContentBytes) { throw "The QSetup record exceeds the $MaximumContentBytes-byte content limit" }
            $Output.Write($Buffer, 0, $Read)
          }
          $Content = $Output.ToArray()
          $ContentLength = $Written
        } finally { $Output.Dispose() }
      }
      [pscustomobject]@{
        Name             = $Match.Groups['Name'].Value
        Required         = $Match.Groups['Required'].Success
        Stamp            = $Match.Groups['Stamp'].Value
        Offset           = [long]$Offset
        CompressedLength = [long]$CompressedLength
        NextOffset       = [long]($Offset + 4 + $CompressedLength)
        ContentLength    = $ContentLength
        Content          = $Content
      }
    } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Get-QSetupTrailingCertificateInfo {
  <#
  .SYNOPSIS
    Validate optional alignment and WIN_CERTIFICATE records after a QSetup footer.
  .PARAMETER Stream
    Seekable caller-owned installer stream positioned by absolute offsets.
  .PARAMETER Offset
    Absolute byte immediately after the candidate footer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset
  )

  for ($PaddingLength = 0; $PaddingLength -le 7; $PaddingLength++) {
    $CertificateOffset = $Offset + $PaddingLength
    if ($CertificateOffset -gt $Stream.Length) { break }
    if ($PaddingLength -gt 0) {
      $Padding = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $PaddingLength
      if (@($Padding | Where-Object { $_ -ne 0 }).Count -gt 0) { break }
    }

    if ($CertificateOffset -eq $Stream.Length) {
      return [pscustomobject][ordered]@{ IsValid = $true; Offset = 0L; Size = 0L; AlignmentPadding = $PaddingLength; EntryCount = 0 }
    }
    $CertificateSize = $Stream.Length - $CertificateOffset
    if ($CertificateSize -lt 8 -or $CertificateSize -gt $Script:QSetupMaximumCertificateBytes) { continue }

    # A certificate table can contain multiple aligned WIN_CERTIFICATE records.
    # Validate every record to avoid mistaking arbitrary trailer bytes for a signature.
    $EntryOffset = $CertificateOffset
    $EntryCount = 0
    $Valid = $true
    while ($EntryOffset -lt $Stream.Length) {
      if ($Stream.Length - $EntryOffset -lt 8) { $Valid = $false; break }
      $EntryLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset $EntryOffset -Size 4)
      $Revision = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($EntryOffset + 4) -Size 2)
      $CertificateType = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($EntryOffset + 6) -Size 2)
      if ($EntryLength -lt 8 -or $EntryLength -gt $Stream.Length - $EntryOffset -or $Revision -notin @(0x0100, 0x0200) -or $CertificateType -ne 2) {
        $Valid = $false
        break
      }
      $EntryOffset += (($EntryLength + 7) -band -bnot 7)
      $EntryCount++
    }
    if ($Valid -and $EntryOffset -eq $Stream.Length) {
      return [pscustomobject][ordered]@{
        IsValid          = $true
        Offset           = [long]$CertificateOffset
        Size             = [long]$CertificateSize
        AlignmentPadding = [int]$PaddingLength
        EntryCount       = [int]$EntryCount
      }
    }
  }

  return [pscustomobject][ordered]@{ IsValid = $false; Offset = 0L; Size = 0L; AlignmentPadding = 0; EntryCount = 0 }
}

function Get-QSetupTerminalInfo {
  <#
  .SYNOPSIS
    Validate the QSetup footer and optional Authenticode trailer at a record boundary.
  .PARAMETER Stream
    Seekable caller-owned installer stream.
  .PARAMETER Offset
    Absolute offset where the next record or footer would begin.
  .PARAMETER Preamble
    Validated preamble and overlay evidence.
  .PARAMETER RecordCount
    Number of structurally valid records preceding the candidate footer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][psobject]$Preamble,
    [Parameter(Mandatory)][ValidateRange(0, 100000)][int]$RecordCount
  )

  if ($Offset -eq $Stream.Length) {
    return [pscustomobject][ordered]@{ IsValid = $true; DataEndOffset = $Offset; Footer = $null; Certificate = $null; StructuralRoute = 'Footerless' }
  }

  # QSetup 3 and later use a 74-byte footer. Releases before the modern marker
  # retain opaque generation fields at +0x10, so those bytes are reported but
  # never assigned invented semantics.
  if ($Stream.Length - $Offset -ge 74) {
    $FooterLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 70) -Size 4)
    $FooterVersion = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    $RecordedOverlayOffset = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4)
    $DeclaredRecordCount = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 8) -Size 4)
    $Magic = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 12) -Size 4)
    if ($FooterLength -eq 74 -and $FooterVersion -gt 0 -and $RecordedOverlayOffset -eq $Preamble.OverlayOffset -and
      $DeclaredRecordCount -eq $RecordCount -and $Magic -eq $Script:QSetupFooterMagic) {
      $Trailer = Get-QSetupTrailingCertificateInfo -Stream $Stream -Offset ($Offset + 74)
      if ($Trailer.IsValid) {
        $Marker = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 16) -Size 4)
        $Route = $Marker -eq $Script:QSetupFooterMarker ? 'Modern74' : 'Legacy74'
        return [pscustomobject][ordered]@{
          IsValid         = $true
          DataEndOffset   = [long]$Offset
          StructuralRoute = $Route
          Footer          = [pscustomobject][ordered]@{
            RouteId             = $Route
            Offset              = [long]$Offset
            Length              = 74L
            Version             = $FooterVersion
            OverlayOffset       = [long]$RecordedOverlayOffset
            DeclaredRecordCount = [int]$DeclaredRecordCount
            Magic               = ('0x{0:X8}' -f $Magic)
            Marker              = $Marker -eq $Script:QSetupFooterMarker ? $Marker : $null
            ObservedField10     = $Marker -eq $Script:QSetupFooterMarker ? $null : ('0x{0:X8}' -f $Marker)
          }
          Certificate     = $Trailer.Offset -gt 0 ? [pscustomobject][ordered]@{ Offset = $Trailer.Offset; Size = $Trailer.Size; AlignmentPadding = $Trailer.AlignmentPadding; EntryCount = $Trailer.EntryCount } : $null
        }
      }
    }
  }

  # QSetup 1 and 2 end with only record count, overlay offset, and magic.
  if ($Stream.Length - $Offset -ge 12) {
    $DeclaredRecordCount = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    $RecordedOverlayOffset = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4)
    $Magic = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 8) -Size 4)
    if ($DeclaredRecordCount -eq $RecordCount -and $RecordedOverlayOffset -eq $Preamble.OverlayOffset -and $Magic -eq $Script:QSetupFooterMagic) {
      $Trailer = Get-QSetupTrailingCertificateInfo -Stream $Stream -Offset ($Offset + 12)
      if ($Trailer.IsValid) {
        return [pscustomobject][ordered]@{
          IsValid         = $true
          DataEndOffset   = [long]$Offset
          StructuralRoute = 'Compact12'
          Footer          = [pscustomobject][ordered]@{
            RouteId             = 'Compact12'
            Offset              = [long]$Offset
            Length              = 12L
            Version             = $null
            OverlayOffset       = [long]$RecordedOverlayOffset
            DeclaredRecordCount = [int]$DeclaredRecordCount
            Magic               = ('0x{0:X8}' -f $Magic)
            Marker              = $null
            ObservedField10     = $null
          }
          Certificate     = $Trailer.Offset -gt 0 ? [pscustomobject][ordered]@{ Offset = $Trailer.Offset; Size = $Trailer.Size; AlignmentPadding = $Trailer.AlignmentPadding; EntryCount = $Trailer.EntryCount } : $null
        }
      }
    }
  }

  return [pscustomobject][ordered]@{ IsValid = $false; DataEndOffset = [long]$Stream.Length; Footer = $null; Certificate = $null; StructuralRoute = 'Unknown' }
}

function Get-QSetupLayout {
  <#
  .SYNOPSIS
    Enumerate bounded QSetup record headers without expanding payload bodies
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. Its position is preserved.
  .PARAMETER MaximumRecords
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [ValidateRange(1, 100000)][int]$MaximumRecords = $Script:QSetupMaximumRecords
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'QSetup layout parsing requires a readable, seekable stream.' }
  $OriginalPosition = $Stream.Position
  try {
    $Preamble = Get-QSetupRecordStartOffset -Stream $Stream
    $Records = [System.Collections.Generic.List[object]]::new()
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $Offset = $Preamble.RecordStartOffset
    $RecordFailure = $null

    # Records are physically adjacent. A failed record decode is not immediately
    # corruption because every known generation places its footer at that point.
    while ($Offset + 4 -le $Stream.Length -and $Records.Count -lt $MaximumRecords) {
      try {
        $Record = Read-QSetupRecord -Stream $Stream -Offset $Offset -EndOffset $Stream.Length
      } catch {
        $RecordFailure = $_.Exception.Message
        break
      }
      $Records.Add($Record)
      if ($Record.NextOffset -le $Offset) {
        $RecordFailure = 'The QSetup record table does not advance.'
        break
      }
      $Offset = $Record.NextOffset
    }

    $Terminal = Get-QSetupTerminalInfo -Stream $Stream -Offset $Offset -Preamble $Preamble -RecordCount $Records.Count
    $Complete = [bool]$Terminal.IsValid
    if ($Records.Count -eq $MaximumRecords -and -not $Complete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.RecordTable.CountLimit' -Source QSetup -Message "The QSetup record count exceeds the $MaximumRecords-record limit." -Kind Invalid -Areas Extraction -AffectedFields ExtractedFiles))
    } elseif (-not $Complete) {
      $Reason = [string]::IsNullOrWhiteSpace($RecordFailure) ? 'The record table has unrecognized trailing data.' : $RecordFailure
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.RecordTable.Incomplete' -Source QSetup -Message $Reason -Kind Incomplete -Areas Extraction, Metadata -AffectedFields ExtractedFiles))
    }

    $Generation = switch ($Preamble.StructuralRoute) {
      'DirectRecords' { 'Legacy1-2' }
      'DoublePipePreamble' { 'Legacy3-5' }
      'VersionedPreamble' { $Terminal.StructuralRoute -eq 'Modern74' ? 'Modern12' : 'Legacy7-8' }
      default { 'Unknown' }
    }
    [pscustomobject][ordered]@{
      Preamble         = $Preamble
      Records          = $Records.ToArray()
      Complete         = $Complete
      ParsedEndOffset  = [long]$Offset
      DataEndOffset    = [long]$Terminal.DataEndOffset
      Footer           = $Terminal.Footer
      Certificate      = $Terminal.Certificate
      FormatGeneration = $Generation
      StructuralRoutes = [string[]]@($Preamble.StructuralRoute, 'Record/Zlib', $Terminal.StructuralRoute)
      Diagnostics      = [object[]]$Diagnostics.ToArray()
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function ConvertFrom-QSetupDirectiveText {
  <#
  .SYNOPSIS
    Parse literal SET_* directives from QSetup Setup.txt
  .PARAMETER Content
    Raw text to parse as format metadata without executing embedded commands.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = @{}
  foreach ($Record in Get-QSetupDirectiveRecord -Content $Content) {
    $Name = $Record.Name
    $Value = $Record.Value
    if (-not $Result.ContainsKey($Name)) { $Result[$Name] = [System.Collections.Generic.List[object]]::new() }
    $Result[$Name].Add($Value)
  }
  return $Result
}

function Get-QSetupDirectiveRecord {
  <#
  .SYNOPSIS
    Parse literal Setup.txt directives while preserving source order.
  .PARAMETER Content
    UTF-8 Setup.txt content. Dynamic expressions are retained as literal values.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = [Collections.Generic.List[object]]::new()
  $LineNumber = 0
  foreach ($Line in ($Content.TrimStart([char]0, [char]0xFEFF) -split "`r?`n")) {
    $LineNumber++
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith('//')) { continue }
    $Match = [regex]::Match($Trimmed, '^(?<Name>SET_[A-Z0-9_]+)(?:\((?<Value>.*)\))?;?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $Match.Success) { continue }
    $Result.Add([pscustomobject][ordered]@{
        Name       = $Match.Groups['Name'].Value.ToUpperInvariant()
        Value      = $Match.Groups['Value'].Success ? $Match.Groups['Value'].Value : $true
        LineNumber = $LineNumber
      })
  }
  return $Result.ToArray()
}

function Get-QSetupDirectiveValue {
  <#
  .SYNOPSIS
    Return the first literal value for a parsed QSetup directive
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  param ([Parameter(Mandatory)][hashtable]$Directive, [Parameter(Mandatory)][string]$Name)
  if (-not $Directive.ContainsKey($Name)) { return $null }
  return @($Directive[$Name])[0]
}

function Get-QSetupDirectiveTextValue {
  <#
  .SYNOPSIS
    Return the first non-empty literal value, optionally falling back to another directive.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  .PARAMETER Name
    Primary directive name.
  .PARAMETER FallbackName
    Directive used when the primary value is absent or empty.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][string]$Name,
    [string]$FallbackName
  )

  $Value = Get-QSetupDirectiveValue -Directive $Directive -Name $Name
  if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { return [string]$Value }
  if ($FallbackName) {
    $Value = Get-QSetupDirectiveValue -Directive $Directive -Name $FallbackName
    if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { return [string]$Value }
  }
  return $null
}

function Test-QSetupDirectiveEnabled {
  <#
  .SYNOPSIS
    Interpret an optional QSetup flag directive without treating an explicit false value as enabled.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  .PARAMETER Name
    Flag directive to inspect.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not $Directive.ContainsKey($Name)) { return $false }
  $Value = @($Directive[$Name])[0]
  if ($Value -is [bool]) { return $Value }
  if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $true }
  return [string]$Value -notmatch '^(?i:0|false|no|off|disabled)$'
}

function Resolve-QSetupAliasText {
  <#
  .SYNOPSIS
    Resolve a bounded set of case-insensitive QSetup aliases in one literal path expression.
  .PARAMETER Text
    Literal path expression from Setup.txt.
  .PARAMETER Alias
    Alias-to-path dictionary. Values can themselves contain aliases and are expanded for at most eight passes.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Text,
    [Parameter(Mandatory)][hashtable]$Alias
  )

  $Result = $Text.Trim().Trim('"')
  for ($Depth = 0; $Depth -lt 8; $Depth++) {
    $Before = $Result
    foreach ($Entry in $Alias.GetEnumerator()) {
      $Result = $Result.Replace([string]$Entry.Key, [string]$Entry.Value, [StringComparison]::OrdinalIgnoreCase)
    }
    if ($Result -ceq $Before) { break }
  }
  return $Result
}

function ConvertTo-QSetupNormalizedPath {
  <#
  .SYNOPSIS
    Normalize separators and literal dot segments while preserving a WinGet environment-variable or drive root.
  .PARAMETER Value
    Alias-expanded Windows path.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Value)

  $Normalized = $Value.Replace('/', '\') -replace '\\+', '\'
  $Root = ''
  $Tail = $Normalized
  if ($Normalized -match '^(?<Root>%[^%]+%|[A-Za-z]:)(?:\\)?(?<Tail>.*)$') {
    $Root = $Matches.Root
    $Tail = $Matches.Tail
  } elseif ($Normalized.StartsWith('\')) {
    $Root = '\'
    $Tail = $Normalized.TrimStart('\')
  }

  $Segments = [Collections.Generic.List[string]]::new()
  foreach ($Segment in $Tail.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
    if ($Segment -eq '.') { continue }
    if ($Segment -eq '..') {
      if ($Segments.Count -eq 0) { return $null }
      $Segments.RemoveAt($Segments.Count - 1)
      continue
    }
    $Segments.Add($Segment)
  }
  if (-not $Root) { return ($Segments -join '\') }
  if ($Segments.Count -eq 0) { return $Root }
  return $Root.TrimEnd('\') + '\' + ($Segments -join '\')
}

function ConvertTo-QSetupManifestPath {
  <#
  .SYNOPSIS
    Resolve deterministic QSetup directory aliases to manifest-safe paths.
  .PARAMETER Value
    QSetup path expression.
  .PARAMETER Directive
    Parsed Setup.txt directives supplying application, common, and auxiliary roots.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][hashtable]$Directive
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $BaseAliases = [ordered]@{
    '<ProgramFilesDir>'     = '%ProgramFiles%'
    '<Program Files Dir>'   = '%ProgramFiles%'
    '<ProgramFiles>'        = '%ProgramFiles%'
    '<CommonFilesDir>'      = '%CommonProgramFiles%'
    '<WinDir>'              = '%WINDIR%'
    '<Windows Directory>'   = '%WINDIR%'
    '<WinSys32Dir>'         = '%WINDIR%\System32'
    '<System Directory>'    = '%WINDIR%\System32'
    '<WinSys16Dir>'         = '%WINDIR%\System'
    '<System 16 Directory>' = '%WINDIR%\System'
    '<FontDir>'             = '%WINDIR%\Fonts'
    '<UserLocalAppDataDir>' = '%LOCALAPPDATA%'
    '<UserAppDataDir>'      = '%APPDATA%'
    '<AllUsersAppDataDir>'  = '%ProgramData%'
    '<UserDir>'             = '%USERPROFILE%'
    '<MyDocumentsDir>'      = '%USERPROFILE%\Documents'
    '<TempDir>'             = '%TEMP%'
    '<AbsoluteDir>'         = ''
  }

  $TargetRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_TARGET_DIR'
  $Target = $TargetRaw ? (Resolve-QSetupAliasText -Text $TargetRaw -Alias $BaseAliases) : $null
  $ApplicationAliases = @{}
  foreach ($Entry in $BaseAliases.GetEnumerator()) { $ApplicationAliases[$Entry.Key] = $Entry.Value }
  if ($Target) {
    $TargetRoot = $Target.TrimEnd('\') + '\'
    $ApplicationAliases['<Application Folder>'] = $TargetRoot
    $ApplicationAliases['<InstallDir>'] = $TargetRoot
  }

  $CommonRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_COMMON_DIR'
  $Common = $CommonRaw ? (Resolve-QSetupAliasText -Text $CommonRaw -Alias $ApplicationAliases) : $null
  $AuxiliaryRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_AUX_DIR'
  $Auxiliary = $AuxiliaryRaw ? (Resolve-QSetupAliasText -Text $AuxiliaryRaw -Alias $ApplicationAliases) : $null
  if ($Common) {
    $ApplicationAliases['<Common Folder>'] = $Common.TrimEnd('\') + '\'
    $ApplicationAliases['<InstallCommonDir>'] = $Common.TrimEnd('\') + '\'
  }
  if ($Auxiliary) {
    $ApplicationAliases['<Auxiliary Folder>'] = $Auxiliary.TrimEnd('\') + '\'
    $ApplicationAliases['<InstallAuxDir>'] = $Auxiliary.TrimEnd('\') + '\'
  }

  $Result = ConvertTo-QSetupNormalizedPath -Value (Resolve-QSetupAliasText -Text $Value -Alias $ApplicationAliases)
  if (-not $Result) { return $null }
  if ($Result -match '<[^>]+>') { return $null }
  return $Result.TrimEnd('\')
}

function ConvertTo-QSetupExtractionPath {
  <#
  .SYNOPSIS
    Convert an installed QSetup destination to a safe path beneath an extraction root.
  .PARAMETER Payload
    Payload-catalog entry containing the resolved installed path and physical record name.
  .PARAMETER InstallLocation
    Resolved application root. Files beneath it retain their installed relative paths.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][psobject]$Payload,
    [AllowNull()][string]$InstallLocation
  )

  $InstalledPath = [string]$Payload.InstalledPath
  $InstallRoot = $InstallLocation ? $InstallLocation.TrimEnd('\') : $null
  if ($InstallRoot -and $InstalledPath.StartsWith($InstallRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    return $InstalledPath.Substring($InstallRoot.Length + 1)
  }
  if ($InstallRoot -and $InstalledPath.Equals($InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
    return [string]$Payload.InstalledName
  }
  if ($InstalledPath -match '^%(?<Root>[^%]+)%\\?(?<Tail>.*)$') {
    return Join-Path (Join-Path '_destinations' $Matches.Root) $Matches.Tail
  }
  if ($InstalledPath -match '^(?<Drive>[A-Za-z]):\\?(?<Tail>.*)$') {
    return Join-Path (Join-Path '_destinations' "Drive-$($Matches.Drive.ToUpperInvariant())") $Matches.Tail
  }
  if ($InstalledPath.StartsWith('\')) {
    return Join-Path (Join-Path '_destinations' 'Root') $InstalledPath.TrimStart('\')
  }
  if (-not [string]::IsNullOrWhiteSpace($InstalledPath)) {
    return Join-Path (Join-Path '_destinations' 'Relative') $InstalledPath
  }
  return Join-Path '_unresolved' ([string]$Payload.InstalledName)
}

function Get-QSetupPayloadCatalog {
  <#
  .SYNOPSIS
    Map physical QSetup records to the installed paths encoded by Setup.txt.
  .PARAMETER DirectiveRecord
    Ordered literal directives returned by Get-QSetupDirectiveRecord.
  .PARAMETER Directive
    Parsed directive dictionary used to resolve destination aliases.
  .PARAMETER Record
    Structurally validated physical record catalog.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$DirectiveRecord,
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][object[]]$Record
  )

  $RecordByName = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in $Record) { if (-not $RecordByName.ContainsKey([string]$Item.Name)) { $RecordByName.Add([string]$Item.Name, $Item) } }
  $Result = [Collections.Generic.List[object]]::new()
  $DestinationExpression = $null
  foreach ($Item in $DirectiveRecord) {
    if ($Item.Name -eq 'SET_SUB_DIR') {
      $DestinationExpression = ([string]$Item.Value) -replace '^\d+\*', ''
      continue
    }
    if ($Item.Name -ne 'SET_COPY_FILES' -or [string]::IsNullOrWhiteSpace([string]$Item.Value)) { continue }
    # QSetup 1 and 2 separate copy descriptors with commas. Later composers use
    # pipes; select one grammar per directive so commas in modern file names are
    # not interpreted as record separators.
    $CopyValue = [string]$Item.Value
    $Separator = $CopyValue.Contains('|') ? '|' : ','
    foreach ($FileDescriptor in $CopyValue.Split($Separator, [StringSplitOptions]::RemoveEmptyEntries)) {
      $Match = [regex]::Match($FileDescriptor, '^(?:(?<Flags>\d+)\*)?(?<RecordName>.+)$')
      if (-not $Match.Success) { continue }
      $RecordName = $Match.Groups['RecordName'].Value
      $PhysicalRecord = $null
      if (-not $RecordByName.TryGetValue($RecordName, [ref]$PhysicalRecord)) { continue }
      $InstalledName = $RecordName -replace '^\d+#', ''
      $ResolvedDirectory = ConvertTo-QSetupManifestPath -Value $DestinationExpression -Directive $Directive
      $InstalledPath = $ResolvedDirectory ? ($ResolvedDirectory.TrimEnd('\') + '\' + $InstalledName) : $null
      $Result.Add([pscustomobject][ordered]@{
          RecordName            = $RecordName
          InstalledName         = $InstalledName
          Flags                 = $Match.Groups['Flags'].Success ? [uint32]$Match.Groups['Flags'].Value : 0
          DestinationExpression = [string]::IsNullOrWhiteSpace($DestinationExpression) ? $null : $DestinationExpression
          ResolvedDirectory     = $ResolvedDirectory
          InstalledPath         = $InstalledPath
          Record                = $PhysicalRecord
        })
    }
  }
  return $Result.ToArray()
}

function ConvertFrom-QSetupExecutionAction {
  <#
  .SYNOPSIS
    Decode one fixed-slot QSetup Execution Engine directive.
  .PARAMETER Content
    Literal SET_PERFORM_EXECUTE_OP value from Setup.txt.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  $Fields = [regex]::Split($Content, '\|')
  $LayoutProfile = $Script:QSetupFormatCatalog.ExecutionRoutes | Where-Object { $Fields.Count -in $_.FieldCounts } | Select-Object -First 1
  if (-not $LayoutProfile -or $Fields[0] -notin @('*', '^') -or $Fields[$LayoutProfile.MiddleSentinel] -ne $Fields[0] -or $Fields[-1] -ne $Fields[0]) {
    throw 'The QSetup execution-action record does not use the supported fixed-slot layout.'
  }

  $Commands = [Collections.Generic.List[object]]::new()
  # Every profile stores command descriptors and command arguments in separate
  # fixed-width arrays. Pair the slots without evaluating runtime conditions.
  for ($Index = 0; $Index -lt $LayoutProfile.CommandCount; $Index++) {
    $DescriptorOffset = $LayoutProfile.CommandStart + ($Index * 3)
    $ArgumentOffset = $LayoutProfile.ArgumentStart + ($Index * 3)
    if ($Fields[$DescriptorOffset] -ne '1' -or [string]::IsNullOrWhiteSpace($Fields[$DescriptorOffset + 1])) { continue }
    $Commands.Add([pscustomobject][ordered]@{
        Slot      = $Index + 1
        Name      = $Fields[$DescriptorOffset + 1]
        Argument1 = $Fields[$ArgumentOffset]
        Argument2 = $Fields[$ArgumentOffset + 1]
        Argument3 = $Fields[$ArgumentOffset + 2]
      })
  }

  return [pscustomobject][ordered]@{
    LayoutRoute          = $LayoutProfile.Id
    Name                 = $Fields[2]
    Stage                = $Fields[3]
    Sequence             = $LayoutProfile.Id -eq 'ModernSixCommand' ? $Fields[4] : $null
    ConditionMode        = $LayoutProfile.Id -eq 'ModernSixCommand' ? $Fields[5] : 'Legacy'
    AppliesDuring        = $Fields[0] -eq '*' ? 'Setup' : 'Uninstall'
    IsConditional        = $LayoutProfile.Id -eq 'ModernSixCommand' ? $Fields[5] -ne 'UnConditional' : $true
    ConditionDescriptors = [string[]]($LayoutProfile.Id -eq 'ModernSixCommand' ? $Fields[6..19] : $Fields[5..19])
    ConditionArguments   = [string[]]($LayoutProfile.Id -eq 'ModernSixCommand' ? $Fields[41..52] : $Fields[34..45])
    Commands             = [object[]]$Commands.ToArray()
    RawValue             = $Content
  }
}

function Get-QSetupExecutionActionInfo {
  <#
  .SYNOPSIS
    Project QSetup Execution Engine records and nested process launches.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Actions = [Collections.Generic.List[object]]::new()
  $ExecutedPayloads = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  $Values = $Directive.ContainsKey('SET_PERFORM_EXECUTE_OP') ? @($Directive['SET_PERFORM_EXECUTE_OP']) : @()
  foreach ($Value in $Values) {
    try {
      $Action = ConvertFrom-QSetupExecutionAction -Content ([string]$Value)
      $Actions.Add($Action)
      foreach ($Command in $Action.Commands) {
        if ($Command.Name -notmatch '^(?:Run (?:Application|Executable|Batch File|MSI File)(?: and Wait)?|Shell Execute(?: and Wait)?|Run DLL(?: No Wait)?)$') { continue }
        $ExecutedPayloads.Add([pscustomobject][ordered]@{
            Command       = $Command.Argument1
            Parameters    = $Command.Argument2
            ShowCommand   = $Command.Argument3
            Operation     = $Command.Name
            Wait          = $Command.Name -match ' and Wait$|^Run DLL$'
            ActionName    = $Action.Name
            Stage         = $Action.Stage
            AppliesDuring = $Action.AppliesDuring
            Conditional   = $Action.IsConditional
            Source        = 'SET_PERFORM_EXECUTE_OP'
          })
      }
    } catch {
      $Warnings.Add("A QSetup execution-action record is malformed or unsupported: $($_.Exception.Message)")
    }
  }

  return [pscustomobject][ordered]@{
    Actions          = [object[]]$Actions.ToArray()
    ExecutedPayloads = [object[]]$ExecutedPayloads.ToArray()
    Diagnostics      = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QSetup' -Kind Incomplete -Areas Metadata)
  }
}

function Get-QSetupShortcutInfo {
  <#
  .SYNOPSIS
    Decode literal Start/Programs shortcut records without assigning semantics to trailing version-specific flags.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Value in @($Directive['SET_START_PROGRAM_LINK_ITEM'])) {
    $Fields = [regex]::Split([string]$Value, '\|')
    if ($Fields.Count -lt 10 -or [string]::IsNullOrWhiteSpace($Fields[1]) -or [string]::IsNullOrWhiteSpace($Fields[2])) { continue }
    $TargetExpression = $Fields[2].Trim()
    $Target = if ($TargetExpression -match '^[A-Za-z][A-Za-z0-9+.-]*:') { $TargetExpression } else { ConvertTo-QSetupManifestPath -Value $TargetExpression -Directive $Directive }
    $WorkingDirectoryExpression = $Fields[5].Trim()
    $IconExpression = $Fields[7].Trim()
    $Result.Add([pscustomobject][ordered]@{
        Name                       = $Fields[1].Trim()
        TargetExpression           = $TargetExpression
        Target                     = $Target
        Subfolder                  = $Fields[3].Trim()
        Parameters                 = $Fields[4].Trim()
        WorkingDirectoryExpression = $WorkingDirectoryExpression
        WorkingDirectory           = $WorkingDirectoryExpression ? (ConvertTo-QSetupManifestPath -Value $WorkingDirectoryExpression -Directive $Directive) : $null
        WindowStyle                = $Fields[6].Trim()
        IconExpression             = $IconExpression
        Icon                       = $IconExpression ? (ConvertTo-QSetupManifestPath -Value $IconExpression -Directive $Directive) : $null
        IconIndex                  = $Fields[8].Trim() -match '^\d+$' ? [int]$Fields[8].Trim() : $null
        ObservedFlags              = [string[]]$Fields[9..($Fields.Count - 2)]
        Source                     = 'SET_START_PROGRAM_LINK_ITEM'
      })
  }
  return $Result.ToArray()
}

function Get-QSetupEnvironmentChange {
  <#
  .SYNOPSIS
    Decode literal QSetup environment-variable operations.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Value in @($Directive['SET_PERFORM_ENVIRONMENT_OP'])) {
    $Fields = ([string]$Value).Split('|')
    if ($Fields.Count -lt 5 -or [string]::IsNullOrWhiteSpace($Fields[0])) { continue }
    $Result.Add([pscustomobject][ordered]@{
        Name            = $Fields[0].Trim()
        Value           = $Fields[1]
        Operation       = $Fields[2].Trim()
        UninstallAction = $Fields[3].Trim()
        Scope           = switch -Regex ($Fields[4].Trim()) { '^User$' { 'user'; break } '^System$|^Machine$' { 'machine'; break } default { $null } }
        RawScope        = $Fields[4].Trim()
        Source          = 'SET_PERFORM_ENVIRONMENT_OP'
      })
  }
  return $Result.ToArray()
}

function ConvertTo-QSetupRegistryEvidence {
  <#
  .SYNOPSIS
    Convert explicit QSetup ARP and association directives to registry evidence
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Scope
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  .PARAMETER InstallLocation
    Manifest-safe installation directory resolved from QSetup aliases.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [AllowNull()][string]$Scope,
    [AllowNull()][string]$InstallLocation
  )

  $Root = if ($Scope -eq 'machine') { 'HKLM' } elseif ($Scope -eq 'user') { 'HKCU' } else { $null }
  $ClassRoot = $Root ? $Root : 'HKCR'
  $Writes = [System.Collections.Generic.List[object]]::new()
  $DisplayName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME' -FallbackName 'SET_PROG_NAME'
  # An ARP entry exists only when both uninstall generation and Add/Remove
  # registration are enabled. The official manual defines the program name as
  # the fallback when the optional ARP display-name field is empty.
  $WritesArp = $Root -and (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_CREATE_UNINSTALL') -and
  (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS') -and $DisplayName
  if ($WritesArp) {
    $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$DisplayName"
    $UninstallName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_UNINSTALL_EXE_NAME'
    if ($UninstallName -and -not [IO.Path]::HasExtension($UninstallName)) { $UninstallName += '.exe' }
    $UninstallString = $InstallLocation -and $UninstallName ? ($InstallLocation.TrimEnd('\') + '\' + $UninstallName) : $null
    $DisplayIcon = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_ICON'
    if ($DisplayIcon) { $DisplayIcon = ConvertTo-QSetupManifestPath -Value $DisplayIcon -Directive $Directive }
    foreach ($Value in @(
        @{ Name = 'DisplayName'; Value = $DisplayName },
        @{ Name = 'DisplayVersion'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_VERSION' },
        @{ Name = 'Publisher'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_NAME' },
        @{ Name = 'InstallLocation'; Value = $InstallLocation },
        @{ Name = 'UninstallString'; Value = $UninstallString },
        @{ Name = 'DisplayIcon'; Value = $DisplayIcon },
        @{ Name = 'HelpLink'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_HELP_LINK' },
        @{ Name = 'URLUpdateInfo'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_UPDATE_INFO_URL' }
      )) {
      if ($null -ne $Value.Value) { $Writes.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = $Value.Name; Value = $Value.Value; Type = 'REG_SZ' }) }
    }
  }

  # Association records are pipe-delimited structured directives. Emit only
  # literal, syntactically valid extensions and their explicit ProgID command.
  foreach ($Association in @($Directive['SET_ADD_ASSOCIATION_ITEM'])) {
    $Fields = @($Association -split '\|')
    if ($Fields.Count -lt 7) { continue }
    $ProgId = $Fields[1].Trim()
    $Description = $Fields[2].Trim()
    $Extension = $Fields[3].Trim()
    $Executable = ConvertTo-QSetupManifestPath -Value $Fields[5].Trim() -Directive $Directive
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]*$' -or [string]::IsNullOrWhiteSpace($ProgId)) { continue }
    if ($Fields.Count -gt 8 -and $Fields[8].Trim() -and $Fields[8].Trim() -notmatch '^(?i:Create|1|True)$') { continue }
    $Writes.Add([pscustomobject]@{ Root = $ClassRoot; Key = "Software\Classes\$Extension"; Name = $null; Value = $ProgId; Type = 'REG_SZ' })
    $Writes.Add([pscustomobject]@{ Root = $ClassRoot; Key = "Software\Classes\$ProgId"; Name = $null; Value = $Description; Type = 'REG_SZ' })
    if ($Executable) {
      $Parameters = $Fields.Count -gt 10 ? $Fields[10].Trim() : $null
      $Command = "`"$Executable`""
      if ($Parameters) { $Command += " $Parameters" }
      $Writes.Add([pscustomobject]@{ Root = $ClassRoot; Key = "Software\Classes\$ProgId\shell\open\command"; Name = $null; Value = $Command; Type = 'REG_SZ' })
    }
    $Icon = ConvertTo-QSetupManifestPath -Value $Fields[6].Trim() -Directive $Directive
    if ($Icon) {
      $IconNumber = $Fields[7].Trim()
      $IconValue = $IconNumber ? "$Icon,$IconNumber" : $Icon
      $Writes.Add([pscustomobject]@{ Root = $ClassRoot; Key = "Software\Classes\$ProgId\DefaultIcon"; Name = $null; Value = $IconValue; Type = 'REG_SZ' })
    }
  }
  return $Writes.ToArray()
}

function Get-QSetupInfo {
  <#
  .SYNOPSIS
    Read QSetup project, ARP, scope, architecture, and association metadata
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Source = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Layout = Get-QSetupLayout -Stream $Source
      # Setup.txt is the authoritative project metadata record. Generic payload
      # strings never participate in identity, scope, or ARP inference.
      $SetupRecord = $Layout.Records | Where-Object Name -ieq 'Setup.txt' | Select-Object -First 1
      if (-not $SetupRecord) { throw 'The QSetup package does not contain Setup.txt in its parsed records' }
      $SetupData = Read-QSetupRecord -Stream $Source -Offset $SetupRecord.Offset -ReadContent -MaximumContentBytes $Script:QSetupMaximumConfigurationBytes -EndOffset $Layout.DataEndOffset
    } finally {
      $Source.Dispose()
    }
    $SetupText = [Text.Encoding]::UTF8.GetString($SetupData.Content).TrimStart([char]0, [char]0xFEFF)
    $DirectiveRecord = @(Get-QSetupDirectiveRecord -Content $SetupText)
    $Directive = ConvertFrom-QSetupDirectiveText -Content $SetupText
    if (-not $Directive.ContainsKey('SET_COMPOSER_BUILD')) { throw 'The Setup.txt record does not contain QSetup composer evidence' }
    $ExecutionActionInfo = Get-QSetupExecutionActionInfo -Directive $Directive
    $PayloadCatalog = @(Get-QSetupPayloadCatalog -DirectiveRecord $DirectiveRecord -Directive $Directive -Record $Layout.Records)
    $Shortcuts = @(Get-QSetupShortcutInfo -Directive $Directive)
    $EnvironmentChanges = @(Get-QSetupEnvironmentChange -Directive $Directive)

    $DisplayName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME' -FallbackName 'SET_PROG_NAME'
    $DisplayVersion = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_PROG_VERSION'
    $Publisher = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_COMPANY_NAME'
    $InstallLocation = ConvertTo-QSetupManifestPath -Value (Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_TARGET_DIR') -Directive $Directive
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName

    # Explicit current/all-user directives win. Newer launchers also carry an
    # authoritative UAC manifest; machine-only destinations are secondary evidence.
    $Scope = if ($Directive.ContainsKey('SET_ALL_USERS')) {
      'machine'
    } elseif ($Directive.ContainsKey('SET_CURRENT_USER')) {
      'user'
    } elseif ($RequestedExecutionLevel -eq 'requireAdministrator') {
      'machine'
    } elseif ($InstallLocation -match '^%(?:LOCALAPPDATA|APPDATA|USERPROFILE)%') {
      'user'
    } elseif ($InstallLocation -match '^%(?:ProgramFiles|CommonProgramFiles|ProgramData|WINDIR)%') {
      'machine'
    } else {
      $null
    }
    $ScopeEvidence = if ($Directive.ContainsKey('SET_ALL_USERS')) {
      'SET_ALL_USERS'
    } elseif ($Directive.ContainsKey('SET_CURRENT_USER')) {
      'SET_CURRENT_USER'
    } elseif ($RequestedExecutionLevel -eq 'requireAdministrator') {
      'PE requestedExecutionLevel=requireAdministrator'
    } elseif ($Scope) {
      'Resolved installation destination'
    } else {
      $null
    }

    $WritesAppsAndFeaturesEntry = (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_CREATE_UNINSTALL') -and
    (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS') -and
    -not [string]::IsNullOrWhiteSpace($DisplayName)
    $ProductCode = $WritesAppsAndFeaturesEntry ? $DisplayName : $null
    $RegistryWrites = @(ConvertTo-QSetupRegistryEvidence -Directive $Directive -Scope $Scope -InstallLocation $InstallLocation)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $ArpWrites = @($RegistryWrites | Where-Object { $_.Key -match '(?i)\\Uninstall\\' })
    $UninstallString = $ArpWrites | Where-Object Name -ieq 'UninstallString' | Select-Object -Last 1 -ExpandProperty Value
    $DisplayIcon = $ArpWrites | Where-Object Name -ieq 'DisplayIcon' | Select-Object -Last 1 -ExpandProperty Value

    # Allowed OS values describe payload compatibility rather than the PE stub.
    # An exclusively 64-bit set is useful package-architecture evidence; mixed
    # media falls back to the launcher machine until payload PE analysis is added.
    $AllowedOs = [string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ALLOWED_OS')
    $Only64BitOs = $AllowedOs -match '(?i)\.64' -and $AllowedOs -notmatch '(?i)(?:^|,)(?:XP|Vista|7|8|10|11)(?:,|$)'
    $OuterMachine = (Get-PELayout -Path $File.FullName).MachineName
    $OuterArchitecture = switch ($OuterMachine) { 'I386' { 'x86' } 'Amd64' { 'x64' } 'Arm64' { 'arm64' } default { $null } }
    $PackageArchitecture = $Only64BitOs ? 'x64' : $OuterArchitecture
    $SupportedArchitectures = $PackageArchitecture ? @($PackageArchitecture) : @()

    $DialogList = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_DIALOGS'
    $HasUserInformationDialog = $DialogList -match '(?i)User(?:Information|Info)|InformationDlg' -or
    $Directive.ContainsKey('SET_REQUEST_USER_NAME') -or $Directive.ContainsKey('SET_REQUEST_COMPANY_NAME') -or $Directive.ContainsKey('SET_REQUEST_SERIAL_ALSO')
    $SupportsSilentInstallation = -not $HasUserInformationDialog
    $InstallModes = $SupportsSilentInstallation ? @('interactive', 'silent', 'silentWithProgress') : @('interactive')
    $InstallerSwitches = [ordered]@{ InstallLocation = '/InstallDir="<INSTALLPATH>"' }
    if ($SupportsSilentInstallation) {
      $InstallerSwitches['Silent'] = '/hide'
      $InstallerSwitches['SilentWithProgress'] = '/silent'
    }

    $AppsAndFeaturesEntries = @()
    if ($WritesAppsAndFeaturesEntry) {
      $Entry = [ordered]@{}
      foreach ($Property in ([ordered]@{ DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; ProductCode = $ProductCode; InstallerType = 'exe' }).GetEnumerator()) {
        if ($null -ne $Property.Value -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) { $Entry[$Property.Key] = $Property.Value }
      }
      $AppsAndFeaturesEntries = @([pscustomobject]$Entry)
    }

    $Diagnostics = [Collections.Generic.List[object]]::new()
    foreach ($Diagnostic in @($Layout.Diagnostics + $ExecutionActionInfo.Diagnostics + $RegistryAssociationInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $Scope) {
      $UnresolvedFields.Add('Scope')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Scope.Unresolved' -Source QSetup -Message 'QSetup scope is not explicit in structured evidence and requires VM validation.' -Kind Incomplete -Areas Installability, Metadata -AffectedFields Scope))
    }
    if ($WritesAppsAndFeaturesEntry -and -not $UninstallString) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.UninstallString.Dynamic' -Source QSetup -Message 'QSetup will derive its default uninstaller filename at runtime; the ARP ProductCode remains available but UninstallString requires VM evidence.' -Kind Incomplete -Areas Metadata -AffectedFields AppsAndFeaturesEntries))
    }
    if ($HasUserInformationDialog) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Silent.UserInformationDialog' -Source QSetup -Message 'The compiled User Information dialog disables QSetup /silent and /hide behavior.' -Kind Unsupported -Areas Installability -AffectedFields InstallModes, InstallerSwitches))
    }
    if ($ExecutionActionInfo.Actions.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.ExecutionActions.Present' -Source QSetup -Message "QSetup defines $($ExecutionActionInfo.Actions.Count) structured execution action(s); review ExecutionActions and ExecutedPayloads for prerequisites and side effects." -Kind Information -Areas Installability))
    }
    if (@($PayloadCatalog | Where-Object { -not $_.InstalledPath }).Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.PayloadPath.Unresolved' -Source QSetup -Message 'One or more payload destinations contain unresolved QSetup aliases.' -Kind Incomplete -Areas Extraction -AffectedFields ExtractedFiles))
    }

    $DotNetRequirementText = [string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_DOT_NET_FRAMEWORK_REQ_VER')
    $DotNetRequirements = @($DotNetRequirementText.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object Trim | Where-Object { $_ })
    $MsiCodes = @(([string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_MSI_CODES')).Split('|', [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' })

    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $InstallLocation
      WritesAppsAndFeaturesEntry   = [bool]$WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())

      UnresolvedFields             = [string[]]$UnresolvedFields.ToArray()
      Family                       = 'QSetup'
      PublisherUrl                 = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_URL'
      ProjectName                  = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROJECT_NAME'
      ProjectStamp                 = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PC_STAMP'
      ComposerBuild                = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPOSER_BUILD'
      MainExecutable               = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_EXE_NAME'
      SupportedScopes              = if ($Scope) { @($Scope) } else { @() }
      SupportedArchitectures       = $SupportedArchitectures
      PackageArchitecture          = $PackageArchitecture
      OuterArchitecture            = $OuterArchitecture
      AllowedOperatingSystems      = $AllowedOs
      RequestedExecutionLevel      = $RequestedExecutionLevel
      ElevationRequirement         = $RequestedExecutionLevel -eq 'requireAdministrator' ? 'elevationRequired' : $null
      ScopeEvidence                = $ScopeEvidence
      InstallModes                 = [string[]]$InstallModes
      InstallerSwitches            = $InstallerSwitches
      SupportsSilentInstallation   = $SupportsSilentInstallation
      HasUserInformationDialog     = $HasUserInformationDialog
      AppsAndFeaturesEntries       = [object[]]$AppsAndFeaturesEntries
      InstallLocation              = $InstallLocation
      UninstallString              = $UninstallString
      QuietUninstallString         = $null
      DisplayIcon                  = $DisplayIcon
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      Shortcuts                    = [object[]]$Shortcuts
      EnvironmentChanges           = [object[]]$EnvironmentChanges
      RegistryOperations           = [object[]]@($Directive.Keys | Where-Object { $_ -match 'REGISTRY.*(?:ITEM|OP)$' } | ForEach-Object { $Directive[$_] })
      IniFileOperations            = [object[]]@($Directive['SET_PERFORM_INI_OP'])
      XmlOperations                = [object[]]@($Directive['SET_PERFORM_XML_OP'])
      Records                      = @($Layout.Records | Select-Object Name, Required, Stamp, Offset, CompressedLength)
      PayloadCatalog               = [object[]]$PayloadCatalog
      ExtractedFiles               = @($PayloadCatalog | ForEach-Object { $_.InstalledPath ? $_.InstalledPath : $_.InstalledName })
      CanExpand                    = [bool]$Layout.Complete
      ExecutionActions             = [object[]]$ExecutionActionInfo.Actions
      ExecutedPayloads             = [object[]]$ExecutionActionInfo.ExecutedPayloads
      PackageFooter                = $Layout.Footer
      Certificate                  = $Layout.Certificate
      FormatGeneration             = $Layout.FormatGeneration
      StructuralRoutes             = $Layout.StructuralRoutes
      SetupDirectives              = $Directive
      DirectiveRecords             = [object[]]$DirectiveRecord
      DotNetFrameworkRequirements  = [string[]]$DotNetRequirements
      MsiCodes                     = [string[]]$MsiCodes
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.QSetup'; ParserMajor = 3; FormatCatalogVersion = $Script:QSetupFormatCatalog.CatalogVersion; Sources = @('validated QSetup generation-specific preamble, zlib record, footer, and certificate routes', 'Setup.txt directives and versioned Execution Engine records', 'official QSetup manual defaults') }
    }
  }
}

function Export-QSetupRecord {
  <#
  .SYNOPSIS
    Export one QSetup record body to a validated destination
  .PARAMETER Stream
    Seekable caller-owned installer stream. The function consumes only the bounded record and restores no position.
  .PARAMETER Record
    Current structured format node or record being interpreted.
  .PARAMETER OutputPath
    Fully resolved output path selected by the caller after safe-path and collision handling.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Record,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  $CompressedRange = New-BoundedReadStream -Stream $Stream -Offset ($Record.Offset + 4) -Length $Record.CompressedLength -LeaveOpen
  $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
  try {
    $PipeCount = 0
    $HeaderLength = 0
    # Consume the metadata prefix before exporting the remaining decoded bytes
    # as the actual file body named by the validated catalog record.
    while ($HeaderLength -lt 4096 -and $PipeCount -lt 3) { $Value = $Decoder.ReadByte(); if ($Value -lt 0) { break }; $HeaderLength++; if ($Value -eq 0x7C) { $PipeCount++ } }
    if ($PipeCount -ne 3) { throw 'The QSetup record header is invalid during extraction' }
    if ($Decoder.ReadByte() -ne 0) { throw 'The QSetup record body marker is invalid during extraction' }
    $Parent = [IO.Path]::GetDirectoryName($OutputPath)
    if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
    $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $null = Copy-BoundedStream -Source $Decoder -Destination $Output -MaximumBytes $MaximumBytes
    } finally { $Output.Dispose() }
    return Get-Item -LiteralPath $OutputPath -Force
  } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
}

function Expand-QSetupInstaller {
  <#
  .SYNOPSIS
    Extract QSetup zlib records without executing the installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Optional exact name or wildcard selecting an installed path/file name, or a physical record in RawRecords mode. Omit it to expand all entries.
  .PARAMETER RawRecords
    Export physical QSetup records under _qsetup\records instead of reconstructing installed payload paths.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name,
    [switch]$RawRecords,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Info = Get-QSetupInfo -Path $ResolvedPath
    if (-not $Info.CanExpand) { throw "The QSetup record table is incomplete: $(@($Info.Diagnostics).Message -join '; ')" }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-QSetup-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Pattern = [string]::IsNullOrWhiteSpace($Name) ? '*' : $Name
    $Entries = [Collections.Generic.List[object]]::new()
    if ($RawRecords) {
      foreach ($Record in $Info.Records) {
        $Entries.Add([pscustomobject]@{ Record = $Record; SelectionPath = $Record.Name; RelativePath = Join-Path '_qsetup\records' $Record.Name })
      }
    } else {
      foreach ($Payload in $Info.PayloadCatalog) {
        $RelativePath = ConvertTo-QSetupExtractionPath -Payload $Payload -InstallLocation $Info.DefaultInstallLocation
        $Entries.Add([pscustomobject]@{ Record = $Payload.Record; SelectionPath = $Payload.InstalledPath ? $Payload.InstalledPath : $Payload.InstalledName; RelativePath = $RelativePath })
      }
    }

    $Written = 0L
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Source = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    # Enforce one aggregate output budget across all selected records, not a new
    # full allowance for each independently compressed member.
    try {
      foreach ($Entry in $Entries) {
        if (-not (Test-ExtractionPattern -Path $Entry.SelectionPath -Pattern $Pattern)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.RelativePath `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $Remaining = $MaximumExpandedBytes - $Written
        if ($Remaining -le 0) { throw 'QSetup extraction exceeds the configured output limit' }
        $File = Export-QSetupRecord -Stream $Source -Record $Entry.Record -OutputPath $Target.Path -MaximumBytes $Remaining
        $Written += $File.Length
        $Result.Add($File)
      }
    } finally {
      $Source.Dispose()
    }
    if ($Result.Count -eq 0) { throw "No QSetup extraction entries matched '$Pattern'" }
    return $Result.ToArray()
  }
}

function Test-QSetup {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable QSetup project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-QSetupInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromQSetup {
  <#
  .SYNOPSIS
    Read literal URL protocol names from QSetup registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromQSetup {
  <#
  .SYNOPSIS
    Read literal file extensions from QSetup association directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project display name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromQSetup {
  <#
  .SYNOPSIS
    Read the explicit QSetup Apps & Features key name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).ProductCode }
}

function Read-ScopeFromQSetup {
  <#
  .SYNOPSIS
    Read scope from explicit QSetup all-users/current-user directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-QSetupInfo, Expand-QSetupInstaller, Test-QSetup, Read-ProtocolsFromQSetup, Read-FileExtensionsFromQSetup, Read-ProductVersionFromQSetup, Read-ProductNameFromQSetup, Read-PublisherFromQSetup, Read-ProductCodeFromQSetup, Read-ScopeFromQSetup
