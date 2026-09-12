# SPDX-License-Identifier: Apache-2.0
# Format research: https://gist.github.com/mickael9/0b902da7c13207d1b86e
# Metakit format and X/MIT-licensed reference: https://www.equi4.com/metakit/format.html
# https://github.com/jcw/metakit
# Static BitRock/VMware InstallBuilder parser. InstallBuilder embeds its project
# VFS in a TclKit/Metakit container; this module reads bounded project records
# and CookFS pages but never loads Tcl, TclKit, or the installer executable.
# Binary structure consumed here (CookFS integers are BE):
#
#   PE/TclKit
#   `-- Metakit VFS -> dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]
#       +-- exact project.xml and origindist control records
#       +-- stored/zlib legacy payload records
#       `-- optional CookFS pages -> page-size table (u32 BE)* -> compressed index
#           -> index magic "CFS2.200" -> 16-byte footer -> "CFS0002"
#
# Footer-relative fields are IndexSize@-16, PageCount@-12, and compression@-8.
# CookFS records begin with a compression ID (stored/Deflate/BZip2/custom LZMA).
# Encrypted/custom records are rejected; page/index/count/path limits are enforced.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallBuilderMaximumCandidates = 4096
$Script:InstallBuilderMaximumProjectBytes = 16777216
$Script:InstallBuilderMarkerSearchRadius = 16777216
$Script:InstallBuilderMaximumCookfsIndexBytes = 67108864
$Script:InstallBuilderMaximumCookfsPages = 1000000
$Script:InstallBuilderMaximumCookfsPageBytes = 536870912
$Script:InstallBuilderMaximumCookfsEntries = 200000
$Script:InstallBuilderMaximumMetakitMetadataBytes = 67108864
$Script:InstallBuilderCookfsPageCacheSize = 16
$Script:InstallBuilderCookfsPageCacheBytes = 67108864
$Script:InstallBuilderMaximumLzmaDictionaryBytes = 134217728
$Script:InstallBuilderMaximumDynamicLogicRecords = 4096
$Script:InstallBuilderMaximumPayloadAnalysisBytes = 536870912
$Script:InstallBuilderStrictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$InstallBuilderMetakitSource = Join-Path $PSScriptRoot '..\..\Assets\Source\InstallBuilder\InstallBuilderMetakitReader.cs'
$null = Import-InstallerManagedSource -Path $InstallBuilderMetakitSource -TypeName 'Dumplings.InstallBuilder.InstallBuilderMetakitArchive'
$Script:InstallBuilderProjectDefaults = [ordered]@{
  installationType              = 'normal'
  createUninstaller             = '1'
  createWindowsARPEntry         = '1'
  windowsARPRegistryPrefix      = '${project.fullName} ${project.version}'
  productDisplayName            = '${product_fullname}'
  productDisplayIcon            = ''
  productUrlInfoAbout           = ''
  productComments               = ''
  productContact                = ''
  productUrlHelpLink            = ''
  uninstallerName               = 'uninstall'
  uninstallerDirectory          = '${installdir}'
  requireInstallationByRootUser = '0'
  requestedExecutionLevel       = 'requireAdministrator'
  windows64bitMode              = '0'
  installationScope             = 'auto'
  unattendedModeUI              = 'none'
}

function Get-InstallBuilderCandidateOffset {
  <#
  .SYNOPSIS
    Return plausible zlib stream offsets near an embedded project.xml record
  .DESCRIPTION
    Metakit stores VFS file names and compressed payloads separately. The
    project.xml name is a stable nearby anchor; a full-file fallback supports
    layouts that place its compressed record elsewhere in the container.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([long[]])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $ProjectMarker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  # InstallBuilder uses the maximum RFC 1950 window size. Search complete valid CMF/FLG pairs
  # instead of every 0x78 byte: old, UPX-packed runtimes can contain thousands of incidental
  # 0x78 values before project.xml, which would otherwise exhaust the candidate bound first.
  $ZlibHeaders = @(
    [byte[]](0x78, 0x01),
    [byte[]](0x78, 0x5E),
    [byte[]](0x78, 0x9C),
    [byte[]](0x78, 0xDA)
  )
  $Offsets = [System.Collections.Generic.HashSet[long]]::new()
  # Metakit stores names separately from compressed records. Use each project.xml name as a local
  # search anchor instead of trying every zlib-looking byte in a large payload.
  $ProjectOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $ProjectMarker -Maximum 32 -Reverse)
  foreach ($ProjectOffset in $ProjectOffsets) {
    $StartOffset = [Math]::Max(0, $ProjectOffset - 65536)
    $Length = [Math]::Min($Script:InstallBuilderMarkerSearchRadius, $File.Length - $StartOffset)
    foreach ($Header in $ZlibHeaders) {
      foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Header -StartOffset $StartOffset -Length $Length -Maximum $Script:InstallBuilderMaximumCandidates)) {
        if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
        $null = $Offsets.Add($Offset)
      }
      if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
    }
  }

  # A project record can be outside the nearby VFS-name table in older
  # InstallBuilder releases. Fall back to a bounded whole-file candidate scan.
  if ($Offsets.Count -eq 0) {
    foreach ($Header in $ZlibHeaders) {
      foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Header -Maximum $Script:InstallBuilderMaximumCandidates)) {
        if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
        $null = $Offsets.Add($Offset)
      }
      if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
    }
  }
  return [long[]]@($Offsets | Sort-Object)
}

function Read-InstallBuilderZlibProject {
  <#
  .SYNOPSIS
    Read one bounded zlib record and return project XML when present
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:InstallBuilderMaximumProjectBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Source = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Output = [IO.MemoryStream]::new()
  try {
    # The zlib decoder stops at its own stream end; the output bound prevents an unrelated or
    # malicious candidate from expanding without limit.
    $Range = New-BoundedReadStream -Stream $Source -Offset $Offset -Length ($Source.Length - $Offset) -LeaveOpen
    try { $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $Range -Destination $Output -MaximumBytes $MaximumExpandedBytes }
    finally { $Range.Dispose() }
    $Content = $Script:InstallBuilderStrictUtf8.GetString($Output.ToArray()).TrimStart([char]0xFEFF, [char]0)
    $Start = $Content.IndexOf('<project', [StringComparison]::OrdinalIgnoreCase)
    if ($Start -lt 0) { return $null }
    $EndTag = '</project>'
    $End = $Content.IndexOf($EndTag, $Start, [StringComparison]::OrdinalIgnoreCase)
    if ($End -lt 0) { return $null }
    [pscustomobject]@{ Offset = $Offset; Content = $Content.Substring($Start, $End - $Start + $EndTag.Length); Length = $Output.Length }
  } catch {
    return $null
  } finally {
    $Output.Dispose()
    $Source.Dispose()
  }
}

function Get-InstallBuilderProjectData {
  <#
  .SYNOPSIS
    Locate and decompress the InstallBuilder project XML from a Metakit VFS
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:InstallBuilderMaximumProjectBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Marker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  if (-not @(Find-BinaryPattern -Path $File.FullName -Pattern $Marker -Maximum 1)) {
    throw 'The file does not contain an InstallBuilder project.xml VFS marker'
  }
  # Prefer the catalog-owned project record whenever a real Metakit VFS is present. This proves
  # record ownership and avoids trying unrelated zlib members in the launcher or payload.
  $Layouts = @(Get-InstallBuilderMetakitLayout -Path $File.FullName)
  if ($Layouts.Count) {
    $Archive = $null
    try {
      $Archive = Open-InstallBuilderMetakitArchive -Path $File.FullName -Layout $Layouts -RequiredEntryPath 'project.xml'
      $ProjectEntry = @($Archive.Entries | Where-Object Path -CEQ 'project.xml')
      if ($ProjectEntry.Count -ne 1) { throw 'The InstallBuilder Metakit VFS does not contain one unambiguous project.xml record' }
      $Bytes = $Archive.ReadEntry([int]$ProjectEntry[0].Index, $MaximumExpandedBytes)
      $Content = $Script:InstallBuilderStrictUtf8.GetString($Bytes).TrimStart([char]0xFEFF, [char]0)
      $Start = $Content.IndexOf('<project', [StringComparison]::OrdinalIgnoreCase)
      $EndTag = '</project>'
      $End = $Start -ge 0 ? $Content.IndexOf($EndTag, $Start, [StringComparison]::OrdinalIgnoreCase) : -1
      if ($Start -lt 0 -or $End -lt 0) { throw 'The catalog-owned InstallBuilder project.xml record does not contain a complete project root' }
      $OriginEntry = @($Archive.Entries | Where-Object Path -CEQ 'origindist')
      $OriginDirectory = if ($OriginEntry.Count -eq 1) { $Script:InstallBuilderStrictUtf8.GetString($Archive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim() } else { $null }
      return [pscustomobject]@{
        Offset          = $ProjectEntry[0].Offset
        Content         = $Content.Substring($Start, $End - $Start + $EndTag.Length)
        Length          = $Bytes.Length
        StoredLength    = $ProjectEntry[0].StoredSize
        MetakitLayout   = [pscustomobject][ordered]@{ HeaderOffset = $Archive.HeaderOffset; EndOffset = $Archive.HeaderOffset + $Archive.Length; Length = $Archive.Length; ByteOrder = ($Layouts | Where-Object HeaderOffset -EQ $Archive.HeaderOffset | Select-Object -First 1).ByteOrder; RootPosition = $Archive.RootPosition; RootLength = $Archive.RootLength }
        MetakitLayouts  = $Layouts
        MetakitEntries  = @($Archive.Entries)
        OriginDirectory = $OriginDirectory
      }
    } finally {
      if ($Archive) { $Archive.Dispose() }
    }
  }
  # Accept the first candidate that expands to a complete project root, not merely XML fragments.
  foreach ($Offset in @(Get-InstallBuilderCandidateOffset -Path $File.FullName)) {
    $Project = Read-InstallBuilderZlibProject -Path $File.FullName -Offset $Offset -MaximumExpandedBytes $MaximumExpandedBytes
    if ($Project) { return $Project }
  }
  throw 'The InstallBuilder Metakit VFS contains project.xml but no supported bounded zlib project record was found'
}

function Get-InstallBuilderXmlValue {
  <#
  .SYNOPSIS
    Read one trimmed InstallBuilder project XML value.
  .PARAMETER Xml
    XML node used as the XPath context.
  .PARAMETER XPath
    Relative or absolute XPath identifying the requested scalar node.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Xml.XmlNode]$Xml, [Parameter(Mandatory)][string]$XPath)
  $Node = $Xml.SelectSingleNode($XPath)
  if ($Node) {
    $Value = $Node.InnerText.Trim()
  } elseif ($XPath -match '^[A-Za-z_][A-Za-z0-9_.-]*$' -and $Xml.Attributes) {
    $Value = $Xml.GetAttribute($XPath).Trim()
  } else {
    return $null
  }
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallBuilderMetakitLayout {
  <#
  .SYNOPSIS
    Locate bounded Metakit VFS databases embedded in an InstallBuilder executable.
  .DESCRIPTION
    Metakit stores a big-endian distance from each JL/LJ header to its logical end. The
    database can be embedded inside a PE and may be followed by Authenticode or launcher data.
    This function validates the terminal Metakit commit record before returning a layout.
  .PARAMETER Path
    Path to the installer whose embedded Metakit databases are inspected.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layouts = [Collections.Generic.List[object]]::new()
  foreach ($Magic in @([byte[]](0x4A, 0x4C, 0x1A, 0x00), [byte[]](0x4C, 0x4A, 0x1A, 0x00))) {
    foreach ($HeaderOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Magic -Maximum 32)) {
      if ($HeaderOffset + 8 -gt $File.Length) { continue }
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $Distance = Read-BinaryInteger -Stream $Stream -Offset ($HeaderOffset + 4) -Size 4 -Endian BigEndian
        $EndOffset = $HeaderOffset + [long]$Distance
        if ($Distance -lt 24 -or $EndOffset -gt $Stream.Length) { continue }
        $Footer = Read-BinaryBytes -Stream $Stream -Offset ($EndOffset - 16) -Count 16
        # A committed Metakit database ends with two eight-byte marks. The second mark starts
        # with 0x80 and carries a three-byte root length plus a four-byte root position.
        if ($Footer[8] -ne 0x80) { continue }
        $RootLength = ([uint32]$Footer[9] -shl 16) -bor ([uint32]$Footer[10] -shl 8) -bor [uint32]$Footer[11]
        $RootPosition = ([uint32]$Footer[12] -shl 24) -bor ([uint32]$Footer[13] -shl 16) -bor ([uint32]$Footer[14] -shl 8) -bor [uint32]$Footer[15]
        if ($RootLength -eq 0 -or $RootPosition -ge $Distance -or [long]$RootPosition + $RootLength -gt $Distance) { continue }
        $Layouts.Add([pscustomobject][ordered]@{
            HeaderOffset = [long]$HeaderOffset
            EndOffset    = $EndOffset
            Length       = [long]$Distance
            ByteOrder    = $Magic[0] -eq 0x4A ? 'LittleEndian' : 'BigEndian'
            RootPosition = [long]$RootPosition
            RootLength   = [long]$RootLength
          })
      } finally {
        $Stream.Dispose()
      }
    }
  }
  return [object[]]@($Layouts | Sort-Object HeaderOffset -Unique)
}

function Open-InstallBuilderMetakitArchive {
  <#
  .SYNOPSIS
    Open the first supported legacy InstallBuilder TclKit VFS.
  .PARAMETER Path
    Resolved path to the installer containing the Metakit database.
  .PARAMETER Layout
    Validated Metakit layouts whose header offsets are tried in file order.
  .PARAMETER RequiredEntryPath
    Optional exact catalog path used to select the package-owned VFS when an installer embeds
    multiple valid Metakit databases.
  #>
  [OutputType([Dumplings.InstallBuilder.InstallBuilderMetakitArchive])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$Layout,
    [string]$RequiredEntryPath
  )

  $Failures = [Collections.Generic.List[string]]::new()
  foreach ($Candidate in @($Layout | Sort-Object HeaderOffset)) {
    try {
      $Archive = [Dumplings.InstallBuilder.InstallBuilderMetakitArchive]::Open(
        $Path,
        [long]$Candidate.HeaderOffset,
        $Script:InstallBuilderMaximumCookfsEntries,
        $Script:InstallBuilderMaximumMetakitMetadataBytes
      )
      if ($RequiredEntryPath) {
        $MatchingEntries = @($Archive.Entries | Where-Object Path -CEQ $RequiredEntryPath)
        if ($MatchingEntries.Count -ne 1) {
          $Archive.Dispose()
          $Failures.Add("0x$(([long]$Candidate.HeaderOffset).ToString('X')): expected one '$RequiredEntryPath' entry, found $($MatchingEntries.Count)")
          continue
        }
      }
      return $Archive
    } catch {
      $Failures.Add("0x$(([long]$Candidate.HeaderOffset).ToString('X')): $($_.Exception.Message)")
    }
  }

  throw "No supported InstallBuilder Metakit VFS was found. $($Failures -join '; ')"
}

function Get-InstallBuilderFolderDestinationMap {
  <#
  .SYNOPSIS
    Map compiled component/folder identifiers to paths relative to the installation root.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and resolved installation directory.
  #>
  [OutputType([Collections.Generic.Dictionary[string, object]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in @($Xml.SelectNodes('//componentList/component/folderList/folder'))) {
    $FolderName = Get-InstallBuilderXmlValue -Xml $Folder -XPath 'name'
    $Component = $Folder.ParentNode.ParentNode
    $ComponentName = Get-InstallBuilderXmlValue -Xml $Component -XPath 'name'
    if ([string]::IsNullOrWhiteSpace($FolderName)) { continue }
    $DestinationExpression = Get-InstallBuilderXmlValue -Xml $Folder -XPath 'destination'
    $Destination = Resolve-InstallBuilderProjectValue -Value $DestinationExpression -Variables $Context.Variables
    $LogicalPrefix = $null
    if ($Destination.Value -and $Context.InstallLocation) {
      $NormalizedDestination = $Destination.Value.Replace('\', '/').TrimEnd('/')
      $NormalizedInstallLocation = $Context.InstallLocation.Replace('\', '/').TrimEnd('/')
      if ($NormalizedDestination -ceq $NormalizedInstallLocation) {
        $LogicalPrefix = ''
      } elseif ($NormalizedDestination.StartsWith($NormalizedInstallLocation + '/', [StringComparison]::OrdinalIgnoreCase)) {
        $LogicalPrefix = $NormalizedDestination.Substring($NormalizedInstallLocation.Length + 1)
      }
    }
    if ($null -eq $LogicalPrefix) { $LogicalPrefix = "_destinations/$FolderName" }
    $Condition = Get-InstallBuilderNodeCondition -Node $Folder -Context $Context
    $States = [Collections.Generic.List[string]]::new()
    $Conditions = [Collections.Generic.List[object]]::new()
    $States.Add($Condition.State)
    foreach ($Item in @($Condition.Conditions)) { $Conditions.Add($Item) }

    # Component selection controls the default unattended payload. A literal selected=0 excludes
    # the folder from the default install, while a runtime expression keeps it conditional.
    $SelectedExpression = Get-InstallBuilderXmlValue -Xml $Component -XPath 'selected'
    if ($null -ne $SelectedExpression) {
      $Selected = Resolve-InstallBuilderProjectValue -Value $SelectedExpression -Variables $Context.Variables
      $SelectedState = if ($null -eq $Selected.Value) {
        'Unknown'
      } elseif ($Selected.Value -match '^(?i:1|true|yes)$') {
        'True'
      } elseif ($Selected.Value -match '^(?i:0|false|no)$') {
        'False'
      } else {
        'Unknown'
      }
      $States.Add($SelectedState)
      $SelectedNode = $Component.SelectSingleNode('selected')
      $Conditions.Add([pscustomobject][ordered]@{ Type = 'ComponentSelected'; State = $SelectedState; Xml = $SelectedNode ? $SelectedNode.OuterXml : "selected=$SelectedExpression" })
    }

    # Folder platform lists use inclusive matching. A Windows installer can resolve all/windows
    # immediately; architecture-specific lists remain conditional when an x86 launcher can run on
    # more than one host architecture.
    foreach ($PlatformOwner in @($Component, $Folder)) {
      $PlatformExpression = Get-InstallBuilderXmlValue -Xml $PlatformOwner -XPath 'platforms'
      if ([string]::IsNullOrWhiteSpace($PlatformExpression)) { continue }
      $Platforms = @($PlatformExpression -split '[,;\s]+' | Where-Object { $_ })
      $PlatformState = if ($Platforms -match '^(?i:all|windows)$') {
        'True'
      } elseif ($Context.NativePlatform -and $Platforms -icontains $Context.NativePlatform) {
        'True'
      } elseif (@($Platforms | Where-Object { $_ -match '^(?i:windows-(?:x86|x64|arm64))$' }).Count) {
        $Context.IsNative64Bit ? 'False' : 'Unknown'
      } elseif (@($Platforms | Where-Object { $_ -match '^(?i:linux|linux-.+|osx|osx-.+|freebsd|solaris|aix|hpux)$' }).Count -eq $Platforms.Count) {
        'False'
      } else {
        'Unknown'
      }
      $States.Add($PlatformState)
      $PlatformNode = $PlatformOwner.SelectSingleNode('platforms')
      $Conditions.Add([pscustomobject][ordered]@{ Type = 'PlatformList'; State = $PlatformState; Xml = $PlatformNode ? $PlatformNode.OuterXml : "platforms=$PlatformExpression" })
    }

    $Value = [pscustomobject][ordered]@{
      Prefix         = $LogicalPrefix
      ConditionState = Merge-InstallerConditionState -State $States.ToArray() -Operator All
      Conditions     = $Conditions.ToArray()
      ComponentName  = $ComponentName
      FolderName     = $FolderName
    }
    $Map[$FolderName] = $Value
    if (-not [string]::IsNullOrWhiteSpace($ComponentName)) { $Map["$ComponentName/$FolderName"] = $Value }
  }
  return $Map
}

function Get-InstallBuilderLegacyPayloadEntry {
  <#
  .SYNOPSIS
    Project legacy Metakit dist records into safe logical payload paths.
  .DESCRIPTION
    TclKit stores runtime support beside package files. The root origindist record identifies the
    VFS payload directory, whose first component is the distribution name and second component is
    the compiled project folder name. The folder destination determines whether that internal
    folder name can be removed or must remain under a safe _destinations namespace.
  .PARAMETER Entry
    Complete Metakit VFS catalog returned by the bounded managed reader.
  .PARAMETER Xml
    Parsed InstallBuilder project used to map compiled folder names and destinations.
  .PARAMETER Context
    Resolved project variable and installation-directory context.
  .PARAMETER OriginDirectory
    Root VFS directory read from the structured origindist control record.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$Entry,
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][pscustomobject]$Context,
    [Parameter(Mandatory)][string]$OriginDirectory
  )

  $FolderDestinations = Get-InstallBuilderFolderDestinationMap -Xml $Xml -Context $Context

  $Prefix = $OriginDirectory.Trim('/').Replace('\', '/') + '/'
  $Projected = [Collections.Generic.List[object]]::new()
  foreach ($Item in @($Entry)) {
    if (-not $Item.Path.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $Remainder = $Item.Path.Substring($Prefix.Length)
    $Separator = $Remainder.IndexOf('/')
    if ($Separator -le 0 -or $Separator -eq $Remainder.Length - 1) { continue }
    $DistributionRemainder = $Remainder.Substring($Separator + 1)
    $FolderSeparator = $DistributionRemainder.IndexOf('/')
    if ($FolderSeparator -le 0 -or $FolderSeparator -eq $DistributionRemainder.Length - 1) { continue }
    $FolderName = $DistributionRemainder.Substring(0, $FolderSeparator)
    $RelativePath = $DistributionRemainder.Substring($FolderSeparator + 1)
    $FolderMapping = $FolderDestinations.ContainsKey($FolderName) ? $FolderDestinations[$FolderName] : $null
    $LogicalPrefix = $FolderMapping ? $FolderMapping.Prefix : "_destinations/$FolderName"
    $LogicalPath = [string]::IsNullOrEmpty($LogicalPrefix) ? $RelativePath : "$LogicalPrefix/$RelativePath"
    $Projected.Add([pscustomobject][ordered]@{
        Index               = $Item.Index
        Path                = $LogicalPath
        PhysicalPath        = $Item.Path
        Size                = $Item.Size
        StoredSize          = $Item.StoredSize
        Compression         = $Item.Compression
        ModifiedUnixSeconds = $Item.ModifiedUnixSeconds
        ConditionState      = $FolderMapping ? $FolderMapping.ConditionState : 'Unknown'
        Conditions          = $FolderMapping ? $FolderMapping.Conditions : @()
      })
  }

  # A malformed project can map two physical sources to one install path. Preserve both records
  # under their internal folder names rather than allowing extraction order to choose a winner.
  $DuplicatePaths = @($Projected | Group-Object Path | Where-Object Count -GT 1 | Select-Object -ExpandProperty Name)
  if ($DuplicatePaths.Count) {
    $DuplicateSet = [Collections.Generic.HashSet[string]]::new([string[]]$DuplicatePaths, [StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $Projected) {
      if (-not $DuplicateSet.Contains($Item.Path)) { continue }
      $Remainder = $Item.PhysicalPath.Substring($Prefix.Length)
      $Item.Path = "_destinations/$Remainder"
    }
  }
  return $Projected.ToArray()
}

function Get-InstallBuilderProjectProperty {
  <#
  .SYNOPSIS
    Read an explicit InstallBuilder project property or its documented default.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Name
    Case-sensitive project property name.
  .PARAMETER NoDefault
    Return null rather than applying a documented runtime default.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$Name,
    [switch]$NoDefault
  )

  $Value = Get-InstallBuilderXmlValue -Xml $Xml -XPath "/project/$Name"
  if ($null -ne $Value -or $NoDefault) { return $Value }
  if ($Script:InstallBuilderProjectDefaults.Contains($Name)) { return [string]$Script:InstallBuilderProjectDefaults[$Name] }
  return $null
}

function Test-InstallBuilderTrueValue {
  <#
  .SYNOPSIS
    Interpret the literal Boolean spellings accepted by InstallBuilder projects.
  .PARAMETER Value
    Literal XML property value. Dynamic expressions are not treated as true.
  #>
  [OutputType([bool])]
  param ([AllowNull()][string]$Value)
  return $Value -match '^(?i:1|true|yes)$'
}

function Resolve-InstallBuilderProjectValue {
  <#
  .SYNOPSIS
    Expand deterministic InstallBuilder project and product variables.
  .PARAMETER Value
    Project expression to resolve.
  .PARAMETER Variables
    Case-insensitive dictionary of source-backed variable values.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.Generic.Dictionary[string, string]]$Variables
  )

  if ($null -eq $Value) { return [pscustomobject]@{ Value = $null; UnresolvedVariables = @() } }
  $Resolved = $Value
  $Unresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  # InstallBuilder substitutions can be nested. Resolve only values already proven by project or PE
  # metadata, and leave Tcl expressions and runtime state unresolved.
  for ($Pass = 0; $Pass -lt 16; $Pass++) {
    $Before = $Resolved
    # Work from distinct matches rather than a callback so variable lookup remains in the current
    # PowerShell scope and ScriptAnalyzer can verify that the dictionary parameter is consumed.
    foreach ($Match in @([regex]::Matches($Resolved, '\$\{(?<Name>[^{}]+)\}'))) {
      $Name = $Match.Groups['Name'].Value
      if ($Variables.ContainsKey($Name) -and $null -ne $Variables[$Name]) {
        $Resolved = $Resolved.Replace($Match.Value, $Variables[$Name])
      } else {
        $null = $Unresolved.Add($Name)
      }
    }
    if ($Resolved -ceq $Before) { break }
  }
  foreach ($Match in [regex]::Matches($Resolved, '\$\{(?<Name>[^{}]+)\}')) { $null = $Unresolved.Add($Match.Groups['Name'].Value) }
  [pscustomobject]@{
    Value               = $Unresolved.Count -eq 0 ? $Resolved : $null
    UnresolvedVariables = [string[]]@($Unresolved | Sort-Object)
  }
}

function Get-InstallBuilderProjectContext {
  <#
  .SYNOPSIS
    Build deterministic variable, platform, and execution-level evidence once.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Path
    Resolved Windows installer path used for PE evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][xml]$Xml, [Parameter(Mandatory)][string]$Path)

  $Layout = try { Get-PELayout -Path $Path } catch { $null }
  $RequestedExecutionLevel = try { Get-PERequestedExecutionLevel -Path $Path } catch { $null }
  if ([string]::IsNullOrWhiteSpace($RequestedExecutionLevel)) {
    $RequestedExecutionLevel = Get-InstallBuilderProjectProperty -Xml $Xml -Name requestedExecutionLevel
  }
  $Windows64BitMode = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name windows64bitMode)
  $IsNative64Bit = $Layout -and $Layout.MachineName -in 'AMD64', 'ARM64', 'IA64'
  $NativePlatform = switch ($Layout.MachineName) {
    'AMD64' { 'windows-x64' }
    'ARM64' { 'windows-arm64' }
    'I386' { 'windows-x86' }
    default { $null }
  }
  $ProgramFiles = ($IsNative64Bit -or $Windows64BitMode) ? '%ProgramFiles%' : '%ProgramFiles(x86)%'
  $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ShortName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/shortName'
  $FullName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/fullName'
  $Version = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/version'
  $Vendor = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/vendor'
  foreach ($Pair in @(
      @('project.shortName', $ShortName), @('project.fullName', $FullName), @('project.version', $Version), @('project.vendor', $Vendor),
      @('product_shortname', $ShortName), @('product_fullname', $FullName), @('product_version', $Version),
      @('platform_install_prefix', $ProgramFiles), @('platform_name', 'windows'), @('platform', 'windows'),
      # Resolve stable Windows folder variables to manifest-safe environment forms. User-specific
      # shell folders retain environment variables rather than embedding the parser host's paths.
      @('windows_folder_program_files', $ProgramFiles),
      @('windows_folder_program_files_common', (($IsNative64Bit -or $Windows64BitMode) ? '%CommonProgramFiles%' : '%CommonProgramFiles(x86)%')),
      @('windows_folder_windows', '%SystemRoot%'), @('windows_folder_systemroot', '%SystemRoot%'), @('windows_folder_system', '%SystemRoot%\System32'),
      @('windows_folder_appdata', '%APPDATA%'), @('windows_folder_local_appdata', '%LOCALAPPDATA%'),
      @('windows_folder_common_appdata', '%ProgramData%'), @('user_home_directory', '%USERPROFILE%'),
      @('windows_folder_personal', '%USERPROFILE%\Documents'), @('windows_folder_desktopdirectory', '%USERPROFILE%\Desktop'),
      @('windows_folder_profile', '%USERPROFILE%'), @('windows_folder_favorites', '%USERPROFILE%\Favorites'),
      @('windows_folder_mymusic', '%USERPROFILE%\Music'), @('windows_folder_mypictures', '%USERPROFILE%\Pictures'),
      @('windows_folder_myvideo', '%USERPROFILE%\Videos'), @('windows_folder_admintools', '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'),
      @('windows_folder_nethood', '%APPDATA%\Microsoft\Windows\Network Shortcuts'), @('windows_folder_printhood', '%APPDATA%\Microsoft\Windows\Printer Shortcuts'),
      @('windows_folder_programs', '%APPDATA%\Microsoft\Windows\Start Menu\Programs'), @('windows_folder_recent', '%APPDATA%\Microsoft\Windows\Recent'),
      @('windows_folder_sendto', '%APPDATA%\Microsoft\Windows\SendTo'), @('windows_folder_startmenu', '%APPDATA%\Microsoft\Windows\Start Menu'),
      @('windows_folder_startup', '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'), @('windows_folder_templates', '%APPDATA%\Microsoft\Windows\Templates'),
      @('windows_folder_common_admintools', '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'),
      @('windows_folder_common_desktopdirectory', '%PUBLIC%\Desktop'), @('windows_folder_common_documents', '%PUBLIC%\Documents'),
      @('windows_folder_common_music', '%PUBLIC%\Music'), @('windows_folder_common_pictures', '%PUBLIC%\Pictures'),
      @('windows_folder_common_programs', '%ProgramData%\Microsoft\Windows\Start Menu\Programs'),
      @('windows_folder_common_startmenu', '%ProgramData%\Microsoft\Windows\Start Menu'),
      @('windows_folder_common_startup', '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
      @('windows_folder_common_templates', '%ProgramData%\Microsoft\Windows\Templates'), @('windows_folder_common_video', '%PUBLIC%\Videos')
    )) { if ($null -ne $Pair[1]) { $Variables[$Pair[0]] = [string]$Pair[1] } }

  # The install directory parameter uses value first and default only when value is empty.
  $Upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  $Lower = 'abcdefghijklmnopqrstuvwxyz'
  $InstallParameter = $Xml.SelectSingleNode("//directoryParameter[translate(normalize-space(name),'$Upper','$Lower')='installdir' or translate(@name,'$Upper','$Lower')='installdir']")
  $InstallExpression = if ($InstallParameter) {
    (Get-InstallBuilderXmlValue -Xml $InstallParameter -XPath 'value'), (Get-InstallBuilderXmlValue -Xml $InstallParameter -XPath 'default') | Where-Object { $null -ne $_ } | Select-Object -First 1
  } else { $null }
  $InstallLocationResult = Resolve-InstallBuilderProjectValue -Value $InstallExpression -Variables $Variables
  $InstallLocation = if ($InstallLocationResult.Value) { $InstallLocationResult.Value.Replace('/', '\') } else { $null }
  if ($InstallLocation) { $Variables['installdir'] = $InstallLocation }

  # These project variables are consumed by the built-in Windows ARP writer and by project
  # actions. Resolve them after installdir because uninstallerDirectory defaults to it.
  $UninstallerName = Get-InstallBuilderProjectProperty -Xml $Xml -Name uninstallerName
  $UninstallerDirectoryResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name uninstallerDirectory) -Variables $Variables
  if ($UninstallerName) {
    $Variables['project.uninstallerName'] = $UninstallerName
    $Variables['uninstallerName'] = $UninstallerName
  }
  if ($UninstallerDirectoryResult.Value) {
    $Variables['project.uninstallerDirectory'] = $UninstallerDirectoryResult.Value
    $Variables['uninstallerDirectory'] = $UninstallerDirectoryResult.Value
  }

  [pscustomobject]@{
    Layout                     = $Layout
    RequestedExecutionLevel    = $RequestedExecutionLevel
    IsNative64Bit              = [bool]$IsNative64Bit
    NativePlatform             = $NativePlatform
    Windows64BitMode           = $Windows64BitMode
    RegistryView               = ($IsNative64Bit -or $Windows64BitMode) ? '64-bit' : '32-bit'
    Variables                  = $Variables
    InstallParameter           = $InstallParameter
    InstallLocation            = $InstallLocation
    InstallLocationResult      = $InstallLocationResult
    UninstallerName            = $UninstallerName
    UninstallerDirectory       = $UninstallerDirectoryResult.Value
    UninstallerDirectoryResult = $UninstallerDirectoryResult
  }
}

function Resolve-InstallBuilderRuleState {
  <#
  .SYNOPSIS
    Evaluate the small source-backed subset of InstallBuilder rules needed for static evidence.
  .PARAMETER Rule
    One compiled rule node. Rules that depend on host state or arbitrary Tcl remain Unknown.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Rule,
    [Parameter(Mandatory)]$Context
  )

  $State = 'Unknown'
  $Detail = $Rule.OuterXml
  switch ($Rule.LocalName) {
    'isTrue' {
      $Result = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      if ($null -ne $Result.Value) { $State = (Test-InstallBuilderTrueValue $Result.Value) ? 'True' : 'False' }
    }
    'isFalse' {
      $Result = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      if ($null -ne $Result.Value) { $State = (Test-InstallBuilderTrueValue $Result.Value) ? 'False' : 'True' }
    }
    'compareText' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ([string]::IsNullOrWhiteSpace($Logic)) { $Logic = 'equals' }
      $NoCase = Test-InstallBuilderTrueValue ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'nocase') ?? $Rule.GetAttribute('nocase'))
      if ($null -ne $Left.Value -and $null -ne $Right.Value) {
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = ($NoCase ? ($Left.Value -ieq $Right.Value) : ($Left.Value -ceq $Right.Value)) ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = ($NoCase ? ($Left.Value -ine $Right.Value) : ($Left.Value -cne $Right.Value)) ? 'True' : 'False' }
          '^(?i:contains)$' { $State = $Left.Value.IndexOf($Right.Value, ($NoCase ? [StringComparison]::OrdinalIgnoreCase : [StringComparison]::Ordinal)) -ge 0 ? 'True' : 'False' }
          '^(?i:does_not_contain)$' { $State = $Left.Value.IndexOf($Right.Value, ($NoCase ? [StringComparison]::OrdinalIgnoreCase : [StringComparison]::Ordinal)) -lt 0 ? 'True' : 'False' }
        }
      }
    }
    'compareTextLength' {
      $Text = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $LengthText = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'length') ?? $Rule.GetAttribute('length')) -Variables $Context.Variables
      $ExpectedLength = 0L
      if ($null -ne $Text.Value -and $null -ne $LengthText.Value -and [long]::TryParse($LengthText.Value, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ExpectedLength)) {
        $Comparison = [long]$Text.Value.Length - $ExpectedLength
        $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'compareValues' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value1') ?? $Rule.GetAttribute('value1')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value2') ?? $Rule.GetAttribute('value2')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ($null -ne $Left.Value -and $null -ne $Right.Value) {
        $LeftNumber = 0.0
        $RightNumber = 0.0
        $HasNumbers = [double]::TryParse($Left.Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$LeftNumber) -and [double]::TryParse($Right.Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$RightNumber)
        $Comparison = $HasNumbers ? $LeftNumber.CompareTo($RightNumber) : [string]::CompareOrdinal($Left.Value, $Right.Value)
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'compareVersions' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version1') ?? $Rule.GetAttribute('version1')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version2') ?? $Rule.GetAttribute('version2')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      $LeftVersion = $null
      $RightVersion = $null
      if ($null -ne $Left.Value -and $null -ne $Right.Value -and [version]::TryParse($Left.Value, [ref]$LeftVersion) -and [version]::TryParse($Right.Value, [ref]$RightVersion)) {
        $Comparison = $LeftVersion.CompareTo($RightVersion)
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'platformTest' {
      $Platform = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'type') ?? $Rule.GetAttribute('type')
      if ($Platform -match '^(?i:all|windows)$') { $State = 'True' }
      elseif ($Platform -in 'windows-x64', 'windows-arm64') {
        # A native 64-bit launcher proves its own required platform. An x86 launcher can run on
        # several Windows architectures, so target-architecture rules remain runtime-dependent.
        $State = $Context.IsNative64Bit ? ($Platform -ieq $Context.NativePlatform ? 'True' : 'False') : 'Unknown'
      } elseif ($Platform -ieq 'windows-x86') {
        $State = $Context.IsNative64Bit ? 'False' : 'Unknown'
      } elseif ($Platform -match '^(?i:unix|linux|linux-.+|osx|osx-.+|freebsd|freebsd.+|openbsd|openbsd.+|solaris|solaris-.+|aix|hpux|hpux-.+|irix|irix-.+)$') { $State = 'False' }
    }
    'regExMatch' {
      $Text = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $Pattern = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'pattern') ?? $Rule.GetAttribute('pattern')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ([string]::IsNullOrWhiteSpace($Logic)) { $Logic = 'matches' }
      # Tcl and .NET regular expressions overlap for ordinary literals, anchors, groups, and
      # character classes. Leave Tcl-specific constructs unresolved instead of changing meaning.
      if ($null -ne $Text.Value -and $null -ne $Pattern.Value -and $Pattern.Value -notmatch '\[\[:|\\[mMyYAQEZ]|\(\?[a-z-]+\)') {
        try {
          $Matched = [regex]::IsMatch($Text.Value, $Pattern.Value, [Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromMilliseconds(250))
          if ($Logic -match '^(?i:matches)$') { $State = $Matched ? 'True' : 'False' }
          elseif ($Logic -match '^(?i:does_not_match)$') { $State = $Matched ? 'False' : 'True' }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
          $State = 'Unknown'
        } catch [ArgumentException] {
          $State = 'Unknown'
        }
      }
    }
    'ruleGroup' {
      $Nested = Resolve-InstallBuilderRuleList -RuleList $Rule.SelectSingleNode('ruleList') -Owner $Rule -Context $Context
      $State = $Nested.State
    }
  }
  if (Test-InstallBuilderTrueValue ($Rule.GetAttribute('negate'))) {
    $State = $State -eq 'True' ? 'False' : ($State -eq 'False' ? 'True' : 'Unknown')
  }
  [pscustomobject][ordered]@{ Type = $Rule.LocalName; State = $State; Xml = $Detail }
}

function Resolve-InstallBuilderRuleList {
  <#
  .SYNOPSIS
    Combine one InstallBuilder rule list using its documented and/or evaluation logic.
  .PARAMETER RuleList
    ruleList or conditionRuleList node. A missing or empty list is true.
  .PARAMETER Owner
    Element that owns the rule list and its evaluation-logic property.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][System.Xml.XmlNode]$RuleList,
    [Parameter(Mandatory)][System.Xml.XmlNode]$Owner,
    [Parameter(Mandatory)]$Context
  )

  if (-not $RuleList -or $RuleList.ChildNodes.Count -eq 0) { return [pscustomobject]@{ State = 'True'; Conditions = @() } }
  $Conditions = [Collections.Generic.List[object]]::new()
  foreach ($Rule in @($RuleList.ChildNodes | Where-Object NodeType -EQ Element)) {
    $Conditions.Add((Resolve-InstallBuilderRuleState -Rule $Rule -Context $Context))
  }
  # InstallBuilder 3.x called this property ruleLogic; later schemas renamed it to
  # ruleEvaluationLogic, while if/while containers may use conditionRuleEvaluationLogic.
  $Logic = (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'ruleEvaluationLogic') ?? (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'conditionRuleEvaluationLogic') ?? (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'ruleLogic') ?? $Owner.GetAttribute('ruleEvaluationLogic') ?? $Owner.GetAttribute('ruleLogic')
  $Operator = $Logic -ieq 'or' ? 'Any' : 'All'
  [pscustomobject]@{
    State      = Merge-InstallerConditionState -State @($Conditions.State) -Operator $Operator
    Conditions = $Conditions.ToArray()
  }
}

function Get-InstallBuilderNodeCondition {
  <#
  .SYNOPSIS
    Resolve direct and inherited conditions that govern one compiled project node.
  .PARAMETER Node
    Action, shortcut, folder, or component whose ancestor rule lists are inspected.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
    [Parameter(Mandatory)]$Context
  )

  $States = [Collections.Generic.List[string]]::new()
  $Conditions = [Collections.Generic.List[object]]::new()
  $Current = $Node
  while ($Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document) {
    $List = $Current.SelectSingleNode('ruleList')
    if ($List) {
      $Result = Resolve-InstallBuilderRuleList -RuleList $List -Owner $Current -Context $Context
      $States.Add($Result.State)
      foreach ($Condition in @($Result.Conditions)) { $Conditions.Add($Condition) }
    }

    # Actions nested under an if/else inherit the conditionRuleList even though that list is a
    # sibling of actionList rather than a direct ancestor of the action itself.
    if ($Current.LocalName -in 'actionList', 'elseActionList' -and $Current.ParentNode.LocalName -in 'if', 'while') {
      $Owner = $Current.ParentNode
      $Result = Resolve-InstallBuilderRuleList -RuleList $Owner.SelectSingleNode('conditionRuleList') -Owner $Owner -Context $Context
      $State = $Result.State
      if ($Current.LocalName -eq 'elseActionList') { $State = $State -eq 'True' ? 'False' : ($State -eq 'False' ? 'True' : 'Unknown') }
      $States.Add($State)
      foreach ($Condition in @($Result.Conditions)) { $Conditions.Add($Condition) }
    }
    $Current = $Current.ParentNode
  }
  [pscustomobject]@{
    State      = Merge-InstallerConditionState -State $States.ToArray() -Operator All
    Conditions = $Conditions.ToArray()
  }
}

function Get-InstallBuilderRegistryWrite {
  <#
  .SYNOPSIS
    Read literal registrySet actions from an InstallBuilder project
  .PARAMETER Xml
    Parsed format configuration used to resolve static installer metadata and payload selection.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )
  # Registry metadata is returned only from literal project actions; Tcl substitutions remain
  # unresolved strings for downstream manual review.
  foreach ($Action in @($Xml.SelectNodes('//registrySet'))) {
    $RawKey = Get-InstallBuilderXmlValue -Xml $Action -XPath 'key'
    if ([string]::IsNullOrWhiteSpace($RawKey)) { continue }
    $RawValue = Get-InstallBuilderXmlValue -Xml $Action -XPath 'value'
    $KeyResult = Resolve-InstallBuilderProjectValue -Value $RawKey -Variables $Context.Variables
    $ValueResult = Resolve-InstallBuilderProjectValue -Value $RawValue -Variables $Context.Variables
    $ResolvedRawKey = $KeyResult.Value
    $RootSource = $ResolvedRawKey ?? $RawKey
    $Root = if ($RootSource -match '^HKEY_LOCAL_MACHINE|^HKLM') { 'HKLM' } elseif ($RootSource -match '^HKEY_CURRENT_USER|^HKCU') { 'HKCU' } elseif ($RootSource -match '^HKEY_CLASSES_ROOT|^HKCR') { 'HKCR' } else { $null }
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $StripRoot = { param([string]$Key) $Key -replace '^HKEY_LOCAL_MACHINE\\?', '' -replace '^HKLM\\?', '' -replace '^HKEY_CURRENT_USER\\?', '' -replace '^HKCU\\?', '' -replace '^HKEY_CLASSES_ROOT\\?', '' -replace '^HKCR\\?', '' }
    [pscustomobject]@{
      Root                = $Root
      Key                 = & $StripRoot $RawKey
      RawKey              = $RawKey
      ResolvedKey         = $ResolvedRawKey ? (& $StripRoot $ResolvedRawKey) : $null
      ResolvedRawKey      = $ResolvedRawKey
      Name                = Get-InstallBuilderXmlValue -Xml $Action -XPath 'name'
      Value               = $RawValue
      ResolvedValue       = $ValueResult.Value
      Type                = Get-InstallBuilderXmlValue -Xml $Action -XPath 'type'
      WowMode             = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'wowMode') ?? $Action.GetAttribute('wowMode')
      Phase               = $Phase
      Lifecycle           = Get-InstallBuilderActionLifecycle -Phase $Phase
      UnresolvedVariables = [string[]]@($KeyResult.UnresolvedVariables + $ValueResult.UnresolvedVariables | Sort-Object -Unique)
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      IsConditional       = $Condition.State -ne 'True'
    }
  }
}

function Get-InstallBuilderScopeInfo {
  <#
  .SYNOPSIS
    Derive scope evidence from structured InstallBuilder project settings.
  .PARAMETER Xml
    Parsed project.xml document.
  .PARAMETER Context
    Resolved installation path and PE elevation evidence.
  .PARAMETER ArpInfo
    Reconstructed built-in and custom uninstall registrations.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$ArpInfo
  )
  $DefiniteHives = @($ArpInfo.Entries | Where-Object ConditionState -EQ 'True' | ForEach-Object RegistryHive | Where-Object { $_ } | Select-Object -Unique)
  $PossibleHives = @($ArpInfo.Entries | Where-Object ConditionState -EQ 'Unknown' | ForEach-Object RegistryHive | Where-Object { $_ } | Select-Object -Unique)
  if ($DefiniteHives.Count -eq 1 -and -not $PossibleHives.Count) {
    $Scope = $DefiniteHives[0] -eq 'HKCU' ? 'user' : 'machine'
    return [pscustomobject]@{ Scope = $Scope; SupportedScopes = @($Scope); Confidence = 'high'; Evidence = "The compiled uninstall registration writes $($DefiniteHives[0])." }
  }
  $AllHives = @($DefiniteHives + $PossibleHives | Select-Object -Unique)
  if ($AllHives -contains 'HKLM' -and $AllHives -contains 'HKCU') {
    return [pscustomobject]@{ Scope = $null; SupportedScopes = @('user', 'machine'); Confidence = 'medium'; Evidence = 'Compiled uninstall registrations can target both HKCU and HKLM under runtime conditions.' }
  }
  $RequireAdministrator = Get-InstallBuilderProjectProperty -Xml $Xml -Name requireInstallationByRootUser
  if (Test-InstallBuilderTrueValue $RequireAdministrator) {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'high'; Evidence = 'requireInstallationByRootUser=1' }
  }
  if ($Context.RequestedExecutionLevel -ieq 'requireAdministrator') {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'high'; Evidence = 'PE requestedExecutionLevel=requireAdministrator' }
  }
  if ($Context.InstallLocation -match '^%(?i:ProgramFiles|ProgramFiles\(x86\))%') {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'medium'; Evidence = 'The resolved default destination is under Program Files.' }
  }
  return [pscustomobject]@{ Scope = $null; SupportedScopes = @(); Confidence = 'unknown'; Evidence = 'InstallBuilder project does not contain statically provable uninstall scope evidence.' }
}

function Read-InstallBuilderBigEndianUInt32 {
  <#
  .SYNOPSIS
    Read a bounded unsigned 32-bit integer from a CookFS byte buffer
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Position
    Current record position or zero-based index within the validated table.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position)
  if ($Position.Value -lt 0 -or $Position.Value + 4 -gt $Bytes.Length) { throw 'The CookFS index is truncated while reading an integer' }
  $Offset = $Position.Value
  $Position.Value += 4
  return ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
}

function Skip-InstallBuilderCookfsByteRange {
  <#
  .SYNOPSIS
    Advance a CookFS index cursor across one validated byte range.
  .PARAMETER Bytes
    Complete expanded CookFS index byte array.
  .PARAMETER Position
    Mutable record-relative cursor. It is advanced by Count on success.
  .PARAMETER Count
    Number of bytes to skip. Negative or out-of-range values throw.
  #>
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position, [Parameter(Mandatory)][int]$Count)
  if ($Count -lt 0 -or $Position.Value + $Count -gt $Bytes.Length) { throw 'The CookFS index is truncated while reading an entry' }
  $Position.Value += $Count
}

function Expand-InstallBuilderCookfsRecord {
  <#
  .SYNOPSIS
    Decompress one CookFS stored page or index record
  .PARAMETER StoredBytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][byte[]]$StoredBytes,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($StoredBytes.Length -eq 0) { throw 'The CookFS stored record is empty' }
  # CookFS prepends a one-byte handler ID to every index/page record. Handler 255 is accepted only
  # when the following bytes form InstallBuilder's unencrypted LZMA-alone record.
  $CompressionId = $StoredBytes[0]
  if ($CompressionId -notin 0, 1, 2, 255) { throw "The CookFS record uses unknown compression identifier $CompressionId" }
  if ($CompressionId -eq 0) {
    if ($StoredBytes.Length - 1 -gt $MaximumExpandedBytes) { throw 'The CookFS uncompressed record exceeds the configured output limit' }
    $Result = [byte[]]::new($StoredBytes.Length - 1)
    if ($Result.Length) { [Array]::Copy($StoredBytes, 1, $Result, 0, $Result.Length) }
    return , $Result
  }
  if ($CompressionId -eq 2 -and $StoredBytes.Length -lt 5) { throw 'The CookFS BZip2 record is truncated' }
  [long]$ExpectedLength = -1
  if ($CompressionId -eq 255) {
    # InstallBuilder's unencrypted custom CookFS handler is lzmadec. Its stored
    # page is the CookFS marker followed by an LZMA-alone header and payload.
    if ($StoredBytes.Length -lt 14 -or $StoredBytes[1] -gt 224) { throw 'The CookFS custom record is unsupported or encrypted' }
    $DictionarySize = [BitConverter]::ToUInt32($StoredBytes, 2)
    if ($DictionarySize -eq 0 -or $DictionarySize -gt $Script:InstallBuilderMaximumLzmaDictionaryBytes) { throw 'The CookFS LZMA dictionary size is invalid or exceeds the configured limit' }
    $ExpectedLength = [BitConverter]::ToInt64($StoredBytes, 6)
    if ($ExpectedLength -lt 0 -or $ExpectedLength -gt $MaximumExpandedBytes) { throw 'The CookFS LZMA record output size is invalid or exceeds the configured limit' }
  }

  # BZip2 carries a four-byte CookFS prefix; custom LZMA carries properties and expected length.
  $PayloadOffset = if ($CompressionId -eq 2) { 5 } elseif ($CompressionId -eq 255) { 14 } else { 1 }
  $InputStream = [IO.MemoryStream]::new($StoredBytes, $PayloadOffset, $StoredBytes.Length - $PayloadOffset, $false)
  $Output = [IO.MemoryStream]::new()
  try {
    $ExpandArguments = @{ Stream = $InputStream; Destination = $Output; MaximumBytes = $MaximumExpandedBytes }
    switch ($CompressionId) {
      1 { $ExpandArguments.Algorithm = 'Deflate' }
      2 { $ExpandArguments.Algorithm = 'BZip2' }
      255 {
        $ExpandArguments.Algorithm = 'Lzma'
        $ExpandArguments.Properties = [byte[]]$StoredBytes[1..5]
        $ExpandArguments.CompressedSize = $StoredBytes.Length - $PayloadOffset
        $ExpandArguments.UncompressedSize = $ExpectedLength
      }
    }
    $null = Expand-InstallerCompressedStream @ExpandArguments
    return , ($Output.ToArray())
  } finally {
    $Output.Dispose()
    $InputStream.Dispose()
  }
}

function Test-InstallBuilderCookfsLzmaRecord {
  <#
  .SYNOPSIS
    Test whether a custom CookFS page is the unencrypted InstallBuilder LZMA form
  .PARAMETER StoredBytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][byte[]]$StoredBytes)
  if ($StoredBytes.Length -lt 14 -or $StoredBytes[0] -ne 255 -or $StoredBytes[1] -gt 224) { return $false }
  $DictionarySize = [BitConverter]::ToUInt32($StoredBytes, 2)
  $ExpectedLength = [BitConverter]::ToInt64($StoredBytes, 6)
  return $DictionarySize -gt 0 -and $DictionarySize -le $Script:InstallBuilderMaximumLzmaDictionaryBytes -and $ExpectedLength -ge 0 -and $ExpectedLength -le $Script:InstallBuilderMaximumCookfsPageBytes
}

function Read-InstallBuilderCookfsIndexNode {
  <#
  .SYNOPSIS
    Recursively decode one CookFS CFS2.200 directory node.
  .PARAMETER Bytes
    Complete expanded CookFS index bytes; all record offsets are relative to this array.
  .PARAMETER Position
    Mutable big-endian index cursor advanced through the node and its children.
  .PARAMETER Prefix
    Already validated logical parent path for child names.
  .PARAMETER Entry
    Caller-owned typed collection receiving decoded file records.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Position,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Prefix,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Entry
  )

  # Directory nodes are recursive lists. A sentinel block count denotes a child directory; normal
  # entries contain page/offset/length triples.
  $ItemCount = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
  if ($ItemCount -gt $Script:InstallBuilderMaximumCookfsEntries -or $Entry.Count + $ItemCount -gt $Script:InstallBuilderMaximumCookfsEntries) { throw 'The CookFS index exceeds the configured entry-count limit' }
  for ($ItemIndex = 0; $ItemIndex -lt $ItemCount; $ItemIndex++) {
    if ($Position.Value -ge $Bytes.Length) { throw 'The CookFS index is truncated while reading a file name' }
    $NameLength = [int]$Bytes[$Position.Value]
    $Position.Value++
    if ($NameLength -eq 0 -or $Position.Value + $NameLength + 1 -gt $Bytes.Length) { throw 'The CookFS index contains an invalid file name' }
    $Name = [Text.Encoding]::UTF8.GetString($Bytes, $Position.Value, $NameLength)
    $Position.Value += $NameLength
    if ($Bytes[$Position.Value] -ne 0) { throw 'The CookFS index file name is not null terminated' }
    $Position.Value++
    if ($Name.IndexOf([char]0) -ge 0 -or $Name.IndexOfAny([char[]]@('/', '\', ':')) -ge 0 -or $Name -in '.', '..') { throw 'The CookFS index contains an unsafe file name' }
    Skip-InstallBuilderCookfsByteRange -Bytes $Bytes -Position $Position -Count 8 # mtime
    $BlockCount = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
    $RelativePath = if ([string]::IsNullOrEmpty($Prefix)) { $Name } else { "$Prefix/$Name" }
    if ($BlockCount -eq [uint32]::MaxValue) {
      # Descend only after the child name has passed path-component validation.
      Read-InstallBuilderCookfsIndexNode -Bytes $Bytes -Position $Position -Prefix $RelativePath -Entry $Entry
      continue
    }
    if ($BlockCount -gt 1048576 -or $BlockCount * 12 -gt $Bytes.Length - $Position.Value) { throw 'The CookFS index contains an invalid block list' }
    $Blocks = [System.Collections.Generic.List[object]]::new()
    [long]$Length = 0
    for ($BlockIndex = 0; $BlockIndex -lt $BlockCount; $BlockIndex++) {
      $Page = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Offset = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Size = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Length += $Size
      if ($Length -gt [long]::MaxValue -or $Size -gt $Script:InstallBuilderMaximumCookfsPageBytes) { throw 'The CookFS index contains an oversized file block' }
      $Blocks.Add([pscustomobject]@{ Page = $Page; Offset = $Offset; Length = $Size })
    }
    $Entry.Add([pscustomobject]@{ Path = $RelativePath; Length = $Length; Blocks = $Blocks.ToArray() })
  }
}

function Get-InstallBuilderCookfsInfo {
  <#
  .SYNOPSIS
    Parse the unencrypted CookFS page and file index embedded in an installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $FooterMarker = [Text.Encoding]::ASCII.GetBytes('CFS0002')
  $Markers = @(Find-BinaryPattern -Path $File.FullName -Pattern $FooterMarker -Maximum 32 -Reverse)
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($MarkerOffset in $Markers) {
      $EndOffset = $MarkerOffset + $FooterMarker.Length
      if ($EndOffset -lt 16 -or $EndOffset -gt $Stream.Length) { continue }
      try {
        $IndexSize = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 16) -Size 4 -Endian BigEndian
        $PageCount = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 12) -Size 4 -Endian BigEndian
        $IndexCompression = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 8) -Size 1
        if ($IndexSize -le 0 -or $IndexSize -gt $Script:InstallBuilderMaximumCookfsIndexBytes -or $PageCount -gt $Script:InstallBuilderMaximumCookfsPages) { continue }
        $IndexOffset = $EndOffset - 16 - [long]$IndexSize - ([long]$PageCount * 20)
        if ($IndexOffset -lt 0) { continue }
        $SizeOffset = $IndexOffset + ([long]$PageCount * 16)
        $StoredIndexOffset = $SizeOffset + ([long]$PageCount * 4)
        if ($StoredIndexOffset + $IndexSize -gt $EndOffset - 16) { continue }
        $PageSizes = [long[]]::new($PageCount)
        $PageOffsets = [long[]]::new($PageCount)
        for ($Index = 0; $Index -lt $PageCount; $Index++) {
          $PageSizes[$Index] = Read-BinaryInteger -Stream $Stream -Offset ($SizeOffset + ($Index * 4)) -Size 4 -Endian BigEndian
          if ($PageSizes[$Index] -le 0 -or $PageSizes[$Index] -gt $Script:InstallBuilderMaximumCookfsPageBytes) { throw 'The CookFS page table contains an invalid page size' }
        }
        # The page table follows all stored page bytes, so derive the page-data
        # start by walking backward from the index area after validating totals.
        $PageDataStart = $IndexOffset
        for ($Index = $PageCount - 1; $Index -ge 0; $Index--) { $PageDataStart -= $PageSizes[$Index] }
        if ($PageDataStart -lt 0) { throw 'The CookFS page data starts before the file' }
        $Cursor = $PageDataStart
        for ($Index = 0; $Index -lt $PageCount; $Index++) { $PageOffsets[$Index] = $Cursor; $Cursor += $PageSizes[$Index] }
        if ($Cursor -ne $IndexOffset) { throw 'The CookFS page data size does not match the index offset' }
        $StoredIndex = Read-BinaryBytes -Stream $Stream -Offset $StoredIndexOffset -Count ([int]$IndexSize)
        if ($StoredIndex[0] -ne $IndexCompression) { throw 'The CookFS footer compression identifier does not match the stored index' }
        $IndexData = Expand-InstallBuilderCookfsRecord -StoredBytes $StoredIndex -MaximumExpandedBytes $Script:InstallBuilderMaximumCookfsIndexBytes
        if ($IndexData.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($IndexData, 0, 8) -ne 'CFS2.200') { throw 'The CookFS file index signature is invalid' }
        $Position = 8
        $Entries = [System.Collections.Generic.List[object]]::new()
        Read-InstallBuilderCookfsIndexNode -Bytes $IndexData -Position ([ref]$Position) -Prefix '' -Entry $Entries
        $CompressionIds = [System.Collections.Generic.HashSet[int]]::new()
        $CompressionTypes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $HasUnsupportedCompression = $false
        for ($Index = 0; $Index -lt $PageCount; $Index++) {
          $HeaderLength = [Math]::Min(14, $PageSizes[$Index])
          $PageHeader = Read-BinaryBytes -Stream $Stream -Offset $PageOffsets[$Index] -Count ([int]$HeaderLength)
          $CompressionId = [int]$PageHeader[0]
          $null = $CompressionIds.Add($CompressionId)
          switch ($CompressionId) {
            0 { $null = $CompressionTypes.Add('None') }
            1 { $null = $CompressionTypes.Add('Deflate') }
            2 { $null = $CompressionTypes.Add('BZip2') }
            255 {
              if (Test-InstallBuilderCookfsLzmaRecord -StoredBytes $PageHeader) { $null = $CompressionTypes.Add('Lzma') } else { $null = $CompressionTypes.Add('Custom'); $HasUnsupportedCompression = $true }
            }
            default { $null = $CompressionTypes.Add("Unknown:$CompressionId"); $HasUnsupportedCompression = $true }
          }
        }
        return [pscustomobject]@{
          EndOffset                 = $EndOffset
          IndexOffset               = $IndexOffset
          PageDataOffset            = $PageDataStart
          PageCount                 = $PageCount
          IndexSize                 = $IndexSize
          CompressionIds            = @($CompressionIds | Sort-Object)
          CompressionTypes          = @($CompressionTypes | Sort-Object)
          HasUnsupportedCompression = $HasUnsupportedCompression
          PageSizes                 = $PageSizes
          PageOffsets               = $PageOffsets
          Entries                   = $Entries.ToArray()
          PageCache                 = [System.Collections.Generic.Dictionary[int, byte[]]]::new()
          PageCacheOrder            = [System.Collections.Generic.Queue[int]]::new()
          PageCacheBytes            = 0L
        }
      } catch {
        continue
      }
    }
  } finally {
    $Stream.Dispose()
  }
  throw 'The file does not contain a supported CookFS CFS0002 footer and file index'
}

function Get-InstallBuilderCookfsPage {
  <#
  .SYNOPSIS
    Decode one bounded CookFS page and retain a small in-memory cache
  .PARAMETER Stream
    Caller-owned installer stream. The function seeks but does not dispose it.
  .PARAMETER Cookfs
    Validated CookFS layout containing page offsets, stored sizes, and the bounded page cache owned by the caller.
  .PARAMETER Page
    Current structured format node or record being interpreted.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)]$Cookfs, [Parameter(Mandatory)][uint32]$Page)
  if ($Page -ge $Cookfs.PageCount) { throw "The CookFS file index references missing page $Page" }
  # Pages are shared by many files. Reuse a bounded FIFO cache to avoid repeated decompression
  # without retaining an unbounded portion of a large installer.
  if ($Cookfs.PageCache.ContainsKey([int]$Page)) { return , $Cookfs.PageCache[[int]$Page] }
  $StoredPage = Read-BinaryBytes -Stream $Stream -Offset $Cookfs.PageOffsets[$Page] -Count ([int]$Cookfs.PageSizes[$Page])
  $PageBytes = Expand-InstallBuilderCookfsRecord -StoredBytes $StoredPage -MaximumExpandedBytes $Script:InstallBuilderMaximumCookfsPageBytes
  while ($Cookfs.PageCacheOrder.Count -gt 0 -and (
      $Cookfs.PageCacheOrder.Count -ge $Script:InstallBuilderCookfsPageCacheSize -or
      $Cookfs.PageCacheBytes + $PageBytes.Length -gt $Script:InstallBuilderCookfsPageCacheBytes
    )) {
    $ExpiredPage = $Cookfs.PageCacheOrder.Dequeue()
    $Cookfs.PageCacheBytes -= $Cookfs.PageCache[$ExpiredPage].Length
    $null = $Cookfs.PageCache.Remove($ExpiredPage)
  }
  if ($PageBytes.Length -le $Script:InstallBuilderCookfsPageCacheBytes) {
    $Cookfs.PageCache[[int]$Page] = $PageBytes
    $Cookfs.PageCacheOrder.Enqueue([int]$Page)
    $Cookfs.PageCacheBytes += $PageBytes.Length
  }
  return , $PageBytes
}

function Get-InstallBuilderCookfsLogicalEntry {
  <#
  .SYNOPSIS
    Merge BitRock ___bitrockBigFileN physical segments into logical files
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Xml
    Parsed project document used to translate component/folder storage prefixes.
  .PARAMETER Context
    Resolved project variables and installation directory.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$Entry,
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )
  $Physical = @{}
  foreach ($Item in $Entry) { $Physical[$Item.Path] = $Item }
  $FolderMap = Get-InstallBuilderFolderDestinationMap -Xml $Xml -Context $Context
  $StoragePrefixes = @($FolderMap.Keys | Where-Object { $_ -match '/' } | Sort-Object Length -Descending)
  $Logical = [System.Collections.Generic.List[object]]::new()
  # BitRock splits large logical files into numbered physical CookFS entries. Only a base entry
  # starts a logical file; consecutive numbered suffixes are appended in order.
  foreach ($Item in $Entry) {
    $Match = [regex]::Match($Item.Path, '^(?<Base>.+)___bitrockBigFile(?<Index>[1-9][0-9]*)$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($Match.Success) { continue }
    $Segments = [System.Collections.Generic.List[object]]::new()
    $Segments.Add($Item)
    $PartIndex = 1
    while ($Physical.ContainsKey("$($Item.Path)___bitrockBigFile$PartIndex")) {
      $Segments.Add($Physical["$($Item.Path)___bitrockBigFile$PartIndex"])
      $PartIndex++
    }
    $PhysicalPath = $Item.Path
    $LogicalPath = $PhysicalPath
    $Mapping = $null
    foreach ($StoragePrefix in $StoragePrefixes) {
      if ($PhysicalPath.StartsWith($StoragePrefix + '/', [StringComparison]::OrdinalIgnoreCase)) {
        $Mapping = $FolderMap[$StoragePrefix]
        $Remainder = $PhysicalPath.Substring($StoragePrefix.Length + 1)
        $LogicalPath = [string]::IsNullOrEmpty($Mapping.Prefix) ? $Remainder : "$($Mapping.Prefix)/$Remainder"
        break
      }
    }
    $Logical.Add([pscustomobject][ordered]@{
        Path           = $LogicalPath
        PhysicalPath   = $PhysicalPath
        Length         = [long](@($Segments | Measure-Object -Property Length -Sum).Sum)
        Segments       = $Segments.ToArray()
        ConditionState = $Mapping ? $Mapping.ConditionState : 'Unknown'
        Conditions     = $Mapping ? $Mapping.Conditions : @()
      })
  }
  $DuplicatePaths = @($Logical | Group-Object Path | Where-Object Count -GT 1 | Select-Object -ExpandProperty Name)
  if ($DuplicatePaths.Count) {
    $DuplicateSet = [Collections.Generic.HashSet[string]]::new([string[]]$DuplicatePaths, [StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $Logical) {
      if ($DuplicateSet.Contains($Item.Path)) { $Item.Path = "_destinations/$($Item.PhysicalPath)" }
    }
  }
  return $Logical.ToArray()
}

function Copy-InstallBuilderCookfsEntry {
  <#
  .SYNOPSIS
    Copy one logical CookFS file to an output stream with output limits
  .PARAMETER Stream
    Caller-owned installer stream. The function seeks but does not dispose it.
  .PARAMETER Cookfs
    Validated CookFS layout used to resolve and decode each physical page referenced by the logical file.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Destination
    Caller-owned output stream. The function writes sequential file bytes and does not dispose the stream.
  .PARAMETER TotalWritten
    Mutable cumulative output-byte counter used to enforce the extraction limit.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)]$Cookfs,
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][ref]$TotalWritten,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )
  # Reassemble segments block-by-block from decoded pages while maintaining one operation-wide
  # output counter.
  foreach ($Segment in $Entry.Segments) {
    foreach ($Block in $Segment.Blocks) {
      $Page = Get-InstallBuilderCookfsPage -Stream $Stream -Cookfs $Cookfs -Page $Block.Page
      if ([long]$Block.Offset + [long]$Block.Length -gt $Page.Length) { throw "The CookFS block for '$($Entry.Path)' exceeds its decoded page" }
      if ($TotalWritten.Value + $Block.Length -gt $MaximumExpandedBytes) { throw 'InstallBuilder extraction exceeds the configured output limit' }
      $Destination.Write($Page, [int]$Block.Offset, [int]$Block.Length)
      $TotalWritten.Value += $Block.Length
    }
  }
}

function Export-InstallBuilderPayloadSelection {
  <#
  .SYNOPSIS
    Materialize an already parsed InstallBuilder payload selection for static analysis.
  .PARAMETER Path
    Resolved installer path that owns the parsed payload records.
  .PARAMETER Entry
    Logical CookFS or legacy Metakit entries selected by exact logical path.
  .PARAMETER Cookfs
    Parsed CookFS layout, or null for legacy Metakit media.
  .PARAMETER MetakitLayouts
    Validated Metakit layouts used to reopen the package-owned legacy VFS.
  .PARAMETER DestinationPath
    Empty temporary directory receiving the selected logical files.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit for the selected analysis files.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$Entry,
    [AllowNull()][object]$Cookfs,
    [AllowNull()][object[]]$MetakitLayouts,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Result = [Collections.Generic.List[IO.FileInfo]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [long]$TotalWritten = 0
  if ($Cookfs) {
    $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      foreach ($Item in $Entry) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.Path -CollisionAction Rename -ReservedPath $ReservedPaths
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
        $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-InstallBuilderCookfsEntry -Stream $Source -Cookfs $Cookfs -Entry $Item -Destination $Output -TotalWritten ([ref]$TotalWritten) -MaximumExpandedBytes $MaximumExpandedBytes }
        finally { $Output.Dispose() }
        $Result.Add((Get-Item -LiteralPath $Target.Path -Force))
      }
    } finally { $Source.Dispose() }
    return $Result.ToArray()
  }

  $Archive = Open-InstallBuilderMetakitArchive -Path $Path -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
  try {
    foreach ($Item in $Entry) {
      if ($Item.Compression -eq 'Unknown') { throw "The legacy Metakit payload '$($Item.PhysicalPath)' uses unsupported compression framing" }
      if ($TotalWritten -gt $MaximumExpandedBytes - [long]$Item.Size) { throw 'InstallBuilder payload analysis exceeds the configured output limit' }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.Path -CollisionAction Rename -ReservedPath $ReservedPaths
      $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
      $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $TotalWritten += $Archive.CopyEntry([int]$Item.Index, $Output, $MaximumExpandedBytes - $TotalWritten) }
      finally { $Output.Dispose() }
      $Result.Add((Get-Item -LiteralPath $Target.Path -Force))
    }
  } finally { $Archive.Dispose() }
  return $Result.ToArray()
}

function Get-InstallBuilderPrimaryPayloadAnalysis {
  <#
  .SYNOPSIS
    Analyze source-referenced installed executables and bounded adjacent sidecars.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Payload
    Logical payload catalog produced by the current top-level parse.
  .PARAMETER PrimaryExecutableCandidate
    Logical executable paths referenced by shortcuts or execution actions.
  .PARAMETER Cookfs
    Parsed CookFS layout, or null for legacy Metakit media.
  .PARAMETER MetakitLayouts
    Validated Metakit layouts used for legacy selected extraction.
  .PARAMETER MaximumAnalysisBytes
    Maximum aggregate bytes materialized for architecture and dependency analysis.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()][object[]]$Payload,
    [AllowNull()][string[]]$PrimaryExecutableCandidate,
    [AllowNull()][object]$Cookfs,
    [AllowNull()][object[]]$MetakitLayouts,
    [ValidateRange(1048576, [long]::MaxValue)][long]$MaximumAnalysisBytes = $Script:InstallBuilderMaximumPayloadAnalysisBytes
  )

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $DefaultPayload = @($Payload | Where-Object ConditionState -EQ 'True')
  $Primary = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in @($PrimaryExecutableCandidate | Select-Object -Unique)) {
    $Match = @($DefaultPayload | Where-Object Path -CEQ $Candidate)
    if ($Match.Count -eq 1) { $Primary.Add($Match[0]) }
  }
  if ($Primary.Count -eq 0) {
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = @() }
  }
  if ($Primary.Count -gt 4) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.PrimaryExecutableLimit' -Source InstallBuilder -Message 'Only the first four source-referenced primary executables were inspected.' -Kind Information -Areas Metadata -AffectedFields @('Architecture', 'Dependencies') -Evidence ([pscustomobject]@{ CandidateCount = $Primary.Count; Limit = 4 })))
    $Primary = [Collections.Generic.List[object]]@($Primary | Select-Object -First 4)
  }

  $Selected = [Collections.Generic.List[object]]::new()
  $SelectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [long]$SelectedBytes = 0
  foreach ($Item in $Primary) {
    $ItemLength = $Item.PSObject.Properties['Length'] ? [long]$Item.Length : [long]$Item.Size
    if ($SelectedBytes -gt $MaximumAnalysisBytes - $ItemLength) { continue }
    if ($SelectedPaths.Add([string]$Item.Path)) { $Selected.Add($Item); $SelectedBytes += $ItemLength }
    $Directory = [IO.Path]::GetDirectoryName(([string]$Item.Path).Replace('/', '\'))
    foreach ($Related in @($DefaultPayload | Where-Object {
          $RelatedPath = ([string]$_.Path).Replace('/', '\')
          [IO.Path]::GetDirectoryName($RelatedPath) -ieq $Directory -and $RelatedPath -match '(?i)\.(?:dll|deps\.json|runtimeconfig\.json)$'
        } | Select-Object -First 64)) {
      $RelatedLength = $Related.PSObject.Properties['Length'] ? [long]$Related.Length : [long]$Related.Size
      if ($SelectedBytes -gt $MaximumAnalysisBytes - $RelatedLength) { break }
      if ($SelectedPaths.Add([string]$Related.Path)) { $Selected.Add($Related); $SelectedBytes += $RelatedLength }
    }
  }
  if ($Selected.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.AnalysisLimit' -Source InstallBuilder -Message 'The source-referenced primary executable payloads exceed the configured static-analysis limit.' -Kind Unsupported -Areas Metadata -AffectedFields @('Architecture', 'Dependencies') -Evidence ([pscustomobject]@{ MaximumAnalysisBytes = $MaximumAnalysisBytes })))
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  }

  $TemporaryDirectory = New-TempFolder
  try {
    $Files = @(Export-InstallBuilderPayloadSelection -Path $Path -Entry $Selected.ToArray() -Cookfs $Cookfs -MetakitLayouts $MetakitLayouts -DestinationPath $TemporaryDirectory -MaximumExpandedBytes $MaximumAnalysisBytes)
    $ArchitectureInfo = [Collections.Generic.List[object]]::new()
    $DependencyInfo = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Primary) {
      if (-not $SelectedPaths.Contains([string]$Item.Path)) { continue }
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Item.Path)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -ne 1) { continue }
      $Directory = $PrimaryFile[0].DirectoryName
      $RelatedFiles = @($Files | Where-Object { $_.FullName -cne $PrimaryFile[0].FullName -and $_.DirectoryName -ieq $Directory })
      try {
        $ArchitectureInfo.Add((Get-PEArchitectureInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Where-Object Extension -IEQ '.dll' | Select-Object -ExpandProperty FullName)))
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.ArchitectureUnavailable' -Source InstallBuilder -Message "Payload architecture analysis failed for '$($Item.Path)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
      }
      try {
        $DependencyInfo.Add((Get-PEDependencyInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Select-Object -ExpandProperty FullName)))
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.DependenciesUnavailable' -Source InstallBuilder -Message "Payload dependency analysis failed for '$($Item.Path)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
      }
    }
    foreach ($Child in @($ArchitectureInfo) + @($DependencyInfo)) {
      foreach ($Diagnostic in @($Child.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    return [pscustomobject]@{
      ArchitectureInfo = $ArchitectureInfo.ToArray()
      Architectures    = [string[]]@($ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
      DependencyInfo   = $DependencyInfo.ToArray()
      InspectedFiles   = [string[]]@($Selected.Path)
      Diagnostics      = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-InstallBuilderActionPhase {
  param ([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

  $Current = $Node.ParentNode
  while ($Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document) {
    if ($Current.LocalName -cmatch 'ActionList$' -and $Current.LocalName -notin 'actionList', 'elseActionList') { return $Current.LocalName }
    $Current = $Current.ParentNode
  }
  return 'actionList'
}

function Get-InstallBuilderActionLifecycle {
  <#
  .SYNOPSIS
    Classify an InstallBuilder action-list name by the runtime phase that owns its effects.
  .PARAMETER Phase
    Compiled action-list element name returned by Get-InstallBuilderActionPhase.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Phase)

  # Only persistent installation phases may contribute authoritative installed-state evidence.
  # Startup, page, failure, rollback, and uninstall actions remain useful raw evidence but do not
  # describe the state produced by a successful default installation.
  if ($Phase -in 'readyToInstallActionList', 'preInstallationActionList', 'postInstallationActionList', 'postUninstallerCreationActionList') { return 'Installation' }
  if ($Phase -match '(?i)uninstall') { return 'Uninstallation' }
  if ($Phase -match '(?i)rollback|aborted|cancel|failure|error') { return 'Rollback' }
  if ($Phase -match '(?i)finalPage|preShow|postShow|pageAction') { return 'Presentation' }
  if ($Phase -match '(?i)initialization|startup') { return 'Initialization' }
  return 'Unknown'
}

function Get-InstallBuilderProjectActionInfo {
  <#
  .SYNOPSIS
    Return phase-aware records for every compiled leaf action in an InstallBuilder project.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and inherited-condition evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $ContainerNames = @('actionGroup', 'if', 'while')
  foreach ($Action in @($Xml.SelectNodes('//*') | Where-Object {
        $_.NodeType -eq [Xml.XmlNodeType]::Element -and
        $_.ParentNode -and $_.ParentNode.LocalName -cmatch 'ActionList$' -and
        $_.LocalName -notin $ContainerNames
      })) {
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Properties = [ordered]@{}
    $SensitiveProperties = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Attributes and scalar direct children are the stable compiled action parameters. Nested rule
    # and action lists are represented separately by condition and phase evidence.
    foreach ($Attribute in @($Action.Attributes)) {
      $IsSensitive = $Attribute.LocalName -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
      $Properties[$Attribute.LocalName] = $IsSensitive -and -not [string]::IsNullOrEmpty($Attribute.Value) ? '<redacted>' : $Attribute.Value
      if ($IsSensitive -and -not [string]::IsNullOrEmpty($Attribute.Value)) { $null = $SensitiveProperties.Add($Attribute.LocalName) }
    }
    foreach ($Child in @($Action.ChildNodes | Where-Object NodeType -EQ Element)) {
      if ($Child.LocalName -match '(?i)(?:ActionList|RuleList)$' -or @($Child.ChildNodes | Where-Object NodeType -EQ Element).Count) { continue }
      $Value = $Child.InnerText.Trim()
      $IsSensitive = $Child.LocalName -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
      if ($IsSensitive -and -not [string]::IsNullOrEmpty($Value)) {
        $Value = '<redacted>'
        $null = $SensitiveProperties.Add($Child.LocalName)
      }
      if ($Properties.Contains($Child.LocalName)) {
        $Properties[$Child.LocalName] = @($Properties[$Child.LocalName]) + $Value
      } else {
        $Properties[$Child.LocalName] = $Value
      }
    }

    $ResolvedProperties = [ordered]@{}
    $UnresolvedVariables = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in $Properties.Keys) {
      if ($Properties[$Name] -isnot [string]) { $ResolvedProperties[$Name] = $Properties[$Name]; continue }
      $Resolved = Resolve-InstallBuilderProjectValue -Value $Properties[$Name] -Variables $Context.Variables
      $ResolvedProperties[$Name] = $Resolved.Value
      foreach ($Variable in @($Resolved.UnresolvedVariables)) { $null = $UnresolvedVariables.Add($Variable) }
    }

    $ActionType = $Action.LocalName
    $Category = switch -Regex ($ActionType) {
      '(?i)^registry' { 'Registry'; break }
      '(?i)service' { 'Service'; break }
      '(?i)^(?:download|contactUpdateServer|launchBrowser)$' { 'Network'; break }
      '(?i)^(?:run|execute)' { 'Execution'; break }
      '(?i)environment' { 'Environment'; break }
      '(?i)(?:file|folder|directory|unpack|substitute)' { 'FileSystem'; break }
      '(?i)(?:setInstallerVariable|setVariable|properties|pathManipulation)' { 'Configuration'; break }
      default { 'Other' }
    }
    [pscustomobject][ordered]@{
      ActionType          = $ActionType
      Category            = $Category
      Phase               = $Phase
      Lifecycle           = $Lifecycle
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      Properties          = [pscustomobject]$Properties
      ResolvedProperties  = [pscustomobject]$ResolvedProperties
      UnresolvedVariables = [string[]]@($UnresolvedVariables | Sort-Object)
      SensitiveProperties = [string[]]@($SensitiveProperties | Sort-Object)
    }
  }
}

function Get-InstallBuilderDynamicLogicInfo {
  <#
  .SYNOPSIS
    Collect exact unresolved InstallBuilder expressions and rule source for agent review.
  .DESCRIPTION
    The parser does not execute Tcl or external scripts. This projection returns the source text
    stored in project.xml together with values for referenced deterministic variables, parameter
    defaults, and setInstallerVariable assignments. Password-like values are redacted.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project context used by the bounded static evaluator.
  .PARAMETER ProjectAction
    Phase-aware project actions used to associate variable assignments and affected operations.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowNull()][object[]]$ProjectAction
  )

  $VariableFacts = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $AddVariableFact = {
    param ([string]$Name, [string]$Source, [AllowNull()][string]$Value, [bool]$IsKnown, [bool]$IsRuntimeMutable, [bool]$IsSensitive)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    if (-not $VariableFacts.ContainsKey($Name)) { $VariableFacts[$Name] = [Collections.Generic.List[object]]::new() }
    $VariableFacts[$Name].Add([pscustomobject][ordered]@{
        Name             = $Name
        Source           = $Source
        Value            = $IsSensitive -and $null -ne $Value ? '<redacted>' : $Value
        IsKnown          = $IsKnown
        IsRuntimeMutable = $IsRuntimeMutable
        IsRedacted       = $IsSensitive -and $null -ne $Value
      })
  }

  foreach ($Name in $Context.Variables.Keys) {
    $Sensitive = $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name 'DeterministicProjectContext' $Context.Variables[$Name] $true $false $Sensitive
  }
  foreach ($ParameterNode in @($Xml.SelectNodes('//parameterList//*'))) {
    if ($ParameterNode.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
    $Name = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'name') ?? $ParameterNode.GetAttribute('name')
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $ConfiguredValue = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'value') ?? $ParameterNode.GetAttribute('value')
    if ($null -eq $ConfiguredValue) { $ConfiguredValue = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'default') ?? $ParameterNode.GetAttribute('default') }
    $Sensitive = $ParameterNode.LocalName -match '(?i)password' -or $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name "ParameterDefault:$($ParameterNode.LocalName)" $ConfiguredValue ($null -ne $ConfiguredValue) $true $Sensitive
  }
  foreach ($Action in @($ProjectAction | Where-Object ActionType -EQ 'setInstallerVariable')) {
    $Name = [string]$Action.Properties.name
    $Value = [string]$Action.Properties.value
    $Sensitive = $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name "setInstallerVariable:$($Action.Phase)" $Value ($Action.ConditionState -eq 'True') $true $Sensitive
  }

  $Records = [Collections.Generic.List[object]]::new()
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $AddRecord = {
    param (
      [string]$EvidenceKind,
      [string]$OwnerType,
      [AllowNull()][string]$Property,
      [AllowNull()][string]$Phase,
      [AllowNull()][string]$Lifecycle,
      [string]$SourceCode,
      [AllowNull()][string[]]$AffectedFields
    )
    if ([string]::IsNullOrWhiteSpace($SourceCode) -or $Records.Count -ge $Script:InstallBuilderMaximumDynamicLogicRecords) { return }
    if ($Property -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)') { $SourceCode = '<redacted>' }
    $Identity = "$EvidenceKind`0$OwnerType`0$Property`0$Phase`0$SourceCode"
    if (-not $Seen.Add($Identity)) { return }
    $Variables = [Collections.Generic.List[object]]::new()
    foreach ($Match in [regex]::Matches($SourceCode, '\$\{(?<Name>[^{}]+)\}')) {
      $Name = $Match.Groups['Name'].Value
      if ($VariableFacts.ContainsKey($Name)) {
        foreach ($Fact in $VariableFacts[$Name]) { $Variables.Add($Fact) }
      } else {
        $Variables.Add([pscustomobject][ordered]@{ Name = $Name; Source = 'RuntimeOrUnknown'; Value = $null; IsKnown = $false; IsRuntimeMutable = $true; IsRedacted = $false })
      }
    }
    $Records.Add([pscustomobject][ordered]@{
        EvidenceKind        = $EvidenceKind
        Language            = $EvidenceKind -eq 'Rule' ? 'InstallBuilderRuleXml' : 'InstallBuilderExpression'
        OwnerType           = $OwnerType
        Property            = $Property
        Phase               = $Phase
        Lifecycle           = $Lifecycle
        SourceCode          = $SourceCode
        ReferencedVariables = [string[]]@($Variables.Name | Sort-Object -Unique)
        VariableValues      = [object[]]@($Variables | Sort-Object Name, Source -Unique)
        AffectedFields      = [string[]]@($AffectedFields | Where-Object { $_ } | Sort-Object -Unique)
      })
  }

  # Unknown rule results retain their exact XML rather than being translated into another
  # expression language. The surrounding action identifies the operation the rule controls.
  foreach ($Action in @($ProjectAction)) {
    $AffectedFields = switch ($Action.Category) {
      'Registry' { @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') }
      'Execution' { @('ProductCode', 'AppsAndFeaturesEntries', 'InstallerSwitches') }
      'FileSystem' { @('Architecture', 'Dependencies') }
      default { @() }
    }
    foreach ($Condition in @($Action.Conditions | Where-Object State -EQ 'Unknown')) {
      & $AddRecord 'Rule' $Action.ActionType $Condition.Type $Action.Phase $Action.Lifecycle ([string]$Condition.Xml) $AffectedFields
    }
    foreach ($PropertyInfo in @($Action.Properties.PSObject.Properties)) {
      if ($PropertyInfo.Name -in @($Action.SensitiveProperties) -or $PropertyInfo.Value -isnot [string]) { continue }
      $Resolved = Resolve-InstallBuilderProjectValue -Value ([string]$PropertyInfo.Value) -Variables $Context.Variables
      if ($Resolved.UnresolvedVariables.Count -eq 0) { continue }
      & $AddRecord 'Expression' $Action.ActionType $PropertyInfo.Name $Action.Phase $Action.Lifecycle ([string]$PropertyInfo.Value) $AffectedFields
    }
  }

  # Project properties and parameter values can affect payload selection and installer behavior
  # without belonging to an action list. Retain only unresolved substitutions or explicit script,
  # code, and expression fields to avoid duplicating ordinary resolved metadata.
  foreach ($Node in @($Xml.SelectNodes('//*[not(*)]'))) {
    if ($Node.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
    $SourceCode = $Node.InnerText.Trim()
    if ([string]::IsNullOrWhiteSpace($SourceCode)) { continue }
    $Resolved = Resolve-InstallBuilderProjectValue -Value $SourceCode -Variables $Context.Variables
    $IsExplicitLogic = $Node.LocalName -match '(?i)(?:script|expression|code)$'
    if (-not $IsExplicitLogic -and $Resolved.UnresolvedVariables.Count -eq 0) { continue }
    $Owner = $Node.ParentNode -and $Node.ParentNode.NodeType -eq [Xml.XmlNodeType]::Element ? $Node.ParentNode.LocalName : 'project'
    $Phase = try { Get-InstallBuilderActionPhase -Node $Node } catch { $null }
    if ($Phase -eq 'actionList') { $Phase = $null }
    & $AddRecord ($IsExplicitLogic ? 'ScriptOrExpression' : 'Expression') $Owner $Node.LocalName $Phase ($Phase ? (Get-InstallBuilderActionLifecycle -Phase $Phase) : $null) $SourceCode @()
  }

  return $Records.ToArray()
}

function Get-InstallBuilderFileAssociationInfo {
  <#
  .SYNOPSIS
    Project native InstallBuilder file-association actions into structured evidence.
  .DESCRIPTION
    InstallBuilder's associateWindowsFileExtension action writes one ProgID and one or more
    extension registrations. This function resolves only deterministic project variables and
    retains lifecycle and condition evidence so callers can distinguish installed state from
    uninstall, presentation, and conditional actions.
  .PARAMETER Xml
    Parsed InstallBuilder project document containing compiled action lists.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence used by value and condition
    resolution.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Associations = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//associateWindowsFileExtension'))) {
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $ResolvedValues = [ordered]@{}
    $UnresolvedVariables = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in 'extensions', 'progID', 'icon', 'scope', 'mimeType', 'friendlyName') {
      $Expression = Get-InstallBuilderXmlValue -Xml $Action -XPath $Name
      if ($Name -eq 'scope' -and [string]::IsNullOrWhiteSpace($Expression)) { $Expression = 'system' }
      $Resolved = Resolve-InstallBuilderProjectValue -Value $Expression -Variables $Context.Variables
      $ResolvedValues[$Name] = $Resolved.Value
      foreach ($Variable in @($Resolved.UnresolvedVariables)) { $null = $UnresolvedVariables.Add($Variable) }
    }

    $Commands = [Collections.Generic.List[object]]::new()
    foreach ($CommandNode in @($Action.SelectNodes('./commandList/command'))) {
      $CommandCondition = Get-InstallBuilderNodeCondition -Node $CommandNode -Context $Context
      $CommandValues = [ordered]@{}
      $CommandUnresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Name in 'verb', 'runProgram', 'runProgramArguments') {
        $Resolved = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderXmlValue -Xml $CommandNode -XPath $Name) -Variables $Context.Variables
        $CommandValues[$Name] = $Resolved.Value
        foreach ($Variable in @($Resolved.UnresolvedVariables)) {
          $null = $CommandUnresolved.Add($Variable)
          $null = $UnresolvedVariables.Add($Variable)
        }
      }
      $Program = ([string]$CommandValues.runProgram).Replace('/', '\')
      $Arguments = [string]$CommandValues.runProgramArguments
      $CommandLine = $null
      if (-not [string]::IsNullOrWhiteSpace($Program)) {
        # InstallBuilder stores executable and arguments separately. Quote a path containing
        # whitespace in the projected command line without modifying an already quoted value.
        $CommandProgram = if ($Program -match '^\s*".*"\s*$' -or ($Program -notmatch '\s' -and $Program -notmatch '%[^%]+%')) { $Program } else { '"' + $Program + '"' }
        $CommandLine = [string]::IsNullOrWhiteSpace($Arguments) ? $CommandProgram : "$CommandProgram $Arguments"
      }
      $Commands.Add([pscustomobject][ordered]@{
          Verb                = [string]$CommandValues.verb
          Executable          = $Program
          Arguments           = $Arguments
          Command             = $CommandLine
          # Node-condition evaluation already walks the association ancestor, so the command
          # state includes both command-local and parent-action rules without double counting.
          ConditionState      = $CommandCondition.State
          Conditions          = $CommandCondition.Conditions
          UnresolvedVariables = [string[]]@($CommandUnresolved | Sort-Object)
        })
    }

    $Extensions = @([string]$ResolvedValues.extensions -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $AssociationScope = switch ([string]$ResolvedValues.scope) {
      { $_ -ieq 'user' } { 'user'; break }
      { $_ -ieq 'system' } { 'machine'; break }
      default { $null }
    }
    foreach ($ExtensionText in $Extensions) {
      $Extension = $ExtensionText.StartsWith('.') ? $ExtensionText : ".$ExtensionText"
      if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ExtensionInvalid' -Source InstallBuilder -Message "The associateWindowsFileExtension action contains an invalid literal extension '$ExtensionText'." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Extension = $ExtensionText; Phase = $Phase })))
        continue
      }
      $PrimaryCommand = @($Commands | Where-Object { $_.Verb -ieq 'open' } | Select-Object -First 1)
      if ($PrimaryCommand.Count -eq 0) { $PrimaryCommand = @($Commands | Select-Object -First 1) }
      $Associations.Add([pscustomobject][ordered]@{
          FileExtension       = $Extension.TrimStart('.').ToLowerInvariant()
          Extension           = $Extension.ToLowerInvariant()
          Root                = $AssociationScope -eq 'user' ? 'HKCU' : ($AssociationScope -eq 'machine' ? 'HKLM' : $null)
          DefaultProgId       = [string]$ResolvedValues.progID
          ProgIds             = [string[]]@($ResolvedValues.progID | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
          Description         = [string]$ResolvedValues.friendlyName
          Command             = $PrimaryCommand.Count ? $PrimaryCommand[0].Command : $null
          Executable          = $PrimaryCommand.Count ? $PrimaryCommand[0].Executable : $null
          Arguments           = $PrimaryCommand.Count ? $PrimaryCommand[0].Arguments : $null
          DefaultIcon         = ([string]$ResolvedValues.icon).Replace('/', '\')
          MimeType            = [string]$ResolvedValues.mimeType
          Scope               = $AssociationScope
          Commands            = $Commands.ToArray()
          Phase               = $Phase
          Lifecycle           = $Lifecycle
          ConditionState      = $Condition.State
          Conditions          = $Condition.Conditions
          UnresolvedVariables = [string[]]@($UnresolvedVariables | Sort-Object)
          Source              = 'associateWindowsFileExtension'
          Evidence            = @($Action.OuterXml)
        })
    }
  }

  $Conditional = @($Associations | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.ConditionState -eq 'Unknown' })
  if ($Conditional.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ConditionsUnresolved' -Source InstallBuilder -Message "$($Conditional.Count) file-extension association(s) depend on runtime rules and were excluded from authoritative installed-state projection." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Extensions = @($Conditional.Extension | Sort-Object -Unique) })))
  }
  $Unresolved = @($Associations | Where-Object { $_.Lifecycle -eq 'Installation' -and @($_.UnresolvedVariables).Count })
  if ($Unresolved.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ValuesUnresolved' -Source InstallBuilder -Message "$($Unresolved.Count) file-extension association(s) contain unresolved runtime variables." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Variables = @($Unresolved.UnresolvedVariables | Sort-Object -Unique) })))
  }
  [pscustomobject][ordered]@{
    # The extension itself remains authoritative when optional icon, command, or description
    # values are dynamic; only the owning action condition controls whether registration occurs.
    FileExtensions            = @($Associations | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.ConditionState -eq 'True' } | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    FileExtensionAssociations = $Associations.ToArray()
    Diagnostics               = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
  }
}

function Get-InstallBuilderSystemEffectInfo {
  <#
  .SYNOPSIS
    Normalize source-backed persistent system-effect actions.
  .PARAMETER ProjectAction
    Phase-aware records returned by Get-InstallBuilderProjectActionInfo.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$ProjectAction)

  $EnvironmentChanges = [Collections.Generic.List[object]]::new()
  $PathChanges = [Collections.Generic.List[object]]::new()
  $WindowsServices = [Collections.Generic.List[object]]::new()
  $ScheduledTasks = [Collections.Generic.List[object]]::new()
  $FontChanges = [Collections.Generic.List[object]]::new()
  $SharedDllChanges = [Collections.Generic.List[object]]::new()
  $WindowsAclChanges = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($ProjectAction)) {
    $Values = $Action.ResolvedProperties
    $Value = [ordered]@{}
    foreach ($Name in 'scope', 'insertAt', 'path', 'name', 'value', 'username', 'serviceName', 'displayName', 'description', 'program', 'programArguments', 'startType', 'account', 'password', 'dependencies', 'delay', 'abortOnError', 'type', 'runAsAdmin', 'executionTimeLimit', 'weekDays', 'startTime', 'runOnlyIfLoggedOn', 'endDate', 'interval', 'dayOfMonth', 'runAs', 'period', 'startDate', 'disallowStartIfOnBatteries', 'workingDirectory', 'duration', 'files', 'excludeFiles', 'matchHiddenFiles', 'permissions', 'recurseOneLevelOnly', 'users', 'self', 'action', 'recurseObjects', 'recurseContainers', 'owner') {
      $Property = $Values.PSObject.Properties[$Name]
      $Value[$Name] = $Property ? [string]$Property.Value : $null
    }
    $ScopeProperty = $Values.PSObject.Properties['scope']
    $Scope = if (-not $ScopeProperty) { 'machine' } elseif ($Value.scope -ieq 'user') { 'user' } elseif ($Value.scope -ieq 'system') { 'machine' } else { $null }
    $AppliesToInstalledState = $Action.Lifecycle -eq 'Installation' -and $Action.ConditionState -eq 'True' -and @($Action.UnresolvedVariables).Count -eq 0
    $Common = [ordered]@{
      ActionType              = $Action.ActionType
      Phase                   = $Action.Phase
      Lifecycle               = $Action.Lifecycle
      ConditionState          = $Action.ConditionState
      Conditions              = $Action.Conditions
      UnresolvedVariables     = $Action.UnresolvedVariables
      AppliesToInstalledState = $AppliesToInstalledState
    }
    switch ($Action.ActionType) {
      'addDirectoryToPath' {
        $PathChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Add'; Path = ([string]$Value.path).Replace('/', '\'); Scope = $Scope; Position = ([string]::IsNullOrWhiteSpace($Value.insertAt) ? 'end' : $Value.insertAt); PositionAppliesOnWindows = $false; Persistent = $true }))
      }
      'removeDirectoryFromPath' {
        $PathChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Remove'; Path = ([string]$Value.path).Replace('/', '\'); Scope = $Scope; Position = $null; PositionAppliesOnWindows = $false; Persistent = $true }))
      }
      'addEnvironmentVariable' {
        $EnvironmentChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Add'; Name = $Value.name; Value = $Value.value; Scope = $Scope; Username = $Value.username; Persistent = $true }))
      }
      'deleteEnvironmentVariable' {
        $EnvironmentChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Delete'; Name = $Value.name; Value = $null; Scope = $Scope; Username = $Value.username; Persistent = $true }))
      }
      'setEnvironmentVariable' {
        # The documented setEnvironmentVariable action changes only the installer's process
        # environment. Preserve it as execution evidence without claiming installed state.
        $ProcessEffect = [pscustomobject]($Common + [ordered]@{ Action = 'SetProcess'; Name = $Value.name; Value = $Value.value; Scope = 'process'; Username = $null; Persistent = $false })
        $ProcessEffect.AppliesToInstalledState = $false
        $EnvironmentChanges.Add($ProcessEffect)
      }
      { $_ -in 'createWindowsService', 'deleteWindowsService', 'startWindowsService', 'stopWindowsService', 'restartWindowsService' } {
        $Operation = switch ($_) { 'createWindowsService' { 'Create' } 'deleteWindowsService' { 'Delete' } 'startWindowsService' { 'Start' } 'stopWindowsService' { 'Stop' } 'restartWindowsService' { 'Restart' } }
        $DelayMilliseconds = 0L
        $HasDelay = [long]::TryParse($Value.delay, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$DelayMilliseconds)
        if (-not $HasDelay -and $Operation -in 'Start', 'Stop', 'Restart') { $DelayMilliseconds = 15000; $HasDelay = $true }
        $WindowsServices.Add([pscustomobject]($Common + [ordered]@{
              Operation          = $Operation
              ServiceName        = $Value.serviceName
              DisplayName        = $Value.displayName
              Description        = $Value.description
              Program            = ([string]$Value.program).Replace('/', '\')
              ProgramArguments   = $Value.programArguments
              StartType          = if (-not [string]::IsNullOrWhiteSpace($Value.startType)) { $Value.startType } elseif ($Operation -eq 'Create') { 'auto' } else { $null }
              Account            = if (-not [string]::IsNullOrWhiteSpace($Value.account)) { $Value.account } elseif ($Operation -eq 'Create') { 'LocalSystem' } else { $null }
              PasswordConfigured = -not [string]::IsNullOrWhiteSpace($Value.password)
              Dependencies       = @($Value.dependencies -split '\s*,\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
              DelayMilliseconds  = $HasDelay ? $DelayMilliseconds : $null
              AbortOnError       = Test-InstallBuilderTrueValue $Value.abortOnError
            }))
      }
      { $_ -in 'addScheduledTask', 'deleteScheduledTask' } {
        $Operation = $_ -eq 'addScheduledTask' ? 'CreateOrUpdate' : 'Delete'
        $IsCreateTask = $Operation -eq 'CreateOrUpdate'
        $ScheduledTasks.Add([pscustomobject]($Common + [ordered]@{
              Operation                  = $Operation
              Name                       = $Value.name
              TriggerType                = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.type) ? 'DAILY' : $Value.type.ToUpperInvariant()) : $null
              Program                    = $IsCreateTask ? ([string]$Value.program).Replace('/', '\') : $null
              Arguments                  = $IsCreateTask ? $Value.programArguments : $null
              WorkingDirectory           = $IsCreateTask ? ([string]$Value.workingDirectory).Replace('/', '\') : $null
              RunAs                      = $IsCreateTask ? $Value.runAs : $null
              PasswordConfigured         = $IsCreateTask ? (-not [string]::IsNullOrWhiteSpace($Value.password)) : $null
              RunAsAdministrator         = $IsCreateTask ? (Test-InstallBuilderTrueValue $Value.runAsAdmin) : $null
              RunOnlyIfLoggedOn          = $IsCreateTask ? (Test-InstallBuilderTrueValue $Value.runOnlyIfLoggedOn) : $null
              DisallowStartIfOnBatteries = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.disallowStartIfOnBatteries) -or (Test-InstallBuilderTrueValue $Value.disallowStartIfOnBatteries)) : $null
              StartDate                  = $IsCreateTask ? $Value.startDate : $null
              EndDate                    = $IsCreateTask ? $Value.endDate : $null
              StartTime                  = $IsCreateTask ? $Value.startTime : $null
              WeekDays                   = $IsCreateTask ? $Value.weekDays : $null
              DayOfMonth                 = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.dayOfMonth) ? '1' : $Value.dayOfMonth) : $null
              Period                     = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.period) ? '1' : $Value.period) : $null
              IntervalMinutes            = $IsCreateTask ? $Value.interval : $null
              DurationMinutes            = $IsCreateTask ? $Value.duration : $null
              ExecutionTimeLimitHours    = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.executionTimeLimit) ? '72' : $Value.executionTimeLimit) : $null
            }))
      }
      { $_ -in 'addFonts', 'removeFonts' } {
        $FontChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation        = $_ -eq 'addFonts' ? 'Add' : 'Remove'
              Files            = ([string]$Value.files).Replace('/', '\')
              ExcludeFiles     = ([string]$Value.excludeFiles).Replace('/', '\')
              MatchHiddenFiles = Test-InstallBuilderTrueValue $Value.matchHiddenFiles
            }))
      }
      { $_ -in 'addSharedDLL', 'removeSharedDLL' } {
        $SharedDllChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation = $_ -eq 'addSharedDLL' ? 'IncrementReference' : 'DecrementReference'
              Path      = ([string]$Value.path).Replace('/', '\')
            }))
      }
      { $_ -in 'setWindowsACL', 'clearWindowsACL' } {
        $WindowsAclChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation           = $_ -eq 'setWindowsACL' ? 'Set' : 'Clear'
              Files               = ([string]$Value.files).Replace('/', '\')
              ExcludeFiles        = ([string]$Value.excludeFiles).Replace('/', '\')
              MatchHiddenFiles    = Test-InstallBuilderTrueValue $Value.matchHiddenFiles
              Permissions         = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.permissions) ? 'generic_all' : $Value.permissions) : $null
              Users               = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.users) ? 'S-1-1-0' : $Value.users) : $null
              Access              = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.action) ? 'allow' : $Value.action) : $null
              Owner               = $_ -eq 'setWindowsACL' ? $Value.owner : $null
              ApplyToSelf         = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.self) -or (Test-InstallBuilderTrueValue $Value.self)) : $null
              RecurseObjects      = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseObjects) : $null
              RecurseContainers   = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseContainers) : $null
              RecurseOneLevelOnly = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseOneLevelOnly) : $null
            }))
      }
    }
  }
  [pscustomobject][ordered]@{
    EnvironmentChanges = $EnvironmentChanges.ToArray()
    PathChanges        = $PathChanges.ToArray()
    WindowsServices    = $WindowsServices.ToArray()
    ScheduledTasks     = $ScheduledTasks.ToArray()
    FontChanges        = $FontChanges.ToArray()
    SharedDllChanges   = $SharedDllChanges.ToArray()
    WindowsAclChanges  = $WindowsAclChanges.ToArray()
  }
}

function Resolve-InstallBuilderPayloadPath {
  <#
  .SYNOPSIS
    Match a resolved installed path to one logical InstallBuilder payload path.
  .PARAMETER Path
    Resolved action or shortcut target.
  .PARAMETER Context
    Project context containing the resolved installation directory.
  .PARAMETER PayloadPath
    Case-insensitive set of logical packaged payload paths.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Path,
    [Parameter(Mandatory)]$Context,
    [AllowNull()][Collections.Generic.HashSet[string]]$PayloadPath
  )

  if ($null -eq $PayloadPath) { $PayloadPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
  if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Context.InstallLocation)) { return $null }
  $NormalizedPath = $Path.Replace('\', '/')
  $NormalizedInstallLocation = $Context.InstallLocation.Replace('\', '/').TrimEnd('/')
  if (-not $NormalizedPath.StartsWith($NormalizedInstallLocation + '/', [StringComparison]::OrdinalIgnoreCase)) { return $null }
  $RelativePath = $NormalizedPath.Substring($NormalizedInstallLocation.Length + 1)
  if (-not $PayloadPath.Contains($RelativePath) -and $PayloadPath.Contains($RelativePath + '.exe')) { $RelativePath += '.exe' }
  return $PayloadPath.Contains($RelativePath) ? $RelativePath : $null
}

function Get-InstallBuilderExecutionInfo {
  <#
  .SYNOPSIS
    Project compiled runProgram actions without executing or classifying arbitrary programs.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and inherited-condition evidence.
  .PARAMETER Payload
    Logical payload catalog used only to mark source-backed embedded executable matches.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowEmptyCollection()][object[]]$Payload = @()
  )

  $PayloadPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in @($Payload)) { $null = $PayloadPaths.Add(([string]$Item.Path).Replace('\', '/')) }
  $Actions = [Collections.Generic.List[object]]::new()
  $NestedCandidates = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//runProgram'))) {
    $RawProgram = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'program') ?? $Action.GetAttribute('program')
    if ([string]::IsNullOrWhiteSpace($RawProgram)) { continue }
    $RawArguments = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'programArguments') ?? $Action.GetAttribute('programArguments')
    $RawWorkingDirectory = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'workingDirectory') ?? $Action.GetAttribute('workingDirectory')
    $Program = Resolve-InstallBuilderProjectValue -Value $RawProgram -Variables $Context.Variables
    $Arguments = Resolve-InstallBuilderProjectValue -Value $RawArguments -Variables $Context.Variables
    $WorkingDirectory = Resolve-InstallBuilderProjectValue -Value $RawWorkingDirectory -Variables $Context.Variables
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $RelativeProgram = Resolve-InstallBuilderPayloadPath -Path $Program.Value -Context $Context -PayloadPath $PayloadPaths
    $Record = [pscustomobject][ordered]@{
      Phase               = $Phase
      Lifecycle           = $Lifecycle
      Program             = $Program.Value
      ProgramExpression   = $RawProgram
      Arguments           = $Arguments.Value
      ArgumentsExpression = $RawArguments
      WorkingDirectory    = $WorkingDirectory.Value
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      PayloadPath         = $RelativeProgram
      IsEmbeddedPayload   = [bool]($RelativeProgram -and $PayloadPaths.Contains($RelativeProgram))
      Purpose             = $Lifecycle -eq 'Presentation' ? 'ApplicationLaunch' : ($Lifecycle -eq 'Uninstallation' ? 'UninstallAction' : ($Lifecycle -eq 'Installation' ? 'InstallerAction' : 'OtherAction'))
    }
    $Actions.Add($Record)
    if ($Record.Purpose -eq 'InstallerAction' -and $Record.IsEmbeddedPayload -and $RelativeProgram -match '(?i)\.(?:exe|msi|msp|msix|appx|bat|cmd|ps1)$') {
      $NestedCandidates.Add($Record)
    }
  }
  [pscustomobject]@{
    Actions                   = $Actions.ToArray()
    ExecutedPayloads          = @($Actions | Where-Object IsEmbeddedPayload | ForEach-Object PayloadPath | Select-Object -Unique)
    NestedInstallerCandidates = $NestedCandidates.ToArray()
  }
}

function Get-InstallBuilderShortcutInfo {
  <#
  .SYNOPSIS
    Read compiled shortcut targets and their inherited runtime conditions.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and condition evidence.
  .PARAMETER Payload
    Logical payload catalog used only to identify embedded shortcut targets.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowEmptyCollection()][object[]]$Payload = @()
  )

  $PayloadPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in @($Payload)) { $null = $PayloadPaths.Add(([string]$Item.Path).Replace('\', '/')) }

  foreach ($Shortcut in @($Xml.SelectNodes('//shortcut'))) {
    $Condition = Get-InstallBuilderNodeCondition -Node $Shortcut -Context $Context
    $Resolve = {
      param([string]$Name)
      $Raw = (Get-InstallBuilderXmlValue -Xml $Shortcut -XPath $Name) ?? $Shortcut.GetAttribute($Name)
      (Resolve-InstallBuilderProjectValue -Value $Raw -Variables $Context.Variables).Value
    }
    $Target = (& $Resolve 'windowsExec') ?? (& $Resolve 'exec')
    $PayloadPath = Resolve-InstallBuilderPayloadPath -Path $Target -Context $Context -PayloadPath $PayloadPaths
    [pscustomobject][ordered]@{
      Name              = & $Resolve 'name'
      Target            = $Target
      Arguments         = & $Resolve 'windowsExecArgs'
      WorkingDirectory  = (& $Resolve 'windowsPath') ?? (& $Resolve 'path')
      Icon              = (& $Resolve 'windowsIcon') ?? (& $Resolve 'icon')
      Platforms         = & $Resolve 'platforms'
      PayloadPath       = $PayloadPath
      IsEmbeddedPayload = [bool]$PayloadPath
      ConditionState    = $Condition.State
      Conditions        = $Condition.Conditions
    }
  }
}

function Get-InstallBuilderRequirementInfo {
  <#
  .SYNOPSIS
    Project structured Java and Windows-version requirements without resolving host state.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and target-platform evidence used for inherited conditions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Java = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//autodetectJava'))) {
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Versions = [Collections.Generic.List[object]]::new()
    foreach ($ValidVersion in @($Action.SelectNodes('validVersionList/validVersion'))) {
      $Versions.Add([pscustomobject][ordered]@{
          MinimumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'minVersion'
          MaximumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'maxVersion'
          Vendor         = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'vendor'
          Bitness        = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'bitness'
          RequireJdk     = Test-InstallBuilderTrueValue (Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'requireJDK')
        })
    }
    $Java.Add([pscustomobject][ordered]@{
        PromptUser     = Test-InstallBuilderTrueValue (Get-InstallBuilderXmlValue -Xml $Action -XPath 'promptUser')
        ValidVersions  = $Versions.ToArray()
        ConditionState = $Condition.State
        Conditions     = $Condition.Conditions
      })
  }

  $Windows = [Collections.Generic.List[object]]::new()
  foreach ($Rule in @($Xml.SelectNodes('//compareVersions'))) {
    $Version1 = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version1') ?? $Rule.GetAttribute('version1')
    $Version2 = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version2') ?? $Rule.GetAttribute('version2')
    if ($Version1 -notmatch '\$\{windows_os_version_number\}' -and $Version2 -notmatch '\$\{windows_os_version_number\}') { continue }
    $Windows.Add([pscustomobject][ordered]@{
        Version1 = $Version1
        Version2 = $Version2
        Logic    = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
        State    = (Resolve-InstallBuilderRuleState -Rule $Rule -Context $Context).State
        Xml      = $Rule.OuterXml
      })
  }
  [pscustomobject][ordered]@{
    Java                = $Java.ToArray()
    WindowsVersionRules = $Windows.ToArray()
  }
}

function Get-InstallBuilderArpInfo {
  <#
  .SYNOPSIS
    Reconstruct built-in and literal custom InstallBuilder ARP entries.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Shared project context containing deterministic variables and PE evidence.
  .PARAMETER RegistryWrite
    Parsed registrySet actions. Conditional actions remain evidence but do not become authoritative entries.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrite
  )

  $InstallationType = Get-InstallBuilderProjectProperty -Xml $Xml -Name installationType
  $CreateUninstaller = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name createUninstaller)
  $CreateWindowsArpEntry = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name createWindowsARPEntry)
  $HasBuiltInUninstaller = $InstallationType -ieq 'normal' -and $CreateUninstaller
  $WritesBuiltInArp = $HasBuiltInUninstaller -and $CreateWindowsArpEntry
  $EntryMap = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $Diagnostics = [Collections.Generic.List[object]]::new()

  $BuiltInProductCode = $null
  if ($WritesBuiltInArp) {
    $PrefixResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name windowsARPRegistryPrefix) -Variables $Context.Variables
    $DisplayNameResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name productDisplayName) -Variables $Context.Variables
    if ($PrefixResult.Value) {
      $BuiltInProductCode = $PrefixResult.Value
      $ResolveProperty = {
        param([string]$Name)
        (Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name $Name) -Variables $Context.Variables).Value
      }
      $UninstallerName = $Context.UninstallerName
      if ($UninstallerName -and -not $UninstallerName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $UninstallerName += '.exe' }
      $UninstallerPath = if ($Context.UninstallerDirectory -and $UninstallerName) { "$($Context.UninstallerDirectory.TrimEnd('/', '\'))\$UninstallerName".Replace('/', '\') } else { $null }
      $EntryMap["HKLM|$($Context.RegistryView)|$BuiltInProductCode"] = [pscustomobject][ordered]@{
        ProductCode          = $BuiltInProductCode
        DisplayName          = $DisplayNameResult.Value
        DisplayVersion       = $Context.Variables['project.version']
        Publisher            = $Context.Variables['project.vendor']
        InstallerType        = 'exe'
        RegistryHive         = 'HKLM'
        RegistryView         = $Context.RegistryView
        RegistryKey          = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$BuiltInProductCode"
        UninstallString      = $UninstallerPath ? "`"$UninstallerPath`"" : $null
        QuietUninstallString = $null
        DisplayIcon          = & $ResolveProperty 'productDisplayIcon'
        InstallLocation      = $Context.InstallLocation
        UrlInfoAbout         = & $ResolveProperty 'productUrlInfoAbout'
        Comments             = & $ResolveProperty 'productComments'
        Contact              = & $ResolveProperty 'productContact'
        HelpLink             = & $ResolveProperty 'productUrlHelpLink'
        SystemComponent      = $null
        NoModify             = 1
        NoRepair             = 1
        EstimatedSize        = $null
        InstallDate          = $null
        IsVisible            = $true
        ConditionState       = 'True'
        Conditions           = @()
        Source               = 'BuiltInWindowsARP'
      }
    } else {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.BuiltInPrefixUnresolved' -Source InstallBuilder -Message "The built-in ARP registry prefix contains unresolved variables: $($PrefixResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
    }
  }

  # Custom registrySet actions can replace, hide, or supplement the built-in entry. Group all
  # records first so a SystemComponent override on the built-in key affects visibility.
  $CustomGroups = @($RegistryWrite | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.Key -match '(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\.+' } | Group-Object -Property { "$($_.Root)|$($_.RawKey)" })
  foreach ($Group in $CustomGroups) {
    $RawKey = [string]$Group.Group[0].RawKey
    $KeyResult = Resolve-InstallBuilderProjectValue -Value $RawKey -Variables $Context.Variables
    if (-not $KeyResult.Value) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.CustomKeyUnresolved' -Source InstallBuilder -Message "A custom ARP registry key contains unresolved variables: $($KeyResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ Key = $RawKey; Variables = $KeyResult.UnresolvedVariables })))
      continue
    }
    $ProductCode = Split-Path -Path $KeyResult.Value.Replace('/', '\') -Leaf
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { continue }
    $Root = @($Group.Group.Root | Where-Object { $_ } | Select-Object -Unique)
    $WowMode = @($Group.Group.WowMode | Where-Object { $_ } | Select-Object -Unique)
    $RegistryView = if ($WowMode -contains '32') { '32-bit' } elseif ($WowMode -contains '64') { '64-bit' } else { $Context.RegistryView }
    $Identity = "$($Root.Count -eq 1 ? $Root[0] : '')|$RegistryView|$ProductCode"
    $Existing = $EntryMap.ContainsKey($Identity) ? $EntryMap[$Identity] : $null
    $Values = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Existing) { foreach ($Property in $Existing.PSObject.Properties) { $Values[$Property.Name] = $Property.Value } }
    foreach ($Write in @($Group.Group | Where-Object ConditionState -EQ 'True')) {
      if ([string]::IsNullOrWhiteSpace($Write.Name)) { continue }
      $ValueResult = Resolve-InstallBuilderProjectValue -Value $Write.Value -Variables $Context.Variables
      if ($null -ne $ValueResult.Value) { $Values[$Write.Name] = $ValueResult.Value }
    }
    $UnknownWrites = @($Group.Group | Where-Object ConditionState -EQ 'Unknown')
    $HasTrueWrite = @($Group.Group | Where-Object ConditionState -EQ 'True').Count -gt 0
    if (-not $HasTrueWrite -and -not $Existing -and -not $UnknownWrites.Count) { continue }
    $SystemComponent = $Values.ContainsKey('SystemComponent') ? $Values['SystemComponent'] : $null
    $VisibilityUnknown = @($UnknownWrites | Where-Object Name -IEQ 'SystemComponent').Count -gt 0
    $SystemComponentNumber = 0L
    $IsHidden = if ($null -eq $SystemComponent) {
      $false
    } elseif ([long]::TryParse([string]$SystemComponent, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$SystemComponentNumber)) {
      $SystemComponentNumber -ne 0
    } else {
      Test-InstallBuilderTrueValue ([string]$SystemComponent)
    }
    $IsVisible = $VisibilityUnknown ? $null : -not $IsHidden
    $EntryMap[$Identity] = [pscustomobject][ordered]@{
      ProductCode          = $ProductCode
      DisplayName          = $Values.ContainsKey('DisplayName') ? $Values['DisplayName'] : $null
      DisplayVersion       = $Values.ContainsKey('DisplayVersion') ? $Values['DisplayVersion'] : $null
      Publisher            = $Values.ContainsKey('Publisher') ? $Values['Publisher'] : $null
      InstallerType        = 'exe'
      RegistryHive         = $Root.Count -eq 1 ? $Root[0] : $null
      RegistryView         = $RegistryView
      RegistryKey          = ($KeyResult.Value -replace '^HKEY_LOCAL_MACHINE\\?', '' -replace '^HKLM\\?', '' -replace '^HKEY_CURRENT_USER\\?', '' -replace '^HKCU\\?', '')
      UninstallString      = $Values.ContainsKey('UninstallString') ? $Values['UninstallString'] : $null
      QuietUninstallString = $Values.ContainsKey('QuietUninstallString') ? $Values['QuietUninstallString'] : $null
      DisplayIcon          = $Values.ContainsKey('DisplayIcon') ? $Values['DisplayIcon'] : $null
      InstallLocation      = $Values.ContainsKey('InstallLocation') ? $Values['InstallLocation'] : $null
      UrlInfoAbout         = $Values.ContainsKey('UrlInfoAbout') ? $Values['UrlInfoAbout'] : $null
      Comments             = $Values.ContainsKey('Comments') ? $Values['Comments'] : $null
      Contact              = $Values.ContainsKey('Contact') ? $Values['Contact'] : $null
      HelpLink             = $Values.ContainsKey('HelpLink') ? $Values['HelpLink'] : $null
      SystemComponent      = $SystemComponent
      NoModify             = $Values.ContainsKey('NoModify') ? $Values['NoModify'] : $null
      NoRepair             = $Values.ContainsKey('NoRepair') ? $Values['NoRepair'] : $null
      EstimatedSize        = $Values.ContainsKey('EstimatedSize') ? $Values['EstimatedSize'] : $null
      InstallDate          = $Values.ContainsKey('InstallDate') ? $Values['InstallDate'] : $null
      IsVisible            = $IsVisible
      ConditionState       = ($Existing -or $HasTrueWrite) ? 'True' : 'Unknown'
      Conditions           = @($Group.Group.Conditions)
      Source               = $Existing ? 'BuiltInWindowsARP+RegistrySet' : 'RegistrySet'
    }
    if ($UnknownWrites.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.ConditionalValues' -Source InstallBuilder -Message "The custom uninstall key '$ProductCode' has condition-dependent values; unconditional identity remains usable, but affected ARP values require runtime evidence." -Kind Ambiguous -Areas Metadata -AffectedFields @('AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ProductCode = $ProductCode; ConditionalValueNames = @($UnknownWrites.Name | Where-Object { $_ } | Select-Object -Unique) })))
    }
  }

  $UniqueEntries = @($EntryMap.Values | Sort-Object RegistryHive, RegistryView, ProductCode)
  $VisibleEntries = @($UniqueEntries | Where-Object { $_.IsVisible -eq $true -and $_.ConditionState -eq 'True' })
  $UncertainEntries = @($UniqueEntries | Where-Object { $null -eq $_.IsVisible -or $_.ConditionState -eq 'Unknown' })
  $HiddenEntries = @($UniqueEntries | Where-Object IsVisible -EQ $false)
  if ($HiddenEntries.Count -and -not $VisibleEntries.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.HiddenOnly' -Source InstallBuilder -Message 'The installer writes only hidden uninstall registration evidence; hidden SystemComponent entries are not projected as WinGet AppsAndFeaturesEntries.' -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ProductCodes = @($HiddenEntries.ProductCode) })))
  }
  $Primary = if ($BuiltInProductCode) { $VisibleEntries | Where-Object ProductCode -EQ $BuiltInProductCode | Select-Object -First 1 } elseif ($VisibleEntries.Count -eq 1) { $VisibleEntries[0] } else { $null }
  [pscustomobject]@{
    InstallationType      = $InstallationType
    HasBuiltInUninstaller = $HasBuiltInUninstaller
    WritesBuiltInArp      = $WritesBuiltInArp
    WritesAppsAndFeatures = if ($VisibleEntries.Count) { $true } elseif ($UncertainEntries.Count -or $InstallationType -ieq 'upgrade') { $null } else { $false }
    ProductCode           = $Primary ? $Primary.ProductCode : $null
    PrimaryEntry          = $Primary
    Entries               = $UniqueEntries
    VisibleEntries        = $VisibleEntries
    HiddenEntries         = $HiddenEntries
    UncertainEntries      = $UncertainEntries
    Diagnostics           = $Diagnostics.ToArray()
  }
}

function Get-InstallBuilderInfo {
  <#
  .SYNOPSIS
    Get static metadata from a BitRock or VMware InstallBuilder installer
  .DESCRIPTION
    The parser recovers zlib-compressed project XML and the CookFS file index
    held by the embedded Metakit VFS. It never mounts TclKit or executes Tcl.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER AnalyzePrimaryExecutables
    Selectively extract source-referenced application executables and adjacent sidecars, then run
    bounded PE architecture and dependency analysis. This is opt-in because large application
    payloads can materially increase parsing time and temporary disk use.
  .PARAMETER MaximumPayloadAnalysisBytes
    Maximum aggregate bytes materialized when AnalyzePrimaryExecutables is specified.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$AnalyzePrimaryExecutables,
    [ValidateRange(1048576, [long]::MaxValue)][long]$MaximumPayloadAnalysisBytes = $Script:InstallBuilderMaximumPayloadAnalysisBytes
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    # project.xml is authoritative for identity, scope actions, and registry writes. CookFS is an
    # independent optional payload index and is not required for metadata-only parsing.
    $Project = Get-InstallBuilderProjectData -Path $File.FullName
    $Xml = [xml]$Project.Content
    $ShortName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/shortName'
    $FullName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/fullName'
    $Version = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/version'
    $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $File.FullName
    $RegistryWrites = @(Get-InstallBuilderRegistryWrite -Xml $Xml -Context $Context)
    $ArpInfo = Get-InstallBuilderArpInfo -Xml $Xml -Context $Context -RegistryWrite $RegistryWrites
    $ScopeInfo = Get-InstallBuilderScopeInfo -Xml $Xml -Context $Context -ArpInfo $ArpInfo
    # ARP and association projection use only writes that persist after a successful installation.
    # Other phases remain available in RegistryWrites for manual analysis.
    $InstallationRegistryWrites = @($RegistryWrites | Where-Object Lifecycle -EQ 'Installation')
    $ResolvedAssociationWrites = @($InstallationRegistryWrites | Where-Object { $_.ConditionState -eq 'True' -and $_.ResolvedKey } | ForEach-Object {
        [pscustomobject]@{ Root = $_.Root; Key = $_.ResolvedKey; Name = $_.Name; Value = $_.ResolvedValue; Type = $_.Type; Source = $_ }
      })
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $ResolvedAssociationWrites
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $ProjectMetakitLayout = $Project.PSObject.Properties['MetakitLayout']
    $ProjectMetakitLayouts = $Project.PSObject.Properties['MetakitLayouts']
    $ProjectMetakitEntries = $Project.PSObject.Properties['MetakitEntries']
    $ProjectOriginDirectory = $Project.PSObject.Properties['OriginDirectory']
    $MetakitLayouts = $ProjectMetakitLayouts ? @($ProjectMetakitLayouts.Value) : @(Get-InstallBuilderMetakitLayout -Path $File.FullName)
    $Cookfs = $null
    $MetakitInfo = $null
    $LegacyPayloadFiles = @()
    try {
      $Cookfs = Get-InstallBuilderCookfsInfo -Path $File.FullName
    } catch {
      # project.xml remains useful metadata evidence in older containers that
      # expose no CookFS payload footer. A present but invalid footer is useful
      # corruption evidence and remains visible to callers.
      $FooterMarker = [Text.Encoding]::ASCII.GetBytes('CFS0002')
      if (@(Find-BinaryPattern -Path $File.FullName -Pattern $FooterMarker -Maximum 1).Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.CookfsIndexInvalid' -Source InstallBuilder -Message "The CookFS payload index was not available: $($_.Exception.Message)" -Kind Invalid -Areas Extraction -AffectedFields @()))
      }
    }
    if (-not $Cookfs -and $MetakitLayouts.Count) {
      $LegacyArchive = $null
      try {
        if ($ProjectMetakitEntries -and $ProjectMetakitEntries.Value) {
          $MetakitEntries = @($ProjectMetakitEntries.Value)
          $OriginDirectory = $ProjectOriginDirectory.Value
          $MetakitHeaderOffset = $ProjectMetakitLayout.Value.HeaderOffset
          $MetakitLength = $ProjectMetakitLayout.Value.Length
          $MetakitRootPosition = $ProjectMetakitLayout.Value.RootPosition
          $MetakitRootLength = $ProjectMetakitLayout.Value.RootLength
        } else {
          $LegacyArchive = Open-InstallBuilderMetakitArchive -Path $File.FullName -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
          $MetakitEntries = @($LegacyArchive.Entries)
          $OriginEntry = @($MetakitEntries | Where-Object Path -CEQ 'origindist')
          if ($OriginEntry.Count -ne 1) { throw 'The legacy TclKit VFS does not contain one unambiguous origindist control record' }
          $OriginDirectory = $Script:InstallBuilderStrictUtf8.GetString($LegacyArchive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim()
          $MetakitHeaderOffset = $LegacyArchive.HeaderOffset
          $MetakitLength = $LegacyArchive.Length
          $MetakitRootPosition = $LegacyArchive.RootPosition
          $MetakitRootLength = $LegacyArchive.RootLength
        }
        if ([string]::IsNullOrWhiteSpace($OriginDirectory) -or $OriginDirectory.IndexOfAny([char[]]'\/') -ge 0) { throw 'The legacy TclKit origindist control record is invalid' }
        $LegacyPayloadFiles = @(Get-InstallBuilderLegacyPayloadEntry -Entry $MetakitEntries -Xml $Xml -Context $Context -OriginDirectory $OriginDirectory)
        $MetakitInfo = [pscustomobject][ordered]@{
          HeaderOffset     = $MetakitHeaderOffset
          Length           = $MetakitLength
          RootPosition     = $MetakitRootPosition
          RootLength       = $MetakitRootLength
          EntryCount       = $MetakitEntries.Count
          PayloadFileCount = $LegacyPayloadFiles.Count
          OriginDirectory  = $OriginDirectory
          CompressionTypes = @($LegacyPayloadFiles.Compression | Sort-Object -Unique)
        }
        if ($LegacyPayloadFiles.Count -eq 0) {
          $UnresolvedFields.Add('PayloadFiles')
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyDistAbsent' -Source 'InstallBuilder' -Message 'The legacy Metakit VFS is valid, but no package payload records match the compiled dist/<shortName>/<folderName> layout.' -Kind Incomplete -Areas Extraction -AffectedFields @()))
        }
        $UnsupportedLegacyCompression = @($LegacyPayloadFiles | Where-Object Compression -EQ 'Unknown')
        if ($UnsupportedLegacyCompression.Count) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyCompressionUnsupported' -Source 'InstallBuilder' -Message "$($UnsupportedLegacyCompression.Count) legacy Metakit payload record(s) use unsupported compression framing and cannot be extracted." -Kind Unsupported -Areas Extraction -AffectedFields @()))
        }
      } catch {
        $UnresolvedFields.Add('PayloadFiles')
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyMetakitUnsupported' -Source 'InstallBuilder' -Message "The legacy Metakit VFS payload catalog could not be decoded: $($_.Exception.Message)" -Kind Unsupported -Areas Extraction -AffectedFields @()))
      } finally {
        if ($LegacyArchive) { $LegacyArchive.Dispose() }
      }
    }
    foreach ($Diagnostic in @($ArpInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    $ExcludedRegistryWrites = @($RegistryWrites | Where-Object Lifecycle -NE 'Installation')
    if ($ExcludedRegistryWrites.Count) {
      $ExcludedPhases = @($ExcludedRegistryWrites.Phase | Sort-Object -Unique)
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.NonInstallPhaseExcluded' -Source InstallBuilder -Message "$($ExcludedRegistryWrites.Count) registry write(s) belong to non-installation or unresolved action phases and were excluded from authoritative ARP and association projection." -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') -Evidence ([pscustomobject]@{ Phases = $ExcludedPhases; Count = $ExcludedRegistryWrites.Count })))
    }
    if ($Project.Content -match 'MI_oJ|tcltwofish|installbuilder\.payloadinfo') {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.Encrypted' -Source InstallBuilder -Message 'The installer contains encrypted-payload markers. Project metadata was recovered, but payload extraction requires the project password.' -Kind Unsupported -Areas Extraction -AffectedFields @()))
    }
    if ($Cookfs -and $Cookfs.HasUnsupportedCompression) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.CompressionUnsupported' -Source InstallBuilder -Message 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password.' -Kind Unsupported -Areas Extraction -AffectedFields @()))
    }
    $PayloadCatalog = if ($Cookfs) { @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries -Xml $Xml -Context $Context) } else { @($LegacyPayloadFiles) }
    $PayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'True')
    $ConditionalPayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'Unknown')
    $ExcludedPayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'False')
    if ($Cookfs) {
      # Detect split segments whose base entry is missing; those cannot be safely reassembled.
      $PhysicalPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Entry in $Cookfs.Entries) { $null = $PhysicalPaths.Add($Entry.Path) }
      foreach ($Entry in $Cookfs.Entries) {
        $Match = [regex]::Match($Entry.Path, '^(?<Base>.+)___bitrockBigFile[1-9][0-9]*$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($Match.Success -and -not $PhysicalPaths.Contains($Match.Groups['Base'].Value)) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.OrphanedSplitSegment' -Source InstallBuilder -Message "CookFS payload contains an orphaned BitRock split segment: $($Entry.Path)" -Kind Invalid -Areas Extraction -AffectedFields @() -Evidence ([pscustomobject]@{ Path = $Entry.Path })))
        }
      }
    }
    if ($Context.InstallLocationResult.UnresolvedVariables.Count) {
      $UnresolvedFields.Add('DefaultInstallLocation')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Metadata.InstallLocationUnresolved' -Source InstallBuilder -Message "The installation directory contains unresolved runtime variables: $($Context.InstallLocationResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('DefaultInstallLocation') -Evidence ([pscustomobject]@{ Variables = $Context.InstallLocationResult.UnresolvedVariables })))
    }
    # Execution matching needs every packaged path so a conditional nested payload remains visible,
    # while PayloadFiles itself represents only the default-install selection.
    $ExecutionInfo = Get-InstallBuilderExecutionInfo -Xml $Xml -Context $Context -Payload $PayloadCatalog
    $ProjectActions = @(Get-InstallBuilderProjectActionInfo -Xml $Xml -Context $Context)
    $DynamicProjectLogic = @(Get-InstallBuilderDynamicLogicInfo -Xml $Xml -Context $Context -ProjectAction $ProjectActions)
    $ActionAssociationInfo = Get-InstallBuilderFileAssociationInfo -Xml $Xml -Context $Context
    $SystemEffectInfo = Get-InstallBuilderSystemEffectInfo -ProjectAction $ProjectActions
    foreach ($Diagnostic in @($ActionAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    # Registry writes and the native association action are separate runtime routes. Preserve both
    # evidence sets while exposing one authoritative installed-state list to provider projections.
    $FileExtensions = @($RegistryAssociationInfo.FileExtensions) + @($ActionAssociationInfo.FileExtensions) | Sort-Object -Unique
    $FileExtensionAssociations = @($RegistryAssociationInfo.FileExtensionAssociations) + @($ActionAssociationInfo.FileExtensionAssociations)
    $AssociationInfo = [pscustomobject][ordered]@{
      Protocols                 = @($RegistryAssociationInfo.Protocols)
      FileExtensions            = [string[]]$FileExtensions
      ProtocolAssociations      = @($RegistryAssociationInfo.ProtocolAssociations)
      FileExtensionAssociations = [object[]]$FileExtensionAssociations
      RegistryWrites            = @($RegistryAssociationInfo.RegistryWrites)
      ActionAssociations        = @($ActionAssociationInfo.FileExtensionAssociations)
      Diagnostics               = @(Merge-InstallerDiagnostics -Diagnostic (@($RegistryAssociationInfo.Diagnostics) + @($ActionAssociationInfo.Diagnostics)))
    }
    $Shortcuts = @(Get-InstallBuilderShortcutInfo -Xml $Xml -Context $Context -Payload $PayloadCatalog)
    $PrimaryExecutableCandidates = @(
      @($Shortcuts | Where-Object { $_.IsEmbeddedPayload -and $_.PayloadPath -match '(?i)\.exe$' } | ForEach-Object PayloadPath)
      @($ExecutionInfo.Actions | Where-Object { $_.IsEmbeddedPayload -and $_.PayloadPath -match '(?i)\.exe$' -and $_.Purpose -in 'InstallerAction', 'ApplicationLaunch' } | ForEach-Object PayloadPath)
    ) | Select-Object -Unique
    $PayloadAnalysis = if ($AnalyzePrimaryExecutables) {
      Get-InstallBuilderPrimaryPayloadAnalysis -Path $File.FullName -Payload $PayloadCatalog -PrimaryExecutableCandidate $PrimaryExecutableCandidates -Cookfs $Cookfs -MetakitLayouts $MetakitLayouts -MaximumAnalysisBytes $MaximumPayloadAnalysisBytes
    } else {
      [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = @() }
    }
    foreach ($Diagnostic in @($PayloadAnalysis.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    $ReviewableLogic = @($DynamicProjectLogic | Where-Object EvidenceKind -In 'Rule', 'ScriptOrExpression')
    if ($ReviewableLogic.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Project.DynamicLogic' -Source InstallBuilder -Message "$($ReviewableLogic.Count) project rule or script expression(s) require source review; inspect DynamicProjectLogic for exact source and referenced variable evidence." -Kind ManualValidation -Areas @('Metadata', 'Installability') -AffectedFields @($ReviewableLogic.AffectedFields | Sort-Object -Unique) -Evidence ([pscustomobject]@{ Count = $ReviewableLogic.Count })))
    }
    $Requirements = Get-InstallBuilderRequirementInfo -Xml $Xml -Context $Context
    if ($ExecutionInfo.NestedInstallerCandidates.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Execution.NestedInstallerCandidates' -Source InstallBuilder -Message "The compiled project executes $($ExecutionInfo.NestedInstallerCandidates.Count) embedded installer-like payload(s); inspect NestedInstallerCandidates before assigning outer ARP ownership or switches." -Kind ManualValidation -Areas @('Metadata', 'Installability') -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallerSwitches') -Evidence ([pscustomobject]@{ Payloads = @($ExecutionInfo.NestedInstallerCandidates.PayloadPath) })))
    }
    if ($Requirements.Java.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Requirement.Java' -Source InstallBuilder -Message "The compiled project contains $($Requirements.Java.Count) Java runtime detection action(s); review RuntimeRequirements before deciding whether the package needs an external dependency." -Kind Information -Areas Installability -AffectedFields @('Dependencies') -Evidence $Requirements.Java))
    }
    $ConditionalRegistryWrites = @($InstallationRegistryWrites | Where-Object ConditionState -EQ 'Unknown')
    if ($ConditionalRegistryWrites.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.ConditionsUnresolved' -Source InstallBuilder -Message "$($ConditionalRegistryWrites.Count) registry write(s) depend on runtime rules; those writes are retained as evidence but excluded from authoritative ARP and association projection." -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions')))
    }
    $UnresolvedRegistryWrites = @($InstallationRegistryWrites | Where-Object { @($_.UnresolvedVariables).Count })
    if ($UnresolvedRegistryWrites.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.ValuesUnresolved' -Source InstallBuilder -Message "$($UnresolvedRegistryWrites.Count) installation-time registry write(s) contain runtime variables and were excluded from exact association values where resolution was incomplete." -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') -Evidence ([pscustomobject]@{ Variables = @($UnresolvedRegistryWrites.UnresolvedVariables | Sort-Object -Unique) })))
    }
    if ($ConditionalPayloadFiles.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.ConditionsUnresolved' -Source InstallBuilder -Message "$($ConditionalPayloadFiles.Count) packaged payload file(s) depend on unresolved component, platform, or runtime conditions and were excluded from the default-install payload projection." -Kind Incomplete -Areas Extraction -AffectedFields @() -Evidence ([pscustomobject]@{ Count = $ConditionalPayloadFiles.Count })))
    }
    $AllowedModes = Get-InstallBuilderProjectProperty -Xml $Xml -Name allowedInstallationModes -NoDefault
    $AllowedModeTokens = @([string]$AllowedModes -split '[\s,;]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $SupportsInteractive = $AllowedModeTokens.Count -eq 0 -or @($AllowedModeTokens | Where-Object { $_ -ine 'unattended' }).Count -gt 0
    $SupportsUnattended = $AllowedModeTokens.Count -eq 0 -or $AllowedModeTokens -icontains 'unattended'
    # Legacy Metakit runtimes document unattended mode but predate unattendedModeUI. CookFS-era
    # projects can force silent or progress UI independently of the compiled project default.
    $SupportsUnattendedModeUi = $null -ne $Cookfs -or -not [string]::IsNullOrWhiteSpace((Get-InstallBuilderProjectProperty -Xml $Xml -Name unattendedModeUI -NoDefault))
    $InstallModes = [Collections.Generic.List[string]]::new()
    if ($SupportsInteractive) { $InstallModes.Add('interactive') }
    if ($SupportsUnattended) {
      $InstallModes.Add('silent')
      if ($SupportsUnattendedModeUi) { $InstallModes.Add('silentWithProgress') }
    }
    $InstallerSwitches = [ordered]@{}
    if ($SupportsUnattended) {
      $InstallerSwitches.Silent = $SupportsUnattendedModeUi ? '--mode unattended --unattendedmodeui none' : '--mode unattended'
      if ($SupportsUnattendedModeUi) { $InstallerSwitches.SilentWithProgress = '--mode unattended --unattendedmodeui minimal' }
    }
    $InstallCliOption = if ($Context.InstallParameter) { Get-InstallBuilderXmlValue -Xml $Context.InstallParameter -XPath 'cliOptionName' } else { $null }
    if ([string]::IsNullOrWhiteSpace($InstallCliOption) -and $Context.InstallParameter) { $InstallCliOption = 'installdir' }
    if ($InstallCliOption) { $InstallerSwitches.InstallLocation = "--$InstallCliOption `"<INSTALLPATH>`"" }
    $InstallerSwitches.Log = '--debugtrace "<LOGPATH>"'
    $ElevationRequirement = if ($Context.RequestedExecutionLevel -ieq 'requireAdministrator') { 'elevatesSelf' } elseif (Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name requireInstallationByRootUser)) { 'elevationRequired' } else { $null }
    $ManifestArpEntries = @($ArpInfo.VisibleEntries | ForEach-Object {
        $Entry = [ordered]@{}
        foreach ($Name in 'DisplayName', 'Publisher', 'DisplayVersion', 'ProductCode', 'InstallerType') {
          if ($null -ne $_.$Name -and -not [string]::IsNullOrWhiteSpace([string]$_.$Name)) { $Entry[$Name] = $_.$Name }
        }
        [pscustomobject]$Entry
      })
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ArpInfo.ProductCode
      UpgradeCode                  = $null
      DisplayName                  = if ($FullName) { $FullName } else { $ShortName }
      DisplayVersion               = $Version
      Publisher                    = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/vendor'
      Scope                        = $ScopeInfo.Scope
      DefaultInstallLocation       = $Context.InstallLocation
      WritesAppsAndFeaturesEntry   = $ArpInfo.WritesAppsAndFeatures
      AppsAndFeaturesProductCode   = $ArpInfo.WritesAppsAndFeatures -eq $true ? $ArpInfo.ProductCode : $null
      AppsAndFeaturesInstallerType = $ArpInfo.WritesAppsAndFeatures -eq $true ? 'exe' : $null
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = $UnresolvedFields.ToArray()
      Family                       = 'InstallBuilder'
      FormatGeneration             = $Cookfs ? 'CookFS2' : ($MetakitLayouts.Count ? 'LegacyMetakit' : 'ProjectRecord')
      ContainerRoute               = $Cookfs ? 'PE/MetakitVfs/CookFS2' : ($MetakitLayouts.Count ? 'PE/MetakitVfs' : 'ProjectRecord')
      ProjectSchemaVersion         = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/projectSchemaVersion'
      ProductCodeEvidence          = if ($ArpInfo.ProductCode) { 'InstallBuilder built-in windowsARPRegistryPrefix or unconditional literal registrySet ARP key.' } else { $null }
      SupportedScopes              = $ScopeInfo.SupportedScopes
      ScopeConfidence              = $ScopeInfo.Confidence
      ScopeEvidence                = $ScopeInfo.Evidence
      ShortcutScope                = Get-InstallBuilderProjectProperty -Xml $Xml -Name installationScope
      RequestedExecutionLevel      = $Context.RequestedExecutionLevel
      ElevationRequirement         = $ElevationRequirement
      RegistryView                 = $Context.RegistryView
      SupportsSilentInstallation   = $SupportsUnattended
      InstallModes                 = $InstallModes.ToArray()
      InstallerSwitches            = $InstallerSwitches
      InstallerSuccessCodes        = @()
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      AssociationInfo              = $AssociationInfo
      Protocols                    = $AssociationInfo.Protocols
      ProtocolAssociations         = $AssociationInfo.ProtocolAssociations
      FileExtensions               = $AssociationInfo.FileExtensions
      FileExtensionAssociations    = $AssociationInfo.FileExtensionAssociations
      EnvironmentChanges           = $SystemEffectInfo.EnvironmentChanges
      PathChanges                  = $SystemEffectInfo.PathChanges
      WindowsServices              = $SystemEffectInfo.WindowsServices
      ScheduledTasks               = $SystemEffectInfo.ScheduledTasks
      FontChanges                  = $SystemEffectInfo.FontChanges
      SharedDllChanges             = $SystemEffectInfo.SharedDllChanges
      WindowsAclChanges            = $SystemEffectInfo.WindowsAclChanges
      SystemEffects                = $SystemEffectInfo
      HasBuiltInUninstaller        = $ArpInfo.HasBuiltInUninstaller
      WritesBuiltInArp             = $ArpInfo.WritesBuiltInArp
      AppsAndFeaturesEntries       = $ManifestArpEntries
      ArpEntries                   = $ArpInfo.Entries
      VisibleArpEntries            = $ArpInfo.VisibleEntries
      HiddenArpEntries             = $ArpInfo.HiddenEntries
      UncertainArpEntries          = $ArpInfo.UncertainEntries
      Shortcuts                    = $Shortcuts
      PrimaryExecutableCandidates  = [string[]]$PrimaryExecutableCandidates
      PayloadArchitectureInfo      = $PayloadAnalysis.ArchitectureInfo
      PayloadArchitectures         = $PayloadAnalysis.Architectures
      PayloadDependencyInfo        = $PayloadAnalysis.DependencyInfo
      PayloadAnalysisFiles         = $PayloadAnalysis.InspectedFiles
      ProjectActions               = $ProjectActions
      DynamicProjectLogic          = $DynamicProjectLogic
      ExecutionActions             = $ExecutionInfo.Actions
      ExecutedPayloads             = $ExecutionInfo.ExecutedPayloads
      NestedInstallerCandidates    = $ExecutionInfo.NestedInstallerCandidates
      RuntimeRequirements          = $Requirements
      ProjectOffset                = $Project.Offset
      ProjectLength                = $Project.Length
      ExtractedFiles               = @('project.xml') + @($PayloadCatalog | ForEach-Object Path)
      PayloadCatalog               = $PayloadCatalog
      PackagedPayloadFiles         = @($PayloadCatalog | ForEach-Object Path)
      PayloadFiles                 = @($PayloadFiles | ForEach-Object Path)
      PayloadFileCount             = $PayloadFiles.Count
      PackagedPayloadFileCount     = $PayloadCatalog.Count
      ConditionalPayloadFiles      = @($ConditionalPayloadFiles | ForEach-Object Path)
      ConditionalPayloadFileCount  = $ConditionalPayloadFiles.Count
      ExcludedPayloadFiles         = @($ExcludedPayloadFiles | ForEach-Object Path)
      ExcludedPayloadFileCount     = $ExcludedPayloadFiles.Count
      CookfsInfo                   = if ($Cookfs) { [pscustomobject]@{ EndOffset = $Cookfs.EndOffset; IndexOffset = $Cookfs.IndexOffset; PageDataOffset = $Cookfs.PageDataOffset; PageCount = $Cookfs.PageCount; IndexSize = $Cookfs.IndexSize; CompressionIds = $Cookfs.CompressionIds; CompressionTypes = $Cookfs.CompressionTypes; HasUnsupportedCompression = $Cookfs.HasUnsupportedCompression } } else { $null }
      MetakitInfo                  = $MetakitInfo
      MetakitLayouts               = $MetakitLayouts
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallBuilder'; ParserMajor = 5; Sources = @('Metakit VFS JL/LJ header, column descriptors, and TclKit file schema', 'bounded zlib project record', 'CookFS CFS0002 footer and file index', 'phase-aware project action and payload selection model', 'source-preserving dynamic project logic evidence', 'native file-association, environment, PATH, and Windows-service actions') }
    }
  }
}

function Expand-InstallBuilderInstaller {
  <#
  .SYNOPSIS
    Extract selected unencrypted InstallBuilder payload files without execution
  .PARAMETER Name
    Matches project.xml and logical CookFS payload paths. BitRock split payloads
    ending in ___bitrockBigFileN are reassembled under their original file name.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $Path = (Get-Item -LiteralPath $Path -Force).FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallBuilder-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Extracted = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    [long]$TotalWritten = 0
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Project = $null

    # project.xml and CookFS payloads share one output budget but have independent recovery paths.
    if (Test-ExtractionPattern -Path 'project.xml' -Pattern $Name) {
      $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes))
      $Bytes = [Text.Encoding]::UTF8.GetBytes($Project.Content)
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath 'project.xml' `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if ($Target.ShouldWrite) {
        if ($Bytes.Length -gt $MaximumExpandedBytes) { throw 'The recovered InstallBuilder project exceeds the configured output limit' }
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
        [IO.File]::WriteAllBytes($Target.Path, $Bytes)
        $TotalWritten += $Bytes.Length
        $Extracted.Add((Get-Item -LiteralPath $Target.Path -Force))
      }
    }

    $Cookfs = $null
    $MetakitLayouts = @()
    try { $Cookfs = Get-InstallBuilderCookfsInfo -Path $Path } catch {
      $MetakitLayouts = @(Get-InstallBuilderMetakitLayout -Path $Path)
      if (-not $MetakitLayouts.Count -and $Extracted.Count -eq 0) { throw }
    }
    if ($Cookfs) {
      if (-not $Project) { $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes)) }
      $Xml = [xml]$Project.Content
      $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $Path
      $LogicalEntries = @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries -Xml $Xml -Context $Context | Where-Object {
          (Test-ExtractionPattern -Path $_.Path -Pattern $Name) -or (Test-ExtractionPattern -Path $_.PhysicalPath -Pattern $Name)
        })
      if ($LogicalEntries.Count -gt 0 -and $Cookfs.HasUnsupportedCompression) { throw 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password' }
      # Export logical rather than physical split-file names.
      $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        foreach ($Entry in $LogicalEntries) {
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Path `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try {
            Copy-InstallBuilderCookfsEntry -Stream $Source -Cookfs $Cookfs -Entry $Entry -Destination $Destination -TotalWritten ([ref]$TotalWritten) -MaximumExpandedBytes $MaximumExpandedBytes
          } finally {
            $Destination.Dispose()
          }
          $Extracted.Add((Get-Item -LiteralPath $Target.Path -Force))
        }
      } finally {
        $Source.Dispose()
      }
    }
    if (-not $Cookfs -and $MetakitLayouts.Count) {
      $LegacyArchive = $null
      try {
        if (-not $Project) { $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes)) }
        $Xml = [xml]$Project.Content
        $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $Path
        $LegacyArchive = Open-InstallBuilderMetakitArchive -Path $Path -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
        $OriginEntry = @($LegacyArchive.Entries | Where-Object Path -CEQ 'origindist')
        if ($OriginEntry.Count -ne 1) { throw 'The legacy TclKit VFS does not contain one unambiguous origindist control record' }
        $OriginDirectory = $Script:InstallBuilderStrictUtf8.GetString($LegacyArchive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim()
        if ([string]::IsNullOrWhiteSpace($OriginDirectory) -or $OriginDirectory.IndexOfAny([char[]]'\/') -ge 0) { throw 'The legacy TclKit origindist control record is invalid' }
        $LegacyEntries = @(Get-InstallBuilderLegacyPayloadEntry -Entry @($LegacyArchive.Entries) -Xml $Xml -Context $Context -OriginDirectory $OriginDirectory | Where-Object {
            (Test-ExtractionPattern -Path $_.Path -Pattern $Name) -or (Test-ExtractionPattern -Path $_.PhysicalPath -Pattern $Name)
          })
        foreach ($Entry in $LegacyEntries) {
          if ($Entry.Compression -eq 'Unknown') { throw "The legacy Metakit payload '$($Entry.PhysicalPath)' uses unsupported compression framing" }
          if ($TotalWritten -gt $MaximumExpandedBytes - $Entry.Size) { throw 'The InstallBuilder payload exceeds the configured output limit' }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Path `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try {
            $Written = $LegacyArchive.CopyEntry([int]$Entry.Index, $Destination, $MaximumExpandedBytes - $TotalWritten)
            $TotalWritten += $Written
          } catch {
            # Close the partial output before deleting it; the stream deliberately denies sharing.
            $Destination.Dispose()
            $Destination = $null
            Remove-Item -LiteralPath $Target.Path -Force -ErrorAction SilentlyContinue
            throw
          } finally {
            if ($Destination) { $Destination.Dispose() }
          }
          $Extracted.Add((Get-Item -LiteralPath $Target.Path -Force))
        }
      } finally {
        if ($LegacyArchive) { $LegacyArchive.Dispose() }
      }
    }
    if ($Extracted.Count -eq 0) { throw "No InstallBuilder project or payload file matches selector '$Name'" }
    return $Extracted.ToArray()
  }
}

function Test-InstallBuilder {
  <#
  .SYNOPSIS
    Test whether a PE contains a supported structured InstallBuilder container
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      # A recoverable project record is useful to low-level callers, but detection additionally
      # requires a real PE and a validated Metakit or CookFS container relationship.
      if (-not (Get-PELayout -Path $Path)) { return $false }
      $Info = Get-InstallBuilderInfo -Path $Path
      return [bool]($Info.CookfsInfo -or @($Info.MetakitLayouts).Count)
    } catch {
      return $false
    }
  }
}

function Read-ProtocolsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the version from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the product name from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayName }
}
function Read-PublisherFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the publisher from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the candidate InstallBuilder uninstaller key
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).ProductCode }
}
function Read-ScopeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the statically proven InstallBuilder installation scope
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallBuilderInfo, Expand-InstallBuilderInstaller, Test-InstallBuilder, Read-ProtocolsFromInstallBuilder, Read-FileExtensionsFromInstallBuilder, Read-ProductVersionFromInstallBuilder, Read-ProductNameFromInstallBuilder, Read-PublisherFromInstallBuilder, Read-ProductCodeFromInstallBuilder, Read-ScopeFromInstallBuilder
