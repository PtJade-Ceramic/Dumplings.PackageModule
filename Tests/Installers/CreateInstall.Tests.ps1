. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive

  function New-TestCreateInstallFixture {
    param(
      [Parameter(Mandatory)][string]$Path,
      [ValidateRange(0, 1048576)][int]$PrefixLength = 512
    )

    $Content = [Text.Encoding]::UTF8.GetBytes('static CreateInstall payload')
    $MetadataStream = [IO.MemoryStream]::new()
    $MetadataWriter = [IO.BinaryWriter]::new($MetadataStream, [Text.Encoding]::UTF8, $true)
    try {
      $MetadataWriter.Write([uint16]0)
      $MetadataWriter.Write([long]0)
      $MetadataWriter.Write([uint64]$Content.Length)
      $MetadataWriter.Write([uint64](9 + $Content.Length))
      # GEA stores the running CRC seeded with 0xFFFFFFFF, without CRC32's final XOR.
      $MetadataWriter.Write([uint32]((Get-BinaryCrc32 -Bytes $Content) -bxor [uint32]::MaxValue))
      $MetadataWriter.Write([Text.Encoding]::UTF8.GetBytes('payload.txt'))
      $MetadataWriter.Write([byte]0)
    } finally { $MetadataWriter.Dispose() }
    $Metadata = $MetadataStream.ToArray()
    $HeaderSize = 74 + $Metadata.Length
    $SummarySize = 9 + $Content.Length
    $ArchiveFileSize = $PrefixLength + $HeaderSize + $SummarySize

    $Output = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Output, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([byte[]]::new($PrefixLength))
      $Writer.Write([Text.Encoding]::ASCII.GetBytes("GEA`0"))
      $Writer.Write([uint16]0)
      $Writer.Write([uint32]0x12345678)
      $Writer.Write([byte]2)
      $Writer.Write([byte]0)
      $Writer.Write([long]0)
      $Writer.Write([uint32]0)
      $Writer.Write([uint16]1)
      $Writer.Write([uint32]$HeaderSize)
      $Writer.Write([long]$SummarySize)
      $Writer.Write([uint32]$Metadata.Length)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([uint32]0)
      $Writer.Write([byte]8)
      $Writer.Write([byte]1)
      $Writer.Write([byte]1)
      $Writer.Write([byte]0)
      $Writer.Write($Metadata)
      $Writer.Write([byte]0x80)
      $Writer.Write([uint64]$Content.Length)
      $Writer.Write($Content)
    } finally { $Writer.Dispose() }
    [IO.File]::WriteAllBytes($Path, $Output.ToArray())
  }
}

Describe 'CreateInstall static parser' {
  It 'Should parse and expand a bounded GEA v2 stored file' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall.exe'
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-expanded'
    New-TestCreateInstallFixture -Path $FixturePath
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath; DestinationPath = $DestinationPath } {
      param($FixturePath, $DestinationPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'requireAdministrator' }
      $Info = Get-CreateInstallInfo -Path $FixturePath
      $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -CollisionAction Rename)

      $Info.GEA.MajorVersion | Should -Be 2
      $Info.GEA.EntryCount | Should -Be 1
      $Info.GEA.CompressionMethods | Should -Be @('Store')
      $Info.Scope | Should -Be 'machine'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.UninstallRegistrations | Should -BeNullOrEmpty
      $Info.CanExpand | Should -BeTrue
      $Files.Name | Should -Be @('payload.txt')
      Get-Content -LiteralPath $Files[0].FullName -Raw | Should -Be 'static CreateInstall payload'
    }
  }

  It 'Should decode a source-backed LZGE order-six regression vector' {
    InModuleScope CreateInstall {
      Import-CreateInstallLzgeDecoder
      # Compressed dlgsets.res block from the external real-installer fixture.
      $Compressed = [Convert]::FromBase64String('SbGuB7oAAABax+/4Rks3R5B1UJUlTtymSUq5CSdFqE7FOjuEfVOqp4HoAdnk1Qzu66kVbwObkpO+52PRlK48jwueFvTzw7nh4btvQ8O6vJ/dHs06vBt13o1vDvvQCzWiROqTeN0Ij3bS6qwwSAQDJYwjAMQvzFaPjeW6fvatqXmx+he4pKKr5aRt0cbRGrvU7MYyzQMogmcs4PQqsFyi1IVV/L1Wxnf/L2i4Ql/L32asbki9hI49IzZkk8TmmbobK6Jtl4WJDX03EypK69jr54v9ArD7XjZ3TfHQpnmaZjG9W9Oo52VMXW+L0eoni7q/3fz1KttSBRXm5LdFfeTkKSql8ESTfmbvi0U1jDMiof4F9dwsqVzn2Rpex+P4Zb/x/ZCYpvcXhA==')
      $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($Compressed, 588)

      $Decoded.Length | Should -Be 588
      [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Decoded)) |
        Should -Be 'F28B2E9BAF05FFC72B3059C354EA35A10AA65AE3A574B7110885545699B265CD'
    }
  }

  It 'Should parse a standalone GEA image such as the SETUP_TEMP resource' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall-standalone.gea'
    New-TestCreateInstallFixture -Path $FixturePath -PrefixLength 0

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath

      $Layout.ArchiveOffset | Should -Be 0
      $Layout.Entries.FullName | Should -Be @('payload.txt')
    }
  }

  It 'Should classify official CreateInstall <Version> media through structural archive and ARP profiles' -ForEach @(
    @{ Version = '5.9.0'; FixtureName = 'CreateInstall.Builder.5.9.0.exe'; Sha256 = '0FA71D24ED44035B15055A5356CD76BD76D43A16EC136A65F82B00928E91AB15'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 431; WritesNoModify = $false }
    @{ Version = '5.19.1'; FixtureName = 'CreateInstall.Builder.5.19.1.exe'; Sha256 = 'DA515094D2A287CB402FA5B2B551BF668498A24BBC20C543D3E415799E15B06E'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 596; WritesNoModify = $false }
    @{ Version = '6.0.0'; FixtureName = 'CreateInstall.Builder.6.0.0.exe'; Sha256 = '496E27D83EB5AB8FB4228D5D422DAB5FFA0461A81B76580DB71CD57941DDC95D'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 605; WritesNoModify = $false }
    @{ Version = '6.3.3'; FixtureName = 'CreateInstall.Builder.6.3.3.exe'; Sha256 = '3A32FB655FD7A47215B4ADF0350DA1653F6B108260C2212B1164EED5F131EFA6'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 623; WritesNoModify = $false }
    @{ Version = '6.4.0'; FixtureName = 'CreateInstall.Builder.6.4.0.exe'; Sha256 = '4B61EA517EE0B5AA1453363E09D3B1036D3A2E261B2A95356D557EAC1C31132E'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 635; WritesNoModify = $false }
    @{ Version = '7.0.6'; FixtureName = 'CreateInstall.Builder.7.0.6.exe'; Sha256 = '1243CC0DED031C68E75583F2A7E6FC7AD5CDCA042C621B922E232BC82DC92488'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 631; WritesNoModify = $false }
    @{ Version = '7.0.19'; FixtureName = 'CreateInstall.Builder.7.0.19.exe'; Sha256 = '1538F0CC02B5DC9D824471313C7A8919A87CE8F24E19C4C27F5C957B3F871A62'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 630; WritesNoModify = $false }
    @{ Version = '7.0.26'; FixtureName = 'CreateInstall.Builder.7.0.26.exe'; Sha256 = '17948F38CFA87BB333DED387CFC89D1BE618C430183985B9DD6EF58B62D5DBE1'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Policy4'; ProductCode = 'CreateInstall'; EntryCount = 630; WritesNoModify = $true }
    @{ Version = '7.1.3'; FixtureName = 'CreateInstall.Builder.7.1.3.exe'; Sha256 = '2A37DE3516E6698B6DAEEB3EB90E691CABD17EC73287F225DC82BA456E78111A'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Policy4'; ProductCode = 'CreateInstall'; EntryCount = 633; WritesNoModify = $true }
    @{ Version = '7.1.7'; FixtureName = 'CreateInstall.Builder.7.1.7.exe'; Sha256 = '9529AF370EC0F3328ABB66D0417CAF49E262D054CEE7B685FEE888C7FAC81C44'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 635; WritesNoModify = $true }
    @{ Version = '7.4.0'; FixtureName = 'CreateInstall.Builder.7.4.0.exe'; Sha256 = 'E060C09D45F7ACBF929B4BEE7EB892AEBAF7047AFA5AE3D0449EEEABD5AC6766'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 652; WritesNoModify = $true }
    @{ Version = '8.0.1'; FixtureName = 'CreateInstall.Builder.8.0.1.exe'; Sha256 = '1D0105E0066958D478C22CFAB7FA362E6023F487C5B9950E6E4FE4A8744F81A8'; ArchiveProfile = 'GEA2'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 665; WritesNoModify = $true }
  ) {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $FixtureName)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because "Cache the official CreateInstall $Version builder fixture."
      return
    }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.DisplayVersion | Should -Be $Version
    $Info.GEA.ArchiveProfile | Should -Be $ArchiveProfile
    $Info.GEA.EntryCount | Should -Be $EntryCount
    $Info.GenteeProgram.VersionMajor | Should -Be 4
    $Info.GenteeProgram.VersionMinor | Should -Be 0
    $Info.GenteeProgram.AddRemoveProfile | Should -Be $AddRemoveProfile
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be 'machine'
    $Info.UninstallRegistrations | Should -HaveCount 1
    $Info.UninstallRegistrations[0] | Should -Not -BeNullOrEmpty
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\CreateInstall'
    $Info.UninstallString | Should -Be '"%ProgramFiles(x86)%\CreateInstall\uninstall.exe"'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'UninstallString'
    @($Info.RegistryWrites | Where-Object Name -EQ 'NoModify').Count | Should -Be ([int]$WritesNoModify)
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should let later custom registry values override generated ARP values' {
    InModuleScope CreateInstall {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'DisplayName'; Value = 'Generated name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'Publisher'; Value = 'Generated publisher'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'DisplayName'; Value = 'Custom name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'DisplayName'; Value = 'Hidden name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'SystemComponent'; Value = 1; Type = 'REG_DWORD'; IsConditional = $false }
      )

      $Evidence = Get-CreateInstallArpEvidence -RegistryWrite $Writes

      $Evidence.VisibleEntries | Should -HaveCount 1
      $Evidence.VisibleEntries[0].DisplayName | Should -Be 'Custom name'
      $Evidence.ProductCodes | Should -Be @('Generated')
      $Evidence.Scopes | Should -Be @('machine')
      $Evidence.AppsAndFeaturesEntries | Should -HaveCount 1
      $Evidence.Entries | Should -HaveCount 2
      $Evidence.Diagnostics.Id | Should -Be @('CreateInstall.ARP.Hidden')
    }
  }

  It 'Should expand a GEA1 LZGE payload from the oldest cached builder' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Builder.5.9.0.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 '0FA71D24ED44035B15055A5356CD76BD76D43A16EC136A65F82B00928E91AB15')) {
      Set-ItResult -Skipped -Because 'Cache the official CreateInstall 5.9.0 builder fixture.'
      return
    }
    $DestinationPath = Join-Path $TestDrive 'createinstall-gea1-expanded'

    $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'close.gt' -CollisionAction Error)

    $Files | Should -HaveCount 1
    $Files[0].Length | Should -Be 1215
    (Get-FileHash -LiteralPath $Files[0].FullName -Algorithm SHA256).Hash | Should -Be 'F2C22B0F121E3F2973EBB67FC0D4F9B68E8681CD8A4B855334EA44E12A68C98F'
  }

  It 'Should reject pre-CreateInstall Gentee Installer media rather than weaken GEA detection' -ForEach @(
    @{ Name = 'CreateInstall.Predecessor.ci2000.exe'; Sha256 = '64D04E194898BE7604E374D2AB545AE73DFF336132AE2F2A8D9A4002F648C461' }
    @{ Name = 'CreateInstall.Predecessor.setupgen.exe'; Sha256 = 'F6E425BAFB7057592E631F0D4267CBC5112520A32B2AAE2957DF0BE0405055AE' }
    @{ Name = 'CreateInstall.Predecessor.sgpro.exe'; Sha256 = '2A4C129B04490E66CB40C9C0F57DFA8FE83E4BD5DEA211D911066FC3A90A6E19' }
  ) {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 $Sha256)) { Set-ItResult -Skipped -Because "Cache the predecessor fixture $Name."; return }

    Test-CreateInstall -Path $FixturePath | Should -BeFalse
  }

  It 'Should derive Balabolka ARP identity from its compiled addremoveext call' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'Balabolka'
    $Info.ProductCodeEvidence | Should -Match '^Deterministic CreateInstall uninstall registry writes:'
    $Info.GEA.ArchiveProfile | Should -Be 'GEA2'
    $Info.GenteeProgram.AddRemoveProfile | Should -Be 'Extended5'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.UninstallKeyName | Should -Be @('Balabolka')
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Balabolka'
    $Info.UninstallString | Should -Be '"%ProgramFiles(x86)%\Balabolka\uninstall.exe"'
    $Info.FileExtensions | Should -Be @('bxt', 'bxz')
    $Info.PayloadArchitectures | Should -Be @('x86')
    $Info.PayloadAnalysisFiles | Should -Contain '%ProgramFiles(x86)%\Balabolka\balabolka.exe'
    $Info.PayloadDependencyInfo.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x86'
    $Info.GEA.UnsupportedCompressionMethods | Should -Not -Contain 'PPMd'
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.InstallGroup.ConditionDynamic'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Shortcut.Conditional'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Run.Conditional'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Registry.Conditional'
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
    $Expression = @($Info.GenteeExpressions | Where-Object { $_.Operation -eq 'InstallGroup' -and $_.Expression -ceq '@if73_used' })
    $Expression | Should -HaveCount 1
    $Expression[0].ExpressionKind | Should -Be 'FunctionCondition'
    $Expression[0].RequiresReview | Should -BeTrue
    $Expression[0].FunctionFound | Should -BeTrue
    $Expression[0].ReferencedFunction.Name | Should -Be 'if73_used'
    $Expression[0].ReferencedFunction.CommandsTruncated | Should -BeFalse
    $Expression[0].ReferencedFunction.LiteralStrings | Should -Contain 'oswindows'
    $RuntimeVariable = @($Expression[0].Variables | Where-Object Name -EQ 'oswindows')
    $RuntimeVariable | Should -HaveCount 1
    $RuntimeVariable[0].Source | Should -Be 'RuntimeOrUnknown'
    $RuntimeVariable[0].IsDefined | Should -BeFalse
  }

  It 'Should expand source-backed PPMd and solid-continuation payloads from Balabolka' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-ppmd-expanded'
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    $Wave = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'clipboard.wav' -CollisionAction Rename)
    $Wave.Length | Should -Be 1
    $Wave[0].Length | Should -Be 10328
    (Get-FileHash -LiteralPath $Wave[0].FullName -Algorithm SHA256).Hash |
      Should -Be 'B2391C7751F6EC3296650D6D15C280DA53B6266E2BF5DEEF15DD729C7DA745ED'

    # This executable spans one model-initializing block and six order-1 continuation blocks,
    # exercising allocator exhaustion and the source-matched glue pass.
    $Executable = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'balabolka.exe' -CollisionAction Rename)
    $Executable.Length | Should -Be 1
    $Executable[0].Length | Should -Be 12807680
    (Get-FileHash -LiteralPath $Executable[0].FullName -Algorithm SHA256).Hash |
      Should -Be '0F1312B1A343A0999A854D32E86CC07A5AC3E46F1883021404D9E44D1D9BB58B'
  }

  It 'Should reject physical and declared GEA PPMd truncation without reading adjacent bytes' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath
      $Entry = $Layout.Entries | Where-Object FullName -EQ 'clipboard.wav' | Select-Object -First 1
      $Block = @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)[0]
      $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize)
      $Truncated = [byte[]]::new($InputBytes.Length - 1)
      [Array]::Copy($InputBytes, $Truncated, $Truncated.Length)
      Import-CreateInstallPpmdDecoder
      $Decoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new(
        [int]([uint32]$Layout.MemoryMegabytes * 1MB)
      )
      try {
        $InputStream = [IO.MemoryStream]::new($Truncated, $false)
        try {
          { $Decoder.DecodeBlock($InputStream, $Truncated.Length, [int]$Block.OutputSize, $Block.CompressionOrder) } |
            Should -Throw '*PPMd*'
        } finally { $InputStream.Dispose() }
      } finally { $Decoder.Dispose() }

      # Keep the omitted byte physically available but outside the declared range. This models the
      # CreateInstall extractor's read-ahead cache and proves the provider does not cross the GEA
      # record boundary to make a malformed compressed size appear valid.
      $Decoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new(
        [int]([uint32]$Layout.MemoryMegabytes * 1MB)
      )
      try {
        $InputStream = [IO.MemoryStream]::new($InputBytes, $false)
        try {
          { $Decoder.DecodeBlock($InputStream, $InputBytes.Length - 1, [int]$Block.OutputSize, $Block.CompressionOrder) } |
            Should -Throw '*PPMd*'
          $InputStream.Position | Should -BeLessOrEqual ($InputBytes.Length - 1)
        } finally { $InputStream.Dispose() }
      } finally { $Decoder.Dispose() }
    }
  }

  It 'Should derive the builder ARP identity without package-specific rules' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Novostrim.CreateInstall.8.11.2.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official CreateInstall builder fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'CreateInstall'
    $Info.GEA.ArchiveProfile | Should -Be 'GEA2'
    $Info.GenteeProgram.AddRemoveProfile | Should -Be 'Extended5'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.Count | Should -Be 1
    $Info.FileExtensions | Should -Be @('ci', 'ciq')
    $Info.InstallerSwitches.Silent | Should -Be '-silent'
    @($Info.Shortcuts | Where-Object Route -EQ 'List') | Should -HaveCount 4
    $Info.Shortcuts.ShortcutPath | Should -Contain '%APPDATA%\Microsoft\Windows\Start Menu\Programs\CreateInstall\Quick CreateInstall.lnk'
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should decode source-generated MSI child execution without relying on function names' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Generated.RunMsi.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 'B69078BDE20EC7166AF55650B459D95F8E0449BF2D03B5968D16CC94B48CE39D')) { Set-ItResult -Skipped -Because 'Cache the source-generated CreateInstall Run MSI fixture.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath
    $MsiRuns = @($Info.ExecutedPayloads | Where-Object Kind -EQ 'Msi')
    $ExecutableRuns = @($Info.ExecutedPayloads | Where-Object Kind -EQ 'Executable')

    $ExecutableRuns | Should -HaveCount 1
    $ExecutableRuns[0].Executable | Should -Be 'notepad.exe'
    $MsiRuns | Should -HaveCount 2
    $MsiRuns.MsiFlags | Should -Be @(10, 10)
    $MsiRuns.MsiAction | Should -Be @('Install', 'Install')
    $MsiRuns.NestedInstallerPath | Should -Be @('%ProgramFiles(x86)%\Wait for event\probe.msi', '%ProgramFiles(x86)%\Wait for event\probe.msi')
    $MsiRuns.Arguments | Should -Be @('/l* "%TEMP%\probe.log" /i "%ProgramFiles(x86)%\Wait for event\probe.msi" /quiet /norestart', '/l* "%TEMP%\probe.log" /i "%ProgramFiles(x86)%\Wait for event\probe.msi" /quiet /norestart')
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should accept a source-generated no-payload project without fabricating an archive' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Generated.NoPayload.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 '7E961D905C07BFF8E4AFFE4DBC2AD20D51BC11D44E91E27A07C06988FE0BF14E')) { Set-ItResult -Skipped -Because 'Cache the source-generated CreateInstall no-payload fixture.'; return }

    Test-CreateInstall -Path $FixturePath | Should -BeTrue
    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.GEA | Should -BeNullOrEmpty
    $Info.ExtractedFiles | Should -BeNullOrEmpty
    $Info.CanExpand | Should -BeFalse
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Archive.Absent'
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }
}
