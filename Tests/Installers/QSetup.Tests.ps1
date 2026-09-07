. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.WriteByte(0); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
  }

  function ConvertTo-TestQSetupFooter {
    param(
      [Parameter(Mandatory)][uint32]$OverlayOffset,
      [Parameter(Mandatory)][uint32]$RecordCount,
      [ValidateSet('Compact12', 'Legacy74', 'Modern74')][string]$Route = 'Modern74'
    )
    if ($Route -eq 'Compact12') {
      return [BitConverter]::GetBytes($RecordCount) + [BitConverter]::GetBytes($OverlayOffset) + [BitConverter]::GetBytes([uint32]0x4A3B2C1D)
    }
    $Footer = [byte[]]::new(74)
    foreach ($Value in @(
        @{ Offset = 0; Value = [uint32]0x201 },
        @{ Offset = 4; Value = $OverlayOffset },
        @{ Offset = 8; Value = $RecordCount },
        @{ Offset = 12; Value = [uint32]0x4A3B2C1D },
        @{ Offset = 16; Value = $Route -eq 'Modern74' ? [uint32]1234 : [uint32]0x10203040 },
        @{ Offset = 70; Value = [uint32]$Footer.Length }
      )) {
      [Buffer]::BlockCopy([BitConverter]::GetBytes($Value.Value), 0, $Footer, $Value.Offset, 4)
    }
    return $Footer
  }
}

Describe 'QSetup static parser' {
  It 'Should parse explicit Setup.txt ARP, scope, architecture, and association directives' {
    $SetupText = @'
SET_PROG_NAME(Example QSetup Product);
SET_PROJECT_NAME(ExampleProject);
SET_PROG_VERSION(4.5.6);
SET_COMPANY_NAME(Example Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\Example);
SET_PROG_EXE_NAME(<Application Folder>\Example.exe);
SET_CREATE_UNINSTALL;
SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS;
SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME(Example QSetup ARP);
SET_UNINSTALL_EXE_NAME(uninstall_example.exe);
SET_ALL_USERS;
SET_ALLOWED_OS(10.64,11.64);
SET_SUB_DIR(<Application Folder>\bin);
SET_COPY_FILES(Engine.exe);
SET_ADD_ASSOCIATION_ITEM(|Example.Document|Example document|.example|Example|<Application Folder>\Example.exe|<Application Folder>\Example.exe|0|Create|Remove||);
SET_PERFORM_EXECUTE_OP(*||Install prerequisite|Setup Start|10|UnConditional|0|0|File Found||0|0|0|File Found||0|0|0|File Found||1|Run Executable and Wait||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|*|||=||||=||||=|||<SrcDir>\runtime.exe|/quiet /norestart||||||||||||||||||*);
'@
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example QSetup ARP'
      $Info.DisplayVersion | Should -Be '4.5.6'
      $Info.Publisher | Should -Be 'Example Publisher'
      $Info.ProductCode | Should -Be 'Example QSetup ARP'
      $Info.Scope | Should -Be 'machine'
      $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Example'
      $Info.SupportedArchitectures | Should -Be @('x64')
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.FileExtensions | Should -Be @('example')
      $Info.Records.Name | Should -Be @('Engine.exe', 'Setup.txt')
      @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
      @($Info.Diagnostics | Where-Object Kind -EQ Information) | Should -HaveCount 1
      $Info.ExecutionActions | Should -HaveCount 1
      $Info.ExecutedPayloads | Should -HaveCount 1
      $Info.ExecutedPayloads[0].Command | Should -Be '<SrcDir>\runtime.exe'
      $Info.ExecutedPayloads[0].Parameters | Should -Be '/quiet /norestart'
      $Info.PayloadCatalog | Should -HaveCount 1
      $Info.PayloadCatalog[0].InstalledPath | Should -Be '%ProgramFiles%\Example\bin\Engine.exe'

      $Destination = Join-Path $TestDrive 'qsetup-installed-extraction'
      $Files = Expand-QSetupInstaller -Path $FixturePath -DestinationPath $Destination -CollisionAction Error
      $Files | Should -HaveCount 1
      $Files[0].FullName | Should -Be (Join-Path $Destination 'bin\Engine.exe')
      [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'MZ engine'
    }
  }

  It 'Should stop at the validated QSetup footer instead of treating it as a compressed record' {
    $SetupText = "SET_PROG_NAME(Footer Product);`r`nSET_PROG_VERSION(1.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 2
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-footer-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath
      $Info.Diagnostics | Should -BeNullOrEmpty
      $Info.Records | Should -HaveCount 2
      $Info.PackageFooter.DeclaredRecordCount | Should -Be 2
      $Info.Certificate | Should -BeNullOrEmpty

      $Destination = Join-Path $TestDrive 'qsetup-footer-extraction'
      $Files = Expand-QSetupInstaller -Path $FixturePath -DestinationPath $Destination -Name 'Setup.txt' -RawRecords -CollisionAction Error
      $Files | Should -HaveCount 1
      $Files[0].Name | Should -Be 'Setup.txt'
      $Files[0].FullName | Should -Be (Join-Path $Destination '_qsetup\records\Setup.txt')
    }
  }

  It 'Should classify the direct-record and double-pipe historical routes' -ForEach @(
    @{ Name = 'direct'; Prefix = $null; FooterRoute = 'Compact12'; Generation = 'Legacy1-2'; PreambleRoute = 'DirectRecords' }
    @{ Name = 'double-pipe'; Prefix = 'DoublePipe'; FooterRoute = 'Legacy74'; Generation = 'Legacy3-5'; PreambleRoute = 'DoublePipePreamble' }
  ) {
    $SetupText = "SET_COMPOSER_BUILD(5.0);`r`nSET_PROG_NAME(Historical QSetup);"
    $RecordBytes = ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    if ($Prefix -eq 'DoublePipe') {
      $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|historical|0|')
      $PackagePrefix = [BitConverter]::GetBytes([uint32]5) + [Text.Encoding]::ASCII.GetBytes('||') + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    } else {
      $PackagePrefix = [byte[]]@()
    }
    $FixtureBytes = [byte[]]::new(512) + $PackagePrefix + $RecordBytes
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1 -Route $FooterRoute
    $FixturePath = Join-Path $Script:FixtureDirectory "synthetic-$Name-qsetup.exe"
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath; Generation = $Generation; PreambleRoute = $PreambleRoute; FooterRoute = $FooterRoute } {
      param($FixturePath, $Generation, $PreambleRoute, $FooterRoute)
      Mock Get-PEOverlayOffset { 512 }
      $Layout = Get-QSetupLayout -Path $FixturePath
      $Layout.Complete | Should -BeTrue
      $Layout.FormatGeneration | Should -Be $Generation
      $Layout.StructuralRoutes | Should -Be @($PreambleRoute, 'Record/Zlib', $FooterRoute)
    }
  }

  It 'Should decode the legacy four-command execution layout' {
    InModuleScope QSetup {
      $Fields = [string[]]::new(59)
      $Fields[0] = '*'
      $Fields[2] = 'Legacy prerequisite'
      $Fields[3] = 'Setup Start'
      $Fields[20] = '1'
      $Fields[21] = 'Run Executable and Wait'
      $Fields[32] = '*'
      $Fields[46] = '<SrcDir>\legacy.exe'
      $Fields[47] = '/silent'
      $Fields[58] = '*'
      $Action = ConvertFrom-QSetupExecutionAction -Content ($Fields -join '|')
      $Action.LayoutRoute | Should -Be 'LegacyFourCommand'
      $Action.Commands | Should -HaveCount 1
      $Action.Commands[0].Argument1 | Should -Be '<SrcDir>\legacy.exe'
    }
  }

  It 'Should normalize deterministic aliases and parent segments' {
    InModuleScope QSetup {
      $Directive = @{
        SET_TARGET_DIR = [Collections.Generic.List[object]]@('<ProgramFiles>\Vendor\App')
        SET_COMMON_DIR = [Collections.Generic.List[object]]@('<InstallDir>\..\Shared')
      }
      ConvertTo-QSetupManifestPath -Value '<Application Folder>\bin\app.exe' -Directive $Directive | Should -Be '%ProgramFiles%\Vendor\App\bin\app.exe'
      ConvertTo-QSetupManifestPath -Value '<Common Folder>\data' -Directive $Directive | Should -Be '%ProgramFiles%\Vendor\Shared\data'
      ConvertTo-QSetupManifestPath -Value '<Application Folder>\..\..\..\escape.exe' -Directive $Directive | Should -BeNullOrEmpty
    }
  }

  It 'Should retain malformed execution-action records as warnings' {
    InModuleScope QSetup {
      $Directive = @{ SET_PERFORM_EXECUTE_OP = [Collections.Generic.List[object]]@('unsupported-layout') }
      $Result = Get-QSetupExecutionActionInfo -Directive $Directive
      $Result.Actions | Should -BeNullOrEmpty
      $Result.ExecutedPayloads | Should -BeNullOrEmpty
      $Result.Diagnostics | Should -HaveCount 1
    }
  }

  It 'Should parse representative historical Pantaray media' -ForEach @(
    @{ Version = '1.0.0.1'; Sha256 = 'C9C3F625295DCB5CB3675B79DFEE8EB5C9FF9E4B7ADEB93D395AF53D40A70EFB'; Generation = 'Legacy1-2'; Footer = 'Compact12'; ActionRoute = 'LegacyFourCommand' }
    @{ Version = '5.0.0.0'; Sha256 = '606EF42EF079CC630F79D6E9013F65BE67EBA64E2D7AF99CEDBEA6F07089D629'; Generation = 'Legacy3-5'; Footer = 'Legacy74'; ActionRoute = 'LegacyFourCommand' }
    @{ Version = '8.1.0.2'; Sha256 = '88C8F4BD3819696C765A1FF33935BA769BE6658DB9E1334FB1CD89FCA74C189C'; Generation = 'Legacy7-8'; Footer = 'Legacy74'; ActionRoute = 'ModernSixCommand' }
  ) {
    $RelativePath = "Installers\QSetup\Pantaray.QSetup\$Version\qstp.exe"
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because "Cache the historical QSetup $Version fixture from the source URL recorded in the QSetup internals reference."
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.DisplayVersion | Should -Be $Version
    $Info.FormatGeneration | Should -Be $Generation
    $Info.PackageFooter.RouteId | Should -Be $Footer
    $Info.ExecutionActions | Should -Not -BeNullOrEmpty
    $Info.ExecutionActions[0].LayoutRoute | Should -Be $ActionRoute
    $Info.CanExpand | Should -BeTrue
    $Info.PayloadCatalog | Should -Not -BeNullOrEmpty
    @($Info.PayloadCatalog | Where-Object { -not $_.InstalledPath }) | Should -BeNullOrEmpty
  }

  It 'Should recover current QSetup ARP, association, path, and payload evidence' {
    $RelativePath = 'Installers\QSetup\Pantaray.QSetup\12.0.0.5\qstp.exe'
    $Sha256 = 'E75A31A8E51757C9CA7C33EF836EAE8387139884F2C0B94A9BBD228EFA212ED7'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because 'Cache the official QSetup 12.0.0.5 fixture.'
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.DisplayName | Should -Be 'QSetup Installation Suite'
    $Info.ProductCode | Should -Be 'QSetup Installation Suite'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Pantaray'
    $Info.UninstallString | Should -Be '%ProgramFiles%\Pantaray\uninstall_qstp.exe'
    $Info.FileExtensions | Should -Contain 'qsp'
    $Info.FormatGeneration | Should -Be 'Modern12'
    $Info.PayloadCatalog.Count | Should -BeGreaterThan 100
    $Info.PayloadCatalog.InstalledPath | Should -Contain '%ProgramFiles%\Pantaray\QSetup\Composer.exe'
    $Info.Shortcuts.Target | Should -Contain '%ProgramFiles%\Pantaray\QSetup\Composer.exe'
    $Info.Shortcuts.Target | Should -Contain 'http://www.pantaray.com'

    $Destination = Join-Path $TestDrive 'qsetup-current-extraction'
    $Composer = Expand-QSetupInstaller -Path $Fixture -DestinationPath $Destination -Name Composer.exe -CollisionAction Error
    [Convert]::ToHexString((Get-Content $Composer.FullName -AsByteStream -ReadCount 2 -TotalCount 2)) | Should -Be '4D5A'
  }

  It 'Should decode the legacy environment-operation record' {
    $RelativePath = 'Installers\QSetup\Pantaray.QSetup\4.0.0.4\qstp.exe'
    $Sha256 = 'BFEC5B30D618A4624A2F1957425F7862C26238951218B4A7E4BEC07334E046FE'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because 'Cache the historical QSetup 4.0.0.4 fixture.'
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.EnvironmentChanges | Should -HaveCount 1
    $Info.EnvironmentChanges[0].Name | Should -Be 'FRIDA'
    $Info.EnvironmentChanges[0].Value | Should -Be 'Gonen'
    $Info.EnvironmentChanges[0].Operation | Should -Be 'Append'
    $Info.EnvironmentChanges[0].UninstallAction | Should -Be 'Remove'
    $Info.EnvironmentChanges[0].Scope | Should -Be 'user'
  }

  It 'Should parse the complete signed AGTEK execution-action layout' {
    $RelativePath = 'Installers\QSetup\AGTEK.Trackwork\2.25.5.6\Trackwork4D225.5.6x64.exe'
    $Sha256 = '6EC7D39B466DF83024E1320A8755669CFA7FEB104166D615480D2FD17F42FE62'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      if ($env:DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES -eq '1') {
        $Fixture = Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://agtek.s3.amazonaws.com/Agtek/n9KWMWYsnSRr' -Sha256 $Sha256
      } else {
        Set-ItResult -Skipped -Because 'Set DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES=1 to cache the 125 MiB signed QSetup regression.'
        return
      }
    }

    $Info = Get-QSetupInfo -Path $Fixture
    @($Info.Diagnostics | Where-Object Id -EQ 'QSetup.UninstallString.Dynamic') | Should -HaveCount 1
    @($Info.Diagnostics | Where-Object { $_.Kind -ne 'Information' -and $_.Id -ne 'QSetup.UninstallString.Dynamic' }) | Should -BeNullOrEmpty
    $Info.PackageFooter.DeclaredRecordCount | Should -Be 241
    $Info.Records | Should -HaveCount 241
    $Info.Certificate.Offset | Should -BeGreaterThan $Info.PackageFooter.Offset
    $Info.ExecutionActions.Count | Should -BeGreaterThan 10
    $Info.ExecutedPayloads.Command | Should -Contain '<SrcDir>\vc100redist_x86.exe'
    $Info.ExecutedPayloads.Parameters | Should -Contain '/passive /norestart'
  }
}
