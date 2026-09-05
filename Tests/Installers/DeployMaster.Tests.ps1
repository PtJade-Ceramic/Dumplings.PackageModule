. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
  $Script:DeployMasterFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\KnownScenarios'
  $Script:DeployMasterOptionFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\OptionMatrix'
  $Script:DeployMasterBehaviorFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\BehaviorMatrix'
  $Script:DeployMasterLegacyFixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Setup Brinno Video Player.exe')
}

Describe 'DeployMaster static parser' {
  It 'Should map controlled scope values without PE heuristics' {
    InModuleScope DeployMaster {
      (Get-DeployMasterScopeInfo -Value 0).Scope | Should -Be 'user'
      (Get-DeployMasterScopeInfo -Value 1).Scope | Should -Be 'machine'
      (Get-DeployMasterScopeInfo -Value 2).SupportedScopes | Should -Be @('user', 'machine')
      (Get-DeployMasterScopeInfo -Value 2).SupportsDualScope | Should -BeTrue
    }
  }

  $ArchitectureFixtures = @(
    @{ Name = 'KnownSetup_FileExt_32AppFor32Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86WindowsOnly'; Application = @('x86'); OperatingSystem = @('x86'); RegistryView = '32-bit' }
    @{ Name = 'KnownSetup_FileExt_32AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86AndX64Windows'; Application = @('x86'); OperatingSystem = @('x86', 'x64'); RegistryView = '32-bit' }
    @{ Name = 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86AndX64Application'; Application = @('x86', 'x64'); OperatingSystem = @('x86', 'x64'); RegistryView = 'architecture-selected' }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWith32InstallerStub.exe'; Installer = 'x86'; Mode = 'x64ApplicationWithX86InstallerStub'; Application = @('x64'); OperatingSystem = @('x64'); RegistryView = '64-bit' }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWithPure64Installer.exe'; Installer = 'x64'; Mode = 'x64ApplicationWithX64Installer'; Application = @('x64'); OperatingSystem = @('x64'); RegistryView = '64-bit' }
  )
  It 'Should distinguish all controlled DeployMaster architecture modes' -ForEach $ArchitectureFixtures {
    $FixturePath = Join-Path $Script:DeployMasterFixtureDirectory $Name
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster architecture fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.InstallerArchitecture | Should -Be $Installer
    $Info.ApplicationArchitectureMode | Should -Be $Mode
    $Info.ApplicationArchitectures | Should -Be $Application
    $Info.SupportedOperatingSystemArchitectures | Should -Be $OperatingSystem
    $Info.RegistryView | Should -Be $RegistryView
  }

  It 'Should decode file extensions, actions, and both runtime cores' {
    $AssociationFixture = Join-Path $Script:DeployMasterFixtureDirectory 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'
    if (-not (Test-Path -LiteralPath $AssociationFixture)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster association fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'deploymaster-expanded'
    $Info = Get-DeployMasterInfo -Path $AssociationFixture
    $Files = @(Expand-DeployMasterInstaller -Path $AssociationFixture -DestinationPath $DestinationPath -CollisionAction Rename)

    $Info.DisplayName | Should -Be 'DMDeployMasterKnown'
    $Info.DisplayVersion | Should -Be '12.34.56'
    $Info.Publisher | Should -Be 'Dumplings Parser Lab'
    $Info.LicenseFileName | Should -Be 'license.txt'
    $Info.LicenseRequiredEveryInstall | Should -BeTrue
    $Info.FileExtensions | Should -Be @('ext1', 'ext2')
    $Info.FileAssociations.Actions.Name | Should -Be @('Ext1Action1', 'Ext2Action1', 'Ext2Action2')
    $Info.Components.Count | Should -Be 1
    $Info.Components[0].InstallByDefault | Should -BeTrue
    $Info.Components[0].UserSelectable | Should -BeTrue
    $Info.InstalledFiles.DestinationPath | Should -Be '%APPFOLDER%\payload.txt'
    $Info.CompletionActions.ShowMessage | Should -BeTrue
    $Info.CompletionActions.ShowStartMenuFolder | Should -BeTrue
    $Info.CompletionActions.PromptForReboot | Should -BeFalse
    $Info.UpdatePolicy.DeleteObsoleteFiles | Should -BeFalse
    $Info.UpdatePolicy.RequiredReleaseDate | Should -BeNullOrEmpty
    $Info.PackageSettings.PortableInstallationMode | Should -Be 'UserChoice'
    $Info.PackageSettings.PortableMarkerMode | Should -Be 'Always'
    $Info.PackageSettings.PortableAllowAnyDrive | Should -BeTrue
    $Info.PackageSettings.PortableDefaultFolder | Should -Be 'DMDeployMasterKnown'
    $Info.InstallerSwitches.Silent | Should -Be '/silent'
    $Info.InstallerSwitches.InstallLocation | Should -Be '/appfolder "<INSTALLPATH>"'
    $Info.InstallerSwitches.Contains('SilentWithProgress') | Should -BeFalse
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.AppsAndFeaturesEntries.Count | Should -Be 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'DMDeployMasterKnown'
    $Info.ParserVersionInfo.ParserMajor | Should -Be 3
    $Info.ExtractedFiles | Should -Be @('license.txt', 'payload.txt', 'UnDeploy32.exe', 'UnDeploy64.exe')
    (Get-PELayout -Path (Join-Path $DestinationPath 'Runtime\DeployMasterCore-x86.exe')).MachineName | Should -Be 'I386'
    (Get-PELayout -Path (Join-Path $DestinationPath 'Runtime\DeployMasterCore-x64.exe')).MachineName | Should -Be 'AMD64'
    (Get-DumplingsTestFixtureHash -Path (Join-Path $DestinationPath 'Payload\payload.txt')) | Should -Be '82E809CEAC82F7E214B2E76901A01794929136ADA5243169CA78D953EE91E64D'
    $Files.Count | Should -Be 8
  }

  It 'Should parse and expand the legacy Brinno package table' {
    if (-not (Test-Path -LiteralPath $Script:DeployMasterLegacyFixture)) { Set-ItResult -Skipped -Because 'The legacy DeployMaster fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'deploymaster-legacy'
    $Info = Get-DeployMasterInfo -Path $Script:DeployMasterLegacyFixture
    $Files = @(Expand-DeployMasterInstaller -Path $Script:DeployMasterLegacyFixture -DestinationPath $DestinationPath -Name 'bvplay.exe' -CollisionAction Rename)

    $Info.DisplayName | Should -Be 'Brinno Video Player'
    $Info.DisplayVersion | Should -Be '1.139.00'
    $Info.ProductCode | Should -Be 'Brinno Video Player'
    $Info.Scope | Should -Be 'machine'
    $Info.ExtractedFiles.Count | Should -Be 11
    $Info.Components.Count | Should -Be 1
    $Info.InstalledFiles.Count | Should -Be 7
    $Info.Shortcuts.Count | Should -Be 2
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    $Files.Count | Should -Be 1
    (Get-PELayout -Path $Files[0].FullName).MachineName | Should -Be 'I386'
  }

  It 'Should decode explicit Registry-tab writes and project uninstall evidence' {
    InModuleScope DeployMaster {
      function AddString([Collections.Generic.List[byte]]$Buffer, [string]$Value) {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Buffer.AddRange([BitConverter]::GetBytes([uint16]$Encoded.Length))
        $Buffer.AddRange($Encoded)
      }

      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.Add(1)
      AddString $Bytes 'HKEY_LOCAL_MACHINE'
      foreach ($Key in 'Software', 'Microsoft', 'Windows', 'CurrentVersion', 'Uninstall', 'Custom.Product') {
        $Bytes.Add(1)
        AddString $Bytes $Key
      }
      foreach ($Pair in @(
          @('DisplayName', 'Custom Product'),
          @('DisplayVersion', '1.2.3'),
          @('Publisher', 'Example Publisher')
        )) {
        $Bytes.Add(4)
        AddString $Bytes $Pair[0]
        $Bytes.Add(7)
        AddString $Bytes $Pair[1]
      }
      1..8 | ForEach-Object { $Bytes.Add(0xFF) }

      $Registry = ConvertFrom-DeployMasterRegistryBlock -Bytes $Bytes.ToArray() -ScopeValue 1
      $Registry.RegistryWrites.Count | Should -Be 3
      $Registry.RegistryWrites.Type | Should -Be @('REG_SZ', 'REG_SZ', 'REG_SZ')
      $Entry = @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $Registry.RegistryWrites)
      $Entry.Count | Should -Be 1
      $Entry[0].ProductCode | Should -Be 'Custom.Product'
      $Entry[0].DisplayName | Should -Be 'Custom Product'
      $Entry[0].DisplayVersion | Should -Be '1.2.3'
      $Entry[0].Publisher | Should -Be 'Example Publisher'
    }
  }

  It 'Should merge explicit ARP overrides and exclude hidden entries' {
    InModuleScope DeployMaster {
      $BuiltIn = [pscustomobject]@{ ProductCode = 'Product'; DisplayName = 'Built-in'; DisplayVersion = '1'; Publisher = 'Publisher'; InstallerType = 'exe' }
      $Explicit = [pscustomobject]@{ ProductCode = 'product'; DisplayName = 'Explicit'; DisplayVersion = '2'; InstallerType = 'exe' }
      $Merged = @(Merge-DeployMasterAppsAndFeaturesEntry -Entry @($BuiltIn, $Explicit))
      $Merged.Count | Should -Be 1
      $Merged[0].DisplayName | Should -Be 'Explicit'
      $Merged[0].DisplayVersion | Should -Be '2'
      $Merged[0].Publisher | Should -Be 'Publisher'

      $HiddenWrites = @(
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'DisplayName'; Value = 'Hidden Product'; Type = 'REG_SZ'; OnlyIfMissing = $false },
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'SystemComponent'; Value = [uint32]1; Type = 'REG_DWORD'; OnlyIfMissing = $false }
      )
      @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $HiddenWrites) | Should -BeNullOrEmpty
    }
  }

  It 'Should parse bare-CR prerequisite descriptors without losing positional fields' {
    InModuleScope DeployMaster {
      $Descriptor = ConvertFrom-DeployMasterTextBlock -Bytes ([Text.Encoding]::UTF8.GetBytes("framework.exe`rhttps://example.invalid/framework.exe`r"))
      $Requirement = ConvertFrom-DeployMasterDotNetFrameworkRecord -Flags 0x23 -VersionCode 11 -Descriptor $Descriptor -RawValues ([byte[]]::new(16))

      $Descriptor.Fields | Should -Be @('framework.exe', 'https://example.invalid/framework.exe', '')
      $Requirement.CompatibleVersions | Should -Be @('1.0', '1.1', '4.8.1+')
      $Requirement.Minimum4xVersion | Should -Be '4.8.1'
      $Requirement.InstallerFileName | Should -Be 'framework.exe'
      $Requirement.HasAutomaticInstaller | Should -BeTrue
      $Requirement.DownloadUrl | Should -Be 'https://example.invalid/framework.exe'
      $Requirement.UnknownFlags | Should -Be 0
    }
  }

  It 'Should decode the controlled DeployMaster .NET Framework prerequisite' {
    $FixturePath = Join-Path $Script:DeployMasterOptionFixtureDirectory 'Net40Bundled.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster .NET prerequisite fixture is not cached.'; return }
    $Requirement = (Get-DeployMasterInfo -Path $FixturePath).DotNetFrameworkRequirement

    $Requirement.CompatibleVersions | Should -Be @('4.0+')
    $Requirement.Requires4x | Should -BeTrue
    $Requirement.Minimum4xVersion | Should -Be '4.0'
    $Requirement.InstallerFileName | Should -Be 'DeployMasterCmd.exe'
    $Requirement.HasAutomaticInstaller | Should -BeTrue
    $Requirement.DownloadUrl | Should -Be 'https://example.invalid/dotnet.exe'
  }

  It 'Should distinguish an elevated current-user package from machine scope' {
    $FixturePath = Join-Path $Script:DeployMasterOptionFixtureDirectory 'UserRequireAdmin.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled elevated-user DeployMaster fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.Scope | Should -Be 'user'
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.RequiresAdministrativeRights | Should -BeTrue
    $Info.DefaultInstallLocation | Should -Be '%LOCALAPPDATAROOT%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.MachineInstallLocation | Should -Be '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.RegistryWrites[0].Root | Should -Be 'HKCU'
    $Info.Diagnostics.Message | Should -Not -Contain 'The DeployMaster identity scope marker does not match the package-control scope byte.'
  }

  It 'Should decode current Windows platform constraints from the control header' {
    $FixturePath = Join-Path $Script:DeployMasterFixtureDirectory 'KnownSetup.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster platform fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.SupportedWindowsVersions | Should -Be @('Windows7', 'Windows8', 'Windows8.1', 'Windows10', 'Windows11')
    $Info.SupportsFutureWindowsVersions | Should -BeTrue
    $Info.MinimumWindows10VersionCode | Should -Be 1507
    $Info.MaximumWindows10VersionCode | Should -Be 9999
    $Info.MinimumWindows11VersionCode | Should -Be 2110
    $Info.MaximumWindows11VersionCode | Should -Be 9999
  }

  It 'Should parse the compiled final expiration date without guessing the builder source mode' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'ExpireDays.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster expiration fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.ExpirationPolicy.IsTimeLimited | Should -BeTrue
    $Info.ExpirationPolicy.ExpirationDate | Should -Be ([datetime]'2026-10-05')
    $Info.ExpirationPolicy.SourceMode | Should -Be 'CompiledFinalDate'
    $Info.ExpirationPolicy.Message | Should -Match 'installer expired on 2026/10/5'
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.TimeLimited').Count | Should -Be 1

    $Baseline = Get-DeployMasterInfo -Path (Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe')
    $Baseline.ExpirationPolicy.IsTimeLimited | Should -BeFalse
    $Baseline.ExpirationPolicy.ExpirationDate | Should -BeNullOrEmpty
  }

  It 'Should decode controlled update and running-application policies' {
    foreach ($Case in @(
        @{ Name = 'DeleteObsolete.exe'; Flag = 1; Property = 'DeleteObsoleteFiles'; Value = $true },
        @{ Name = 'PatchMessage.exe'; Flag = 2; Property = 'RequiresPreviousRelease'; Value = $true },
        @{ Name = 'WindowClass.exe'; Flag = 4; Property = 'BlockedWindowClasses'; Value = @('DMParserWindowClass') },
        @{ Name = 'WindowCaption.exe'; Flag = 8; Property = 'BlockedWindowCaptions'; Value = @('DM Parser Caption') }
      )) {
      $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory $Case.Name
      if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster update-policy fixtures are not cached.'; return }
      $Policy = (Get-DeployMasterInfo -Path $FixturePath).UpdatePolicy
      $Policy.Flags | Should -Be $Case.Flag
      $Policy.($Case.Property) | Should -Be $Case.Value
    }

    $Patch = (Get-DeployMasterInfo -Path (Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'PatchMessage.exe')).UpdatePolicy
    $Patch.IsPatchPackage | Should -BeTrue
    $Patch.RequiredReleaseDate | Should -Be ([datetime]'2026-07-13')
    $Patch.PatchRequirementLines | Should -Be @('A previous 12.34 release is required.', 'Download the full installer first.')
  }

  It 'Should distinguish readme, license, and support-DLL catalog entries' {
    $ReadmePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Readme.exe'
    $SupportPath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'SupportDll.exe'
    if (-not (Test-Path -LiteralPath $ReadmePath) -or -not (Test-Path -LiteralPath $SupportPath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster support-file fixtures are not cached.'; return }

    $Readme = Get-DeployMasterInfo -Path $ReadmePath
    $Readme.ReadmeFileName | Should -Be 'payload.txt'
    $Readme.LicenseFileName | Should -Be 'license.txt'
    $Readme.FileEntries.Name | Should -Contain 'payload.txt'
    $Readme.FileEntries.Name | Should -Contain 'license.txt'

    $Support = Get-DeployMasterInfo -Path $SupportPath
    $Support.SupportDlls.Count | Should -Be 1
    $Support.SupportDlls[0].Architecture | Should -Be 'x86'
    $Support.SupportDlls[0].FileName | Should -Be 'version.dll'
    $Support.FileEntries.Name | Should -Contain 'version.dll'
    $Support.UnresolvedFields | Should -Contain 'SupportDllEffects'
    @($Support.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.SupportDllEffectsOpaque').Count | Should -Be 1

    $ExtractedSupportDll = @(Expand-DeployMasterInstaller -Path $SupportPath -DestinationPath (Join-Path $TestDrive 'SupportDll') -Name 'Payload/version.dll' -CollisionAction Rename)
    $ExtractedSupportDll.Count | Should -Be 1
    (Get-PEArchitectureInfo -Path $ExtractedSupportDll[0].FullName).FileKind | Should -Be 'Dll'
  }
}
