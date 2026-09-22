. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'Manifest update operation ownership and cache isolation' -Tag Unit {
  InModuleScope WinGetManifestUpdate {
    BeforeEach {
      $FilePath = Join-Path $TestDrive 'source.bin'
      [IO.File]::WriteAllBytes($FilePath, [byte[]](1, 2, 3))
      $Context = New-WinGetManifestUpdateContext
    }
    AfterEach { Close-WinGetManifestUpdateContext $Context }

    It 'indexes literal selectors while keeping queries and wildcard entries in authored order' {
      $Entries = @(@{ Architecture = 'x86' }, @{ Query = { $true } }, @{ Architecture = 'x64' }, @{ InstallerUrl = 'https://example.test/all' }, @{ Query = @{ Scope = 'user' } })
      $Index = New-WinGetInstallerEntryIndex $Entries
      @(Get-WinGetInstallerEntryCandidate $Index @{ Architecture = 'x64'; Scope = 'machine' }) | Should -Be @(1, 2, 3, 4)
      @(Get-WinGetInstallerEntryCandidate $Index @{ Architecture = 'X64' }) | Should -Be @(1, 3, 4)
      @(Get-WinGetInstallerEntryCandidate $Index @{}) | Should -Be @(1, 3, 4)
    }

    It 'reuses exact parser requests but separates architecture, scope and command line' {
      Mock Get-WinGetKnownInstallerManifestInfo { [pscustomobject]@{ ProductCode = 'Evidence' } }
      $Arguments = @{ Path = $FilePath; InstallerType = 'nullsoft'; Architecture = 'x64'; Scope = 'machine'; CommandLine = '/S' }
      $First = Invoke-WinGetUpdateParser $Context $Arguments
      $Second = Invoke-WinGetUpdateParser $Context $Arguments
      [object]::ReferenceEquals($First, $Second) | Should -BeTrue
      $Arguments.Architecture = 'arm64'
      $null = Invoke-WinGetUpdateParser $Context $Arguments
      $Arguments.Scope = 'user'
      $null = Invoke-WinGetUpdateParser $Context $Arguments
      $Arguments.CommandLine = '/S /currentuser'
      $null = Invoke-WinGetUpdateParser $Context $Arguments
      Should -Invoke Get-WinGetKnownInstallerManifestInfo -Times 4 -Exactly
    }

    It 'does not cache failed parsing or reuse a changed artifact' {
      Mock Get-WinGetKnownInstallerManifestInfo { throw 'parser failure' }
      $Arguments = @{ Path = $FilePath; InstallerType = 'inno' }
      { Invoke-WinGetUpdateParser $Context $Arguments } | Should -Throw '*parser failure*'
      $Context.ParserResults.Count | Should -Be 0
      Mock Get-WinGetKnownInstallerManifestInfo { [pscustomobject]@{ ProductCode = 'Evidence' } }
      $null = Invoke-WinGetUpdateParser $Context $Arguments
      [IO.File]::WriteAllBytes($FilePath, [byte[]](4, 5, 6, 7))
      $null = Invoke-WinGetUpdateParser $Context $Arguments
      $Context.ParserResults.Count | Should -Be 2
    }

    It 'hashes a borrowed artifact once and leaves it intact after cleanup' {
      Mock Get-FileHash { [pscustomobject]@{ Hash = ('A' * 64) } }
      Mock Get-WinGetInstallerReleaseDate { $null }
      $Installer = [ordered]@{ InstallerUrl = 'https://example.test/setup'; InstallerType = 'exe'; Architecture = 'x64' }
      $Arguments = @{ Installer = $Installer; OldInstaller = $Installer; InstallerEntry = [ordered]@{}; InstallerFiles = @{ $Installer.InstallerUrl = $FilePath }; SkipInstallerAnalysis = $true; Logger = {}; Operation = $Context }
      $null = Update-WinGetInstallerManifestInstallerMetadata @Arguments
      $null = Update-WinGetInstallerManifestInstallerMetadata @Arguments
      Should -Invoke Get-FileHash -Times 1 -Exactly
      Close-WinGetManifestUpdateContext $Context
      Test-Path -LiteralPath $FilePath | Should -BeTrue
    }

    It 'removes owned extraction trees and downloads idempotently without removing borrowed files' {
      $Directory = New-Item (Join-Path $TestDrive 'extracted') -ItemType Directory
      $Owned = Join-Path $TestDrive 'download.bin'
      [IO.File]::WriteAllText($Owned, 'owned')
      $null = $Context.OwnedDirectories.Add($Directory.FullName)
      $null = $Context.OwnedFiles.Add($Owned)
      Close-WinGetManifestUpdateContext $Context
      Close-WinGetManifestUpdateContext $Context
      Test-Path $Owned | Should -BeFalse
      Test-Path $Directory.FullName | Should -BeFalse
      Test-Path $FilePath | Should -BeTrue
    }

    It 'reuses a tracking hash only while its local file identity matches' {
      Mock Get-FileHash { [pscustomobject]@{ Hash = ('B' * 64) } }
      Mock Get-WinGetInstallerReleaseDate { $null }
      $Context.FileEvidence[$FilePath] = @{ Identity = Get-InstallerTrackingFileIdentity $FilePath; Sha256 = 'A' * 64 }
      $Installer = [ordered]@{ InstallerUrl = 'https://example.test/setup'; InstallerType = 'exe'; Architecture = 'x64' }
      $Arguments = @{ Installer = $Installer; OldInstaller = $Installer; InstallerEntry = [ordered]@{}; InstallerFiles = @{ $Installer.InstallerUrl = $FilePath }; SkipInstallerAnalysis = $true; Logger = {}; Operation = $Context }
      $null = Update-WinGetInstallerManifestInstallerMetadata @Arguments
      $Installer.InstallerSha256 | Should -Be ('A' * 64)
      Should -Invoke Get-FileHash -Times 0 -Exactly
      [IO.File]::WriteAllBytes($FilePath, [byte[]](4, 5, 6, 7))
      $null = Update-WinGetInstallerManifestInstallerMetadata @Arguments
      $Installer.InstallerSha256 | Should -Be ('B' * 64)
      Should -Invoke Get-FileHash -Times 1 -Exactly
    }

  }
}
