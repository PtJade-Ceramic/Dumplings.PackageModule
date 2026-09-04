# SPDX-License-Identifier: Apache-2.0
# Format sources:
# - https://www.thraexsoftware.com/
# - https://web.archive.org/web/20120410054204id_/http://www.thraexsoftware.com/aiw/version_history.txt
# - Controlled and archived Astrum InstallWizard builder output from 1.80 through 2.29.50
#
# This catalog contains declarative wire-layout evidence only. The parser selects a format from
# validated footer length and trailer structure, then consumes the named fields without branching
# on an application's authored version.
@{
  CatalogVersion        = 1
  Formats               = @(
    @{
      Id                                 = 'astrum-1'
      Generation                         = '1.x'
      ObservedVersionRange               = '1.80-1.95.5'
      FooterLength                       = 0xE8
      FooterOffsets                      = @{
        ConfigurationOffset       = 0x00
        ConfigurationSize         = 0x04
        UninstallerCompressedSize = 0xA4
        UninstallerOffset         = 0xA8
        InstallationItemCount     = 0xAC
        InstallationItemOffset    = 0xB0
        InstallationItemSize      = 0xB4
        FileCount                 = 0xB8
        FileOffset                = 0xBC
        PayloadSize               = 0xC0
        ExpandedSize              = 0xC4
        InstalledSize             = 0xC8
        SelfPointer               = 0xE4
      }
      TrailerRoutes                      = @('LegacyNoMagic', 'DualMagic')
      RequireRuntimeIdentityWithoutMagic = $true
      FileDescriptorSize                 = 60
      FileConditionWordIndex             = -1
      HasRecordConditions                = $false
      RegistryChildRoute                 = 'NameOnly'
      OperationTailRoute                 = 'ObservedUInt32'
      HasAdvancedResourceTable           = $false
      ConfigurationProfileRoute          = 'Fixed'
      DefaultConfigurationProfile        = 'Legacy1'
      RuntimeWordProfile                 = $null
      RuntimeWordMaximum                 = $null
      ContainerRoutePrefix               = 'Astrum1'
      SupportsTiny                       = $false
      SupportsSpanned                    = $false
      InstallerSuccessCodes              = @()
      ValidationInvariants               = @('PEImage', 'RuntimeIdentityForNoMagic', 'FooterSelfPointer', 'ProtectedConfiguration', 'CompleteInstallationItemTable', 'CompleteFileCatalog')
    }
    @{
      Id                                 = 'astrum-2'
      Generation                         = '2.x'
      ObservedVersionRange               = '2.01.50-2.29.50'
      FooterLength                       = 0xEC
      FooterOffsets                      = @{
        ConfigurationOffset       = 0x00
        ConfigurationSize         = 0x04
        UninstallerCompressedSize = 0xA8
        UninstallerOffset         = 0xAC
        InstallationItemCount     = 0xB0
        InstallationItemOffset    = 0xB4
        InstallationItemSize      = 0xB8
        FileCount                 = 0xBC
        FileOffset                = 0xC0
        PayloadSize               = 0xC4
        ExpandedSize              = 0xC8
        InstalledSize             = 0xCC
        SelfPointer               = 0xE8
      }
      TrailerRoutes                      = @('DualMagic')
      RequireRuntimeIdentityWithoutMagic = $false
      FileDescriptorSize                 = 64
      FileConditionWordIndex             = 15
      HasRecordConditions                = $true
      RegistryChildRoute                 = 'UninstallAndCondition'
      OperationTailRoute                 = 'Condition'
      HasAdvancedResourceTable           = $true
      ConfigurationProfileRoute          = 'LeadingRuntimeWord'
      DefaultConfigurationProfile        = 'Early2'
      RuntimeWordProfile                 = 'Modern2'
      RuntimeWordMaximum                 = 0xFFFF
      ContainerRoutePrefix               = 'Astrum2'
      SupportsTiny                       = $true
      SupportsSpanned                    = $true
      InstallerSuccessCodes              = @(1)
      ValidationInvariants               = @('PEImage', 'DualTrailerMagic', 'FooterSelfPointer', 'ProtectedConfiguration', 'CompleteInstallationItemTable', 'CompleteFileCatalog')
    }
  )
  ConfigurationProfiles = @{
    Legacy1 = @{
      Id            = 'Legacy1'
      Generation    = '1.x'
      IdentityRoute = 'Legacy'
      OptionRoute   = 'Opaque'
      SilentRoute   = 'BuilderVersionEvidenceRequired'
      OptionFields  = @()
    }
    Early2  = @{
      Id            = 'Early2'
      Generation    = '2.x'
      IdentityRoute = 'Legacy'
      OptionRoute   = 'Opaque'
      SilentRoute   = 'Documented2'
      OptionFields  = @()
    }
    Modern2 = @{
      Id            = 'Modern2'
      Generation    = '2.x'
      IdentityRoute = 'Modern'
      OptionRoute   = 'SparseModern2'
      SilentRoute   = 'Documented2'
      OptionFields  = @(
        @{ Name = 'MinimumCpuSpeedMHz'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x48; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuManufacturerCode'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x4C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuVendorMask'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x50; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuFeatureFlags'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x54; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumMemoryMiB'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x58; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumWindows9xBuild'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x60; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumNtServicePack'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x6C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumDirectXMajor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x70; Type = 'UInt16'; Endian = 'BigEndian' }
        @{ Name = 'MinimumDirectXMinor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x72; Type = 'UInt16'; Endian = 'BigEndian' }
        @{ Name = 'MinimumResolutionWidth'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x74; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumResolutionHeight'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x78; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'RequiresWavePlayback'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x94; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'RequiresMidiPlayback'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x98; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'RequiresJoystick'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x9C; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'UserInformationFlags'; Group = 'Configuration'; Origin = 'Option'; Offset = 0xA0; Type = 'UInt32'; Endian = 'LittleEndian' }
        @{ Name = 'SilentInstallationDefault'; Group = 'Configuration'; Origin = 'Option'; Offset = 0xF0; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'NoUninstallation'; Group = 'Configuration'; Origin = 'Option'; Offset = 0xF4; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'X64ComplianceMode'; Group = 'Configuration'; Origin = 'Option'; Offset = 0x131; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'RequireAdmin'; Group = 'Configuration'; Origin = 'Option'; Offset = 0x135; Type = 'BooleanUInt32'; Endian = 'LittleEndian' }
        @{ Name = 'DirectLicenseApproval'; Group = 'Configuration'; Origin = 'End'; Distance = 29; Type = 'BooleanByte' }
        @{ Name = 'ProhibitSilentInstallation'; Group = 'Configuration'; Origin = 'End'; Distance = 25; Type = 'BooleanByte' }
      )
    }
  }
}
