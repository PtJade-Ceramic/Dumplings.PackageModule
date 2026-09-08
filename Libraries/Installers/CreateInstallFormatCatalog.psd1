# SPDX-License-Identifier: Apache-2.0
# CreateInstall structural profiles derived independently from Gentee/CreateInstall source and
# official builder installers. Parser dispatch uses validated archive and compiled-routine
# structures; the observed release ranges are regression evidence rather than routing keys.
@{
  CatalogVersion              = 2

  ProgramProfiles             = @(
    @{
      Id                   = 'GE4Launcher'
      MajorVersion         = 4
      ObservedBuilderRange = 'CreateInstall 5.9.0-8.11.2'
      Description          = 'Gentee Launcher header followed by GE 4.0 serialized objects; the program may be stored or LZGE-compressed.'
    }
  )

  ArchiveProfiles             = @(
    @{
      Id                   = 'GEA1'
      MajorVersion         = 1
      SizeFieldWidth       = 4
      ObservedBuilderRange = 'CreateInstall 5.9.0-7.4.0'
      Description          = 'GEA file and block records encode packed and expanded sizes as uint32 LE values.'
    }
    @{
      Id                   = 'GEA2'
      MajorVersion         = 2
      SizeFieldWidth       = 8
      ObservedBuilderRange = 'CreateInstall 8.0.1-8.11.2'
      Description          = 'GEA file and block records encode packed and expanded sizes as uint64 LE values.'
    }
  )

  AddRemoveProfiles           = @(
    @{
      Id                       = 'Extended5'
      Routine                  = 'addremoveext'
      ObservedBuilderRange     = 'CreateInstall 7.1.7-8.11.2'
      RequiredValueNames       = @('UninstallString', 'DisplayName', 'InstallLocation', 'NoModify', 'NoRepair', 'EstimatedSize')
      ForbiddenValueNames      = @()
      StringArgumentCount      = 4
      HasCurrentUserArgument   = $true
      HasEstimatedSizeArgument = $true
      WritesInstallLocation    = $true
      WritesNoModify           = $true
      WritesNoRepair           = $true
      WritesEstimatedSize      = $true
      Description              = 'Five arguments: uninstall-key name, icon path, icon file, current-user flag, and estimated size.'
    }
    @{
      Id                       = 'Policy4'
      Routine                  = 'addremoveex'
      ObservedBuilderRange     = 'CreateInstall 7.0.26-7.1.3'
      RequiredValueNames       = @('UninstallString', 'DisplayName', 'InstallLocation', 'NoModify', 'NoRepair')
      ForbiddenValueNames      = @('EstimatedSize')
      StringArgumentCount      = 3
      HasCurrentUserArgument   = $true
      HasEstimatedSizeArgument = $false
      WritesInstallLocation    = $true
      WritesNoModify           = $true
      WritesNoRepair           = $true
      WritesEstimatedSize      = $false
      Description              = 'Four arguments as in addremoveex, with NoModify and NoRepair policy values but no estimated-size argument.'
    }
    @{
      Id                       = 'Scoped4'
      Routine                  = 'addremoveex'
      ObservedBuilderRange     = 'CreateInstall 6.4.0-7.0.19'
      RequiredValueNames       = @('UninstallString', 'DisplayName', 'InstallLocation')
      ForbiddenValueNames      = @('NoModify', 'NoRepair', 'EstimatedSize')
      StringArgumentCount      = 3
      HasCurrentUserArgument   = $true
      HasEstimatedSizeArgument = $false
      WritesInstallLocation    = $true
      WritesNoModify           = $false
      WritesNoRepair           = $false
      WritesEstimatedSize      = $false
      Description              = 'Four arguments: uninstall-key name, icon path, icon file, and current-user flag.'
    }
    @{
      Id                       = 'Legacy3'
      Routine                  = 'addremove'
      ObservedBuilderRange     = 'CreateInstall 5.9.0-6.3.3'
      RequiredValueNames       = @('UninstallString', 'DisplayName', 'DisplayIcon', 'DisplayVersion', 'Publisher')
      ForbiddenValueNames      = @('InstallLocation', 'NoModify', 'NoRepair', 'EstimatedSize')
      StringArgumentCount      = 3
      HasCurrentUserArgument   = $false
      HasEstimatedSizeArgument = $false
      WritesInstallLocation    = $false
      WritesNoModify           = $false
      WritesNoRepair           = $false
      WritesEstimatedSize      = $false
      Description              = 'Three arguments: uninstall-key name, icon path, and icon file; the routine uses machine context when elevated.'
    }
  )

  InstallGroupProfiles        = @(
    @{
      Id                   = 'Direct5'
      ParameterCount       = 5
      ObservedBuilderRange = 'CreateInstall 5.9.0-5.x'
      Description          = 'unpackgroup receives group, destination, overwrite mode, condition, and wildcard directly.'
    }
    @{
      Id                   = 'Extended6'
      ParameterCount       = 6
      ObservedBuilderRange = 'CreateInstall 6.x-8.11.2'
      Description          = 'unpackgroupex adds a g_list offset carrying per-file overwrite, attribute, and condition options.'
    }
  )

  OperationProfiles           = @(
    @{
      Id             = 'RegistryList5'
      ParameterCount = 5
      ListFieldCount = 5
      Description    = 'regsetsex receives hive, subkey, five-field value-list offset, registry-view flag, and outer condition.'
    }
    @{
      Id             = 'ExtensionList2'
      ListFieldCount = 2
      Description    = 'Extension commands combine four literal operands with a two-field variable list.'
    }
    @{
      Id               = 'ShortcutDirect10'
      SourceFieldCount = 10
      Description      = 'The generator composes ten shortcut project fields into the eight-parameter shortcutex runtime call.'
    }
    @{
      Id               = 'ShortcutList10'
      SourceFieldCount = 10
      Description      = 'shlist receives a g_list offset whose rows contain shortcut path/name, target path/name, arguments, icon, working path/name, condition, and one runtime-ignored comment field.'
    }
    @{
      Id               = 'RunDirect8'
      SourceFieldCount = 8
      Description      = 'The generator composes path/name and work/default-work pairs before calling the six-parameter run runtime function.'
    }
    @{
      Id               = 'RunMsi11'
      SourceFieldCount = 11
      Description      = 'The generator composes an MSI path, five option flags, wait flag, condition, log path, and interface value before calling runmsiex.'
    }
  )

  RejectedPredecessorProfiles = @(
    @{
      Id                = 'GenteeInstaller'
      ObservedArtifacts = @('ci2000.exe', 'setupgen.exe', 'sgpro.exe')
      Description       = 'Installers for pre-CreateInstall Gentee tools use a separate Gentee Installer runtime and contain neither a GE4 launcher program nor a GEA archive. They are not routed to CreateInstall.'
    }
  )
}
