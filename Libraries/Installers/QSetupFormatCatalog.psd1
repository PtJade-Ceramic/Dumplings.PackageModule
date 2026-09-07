# SPDX-License-Identifier: Apache-2.0
# QSetup structural profiles derived independently from official Pantaray media.
# Release labels are evidence for reporting; parser dispatch uses the byte-level
# predicates documented by each route instead of trusting PE version resources.
@{
  CatalogVersion  = 1

  PreambleRoutes  = @(
    @{
      Id               = 'DirectRecords'
      ObservedReleases = '1.0-2.0'
      Description      = 'The PE overlay begins directly with a uint32 compressed length and zlib member.'
    }
    @{
      Id               = 'DoublePipePreamble'
      ObservedReleases = '3.0-5.0'
      Description      = 'The overlay contains Version:u32, literal ||, PreambleLength:u32, and UTF-8 preamble text.'
    }
    @{
      Id               = 'VersionedPreamble'
      ObservedReleases = '7.0-12.0'
      Description      = 'The overlay contains Version:u32, CompressionFormat:u8, PreambleLength:u32, and UTF-8 preamble text.'
    }
  )

  FooterRoutes    = @(
    @{
      Id               = 'Compact12'
      ObservedReleases = '1.0-2.0'
      Length           = 12
      Description      = 'RecordCount:u32, OverlayOffset:u32, Magic:u32.'
    }
    @{
      Id               = 'Legacy74'
      ObservedReleases = '3.0-8.1'
      Length           = 74
      Description      = 'Version:u32, OverlayOffset:u32, RecordCount:u32, Magic:u32, legacy fields, FooterLength:u32.'
    }
    @{
      Id               = 'Modern74'
      ObservedReleases = '12.0'
      Length           = 74
      Description      = 'Version:u32, OverlayOffset:u32, RecordCount:u32, Magic:u32, Marker=1234, fields, FooterLength:u32.'
    }
  )

  ExecutionRoutes = @(
    @{
      Id               = 'LegacyFourCommand'
      ObservedReleases = '1.0-5.0'
      FieldCounts      = @(59, 60)
      CommandStart     = 20
      CommandCount     = 4
      ArgumentStart    = 46
      MiddleSentinel   = 32
    }
    @{
      Id               = 'ModernSixCommand'
      ObservedReleases = '7.0-12.0'
      FieldCounts      = @(73)
      CommandStart     = 20
      CommandCount     = 6
      ArgumentStart    = 53
      MiddleSentinel   = 39
    }
  )
}
