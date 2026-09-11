// SPDX-License-Identifier: Apache-2.0
//
// Independently implemented from the Zero Install manifest specification and
// behavior observed in https://github.com/0install/0install-dotnet. No source
// from that LGPL-licensed project is copied into this file.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Dumplings.ZeroInstall
{
    /// <summary>Result of hashing one materialized Zero Install implementation.</summary>
    public sealed class ImplementationManifestResult
    {
        public string Algorithm { get; internal set; }
        public string Digest { get; internal set; }
        public string ManifestText { get; internal set; }
        public int DirectoryCount { get; internal set; }
        public int FileCount { get; internal set; }
        public long TotalBytes { get; internal set; }
    }

    /// <summary>
    /// Builds the normalized file manifest used by Zero Install implementation
    /// identifiers. This helper only hashes a caller-owned directory and never
    /// follows filesystem links or mutates the directory.
    /// </summary>
    public static class ImplementationManifest
    {
        private sealed class ManifestPathComparer : IComparer<string>
        {
            public int Compare(string left, string right)
            {
                return StringComparer.Ordinal.Compare(
                    (left ?? string.Empty).Replace('/', char.MinValue),
                    (right ?? string.Empty).Replace('/', char.MinValue));
            }
        }

        private sealed class FileRecord
        {
            public string RelativePath;
            public string Directory;
            public string Name;
            public string FullPath;
            public long Length;
            public long ModifiedTime;
            public bool Executable;
        }

        /// <summary>Calculate a sha1new, sha256, or sha256new manifest digest.</summary>
        public static ImplementationManifestResult Compute(
            string rootPath,
            string algorithm,
            IEnumerable<string> executablePaths,
            int maximumEntries,
            long maximumBytes)
        {
            if (string.IsNullOrWhiteSpace(rootPath)) throw new ArgumentNullException(nameof(rootPath));
            if (maximumEntries < 1) throw new ArgumentOutOfRangeException(nameof(maximumEntries));
            if (maximumBytes < 1) throw new ArgumentOutOfRangeException(nameof(maximumBytes));

            string root = Path.GetFullPath(rootPath);
            if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
            RejectReparsePoint(root);

            string normalizedAlgorithm = NormalizeAlgorithm(algorithm);
            var executable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (executablePaths != null)
            {
                foreach (string path in executablePaths)
                    executable.Add(NormalizeRelativePath(path, nameof(executablePaths)));
            }

            var directories = new SortedSet<string>(new ManifestPathComparer()) { string.Empty };
            var files = new List<FileRecord>();
            long totalBytes = 0;
            int entries = 0;
            Walk(root, root, directories, files, executable, ref entries, ref totalBytes, maximumEntries, maximumBytes);

            // AppleDouble sidecars are metadata for their sibling files. Zero
            // Install drops them only when the sibling is present.
            var filePaths = new HashSet<string>(StringComparer.Ordinal);
            foreach (FileRecord file in files) filePaths.Add(file.RelativePath);
            files.RemoveAll(file => file.Name.StartsWith("._", StringComparison.Ordinal)
                && filePaths.Contains(JoinUnix(file.Directory, file.Name.Substring(2))));
            filePaths.Clear();
            long manifestBytesTotal = 0;
            foreach (FileRecord file in files)
            {
                filePaths.Add(file.RelativePath);
                checked { manifestBytesTotal += file.Length; }
            }
            foreach (string executablePath in executable)
            {
                if (!filePaths.Contains(executablePath))
                    throw new InvalidDataException("Executable metadata refers to a missing implementation file: " + executablePath);
            }

            var filesByDirectory = new Dictionary<string, List<FileRecord>>(StringComparer.Ordinal);
            foreach (FileRecord file in files)
            {
                List<FileRecord> list;
                if (!filesByDirectory.TryGetValue(file.Directory, out list))
                {
                    list = new List<FileRecord>();
                    filesByDirectory.Add(file.Directory, list);
                }
                list.Add(file);
            }
            foreach (List<FileRecord> list in filesByDirectory.Values)
                list.Sort((left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));

            var text = new StringBuilder();
            foreach (string directory in directories)
            {
                if (directory.Length != 0) text.Append("D /").Append(directory).Append('\n');
                List<FileRecord> list;
                if (!filesByDirectory.TryGetValue(directory, out list)) continue;
                foreach (FileRecord file in list)
                {
                    string contentDigest = HashFile(file.FullPath, normalizedAlgorithm);
                    text.Append(file.Executable ? "X " : "F ")
                        .Append(contentDigest).Append(' ')
                        .Append(file.ModifiedTime.ToString(CultureInfo.InvariantCulture)).Append(' ')
                        .Append(file.Length.ToString(CultureInfo.InvariantCulture)).Append(' ')
                        .Append(file.Name).Append('\n');
                }
            }

            string manifestText = text.ToString();
            byte[] manifestBytes = new UTF8Encoding(false).GetBytes(manifestText);
            byte[] manifestHash = HashBytes(manifestBytes, normalizedAlgorithm);
            string prefix = normalizedAlgorithm == "sha256new" ? "sha256new_" : normalizedAlgorithm + "=";
            string serializedHash = normalizedAlgorithm == "sha256new" ? ToBase32(manifestHash) : ToHex(manifestHash);
            return new ImplementationManifestResult
            {
                Algorithm = normalizedAlgorithm,
                Digest = prefix + serializedHash,
                ManifestText = manifestText,
                DirectoryCount = Math.Max(0, directories.Count - 1),
                FileCount = files.Count,
                TotalBytes = manifestBytesTotal
            };
        }

        private static void Walk(
            string root,
            string directory,
            SortedSet<string> directories,
            List<FileRecord> files,
            HashSet<string> executable,
            ref int entries,
            ref long totalBytes,
            int maximumEntries,
            long maximumBytes)
        {
            foreach (string childDirectory in Directory.EnumerateDirectories(directory))
            {
                RejectReparsePoint(childDirectory);
                string relative = NormalizeRelativePath(Path.GetRelativePath(root, childDirectory), "directory path");
                if (++entries > maximumEntries) throw new InvalidDataException("The implementation exceeds the entry limit.");
                directories.Add(relative);
                Walk(root, childDirectory, directories, files, executable, ref entries, ref totalBytes, maximumEntries, maximumBytes);
            }

            foreach (string childFile in Directory.EnumerateFiles(directory))
            {
                RejectReparsePoint(childFile);
                string relative = NormalizeRelativePath(Path.GetRelativePath(root, childFile), "file path");
                RejectManifestPath(relative);
                if (++entries > maximumEntries) throw new InvalidDataException("The implementation exceeds the entry limit.");
                var info = new FileInfo(childFile);
                checked { totalBytes += info.Length; }
                if (totalBytes > maximumBytes) throw new InvalidDataException("The implementation exceeds the byte limit.");

                int separator = relative.LastIndexOf('/');
                files.Add(new FileRecord
                {
                    RelativePath = relative,
                    Directory = separator < 0 ? string.Empty : relative.Substring(0, separator),
                    Name = separator < 0 ? relative : relative.Substring(separator + 1),
                    FullPath = childFile,
                    Length = info.Length,
                    ModifiedTime = new DateTimeOffset(info.LastWriteTimeUtc).ToUnixTimeSeconds(),
                    Executable = executable.Contains(relative)
                });
            }
        }

        private static void RejectReparsePoint(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Filesystem links are not supported in this manifest path: " + path);
        }

        private static void RejectManifestPath(string path)
        {
            if (path == ".manifest" || path == ".xbit" || path == ".symlink" || path.IndexOf('\n') >= 0)
                throw new InvalidDataException("The implementation contains a reserved Zero Install path: " + path);
        }

        private static string NormalizeRelativePath(string path, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A relative path is empty.", parameterName);
            string normalized = path.Replace('\\', '/');
            if (normalized.StartsWith("/", StringComparison.Ordinal) || Path.IsPathRooted(path))
                throw new ArgumentException("A relative path is rooted: " + path, parameterName);
            string[] parts = normalized.Split('/');
            foreach (string part in parts)
            {
                if (part.Length == 0 || part == "." || part == ".." || part.IndexOf('\0') >= 0 || part.IndexOf('\n') >= 0)
                    throw new ArgumentException("A relative path contains an invalid component: " + path, parameterName);
            }
            return normalized;
        }

        private static string JoinUnix(string directory, string name)
        {
            return directory.Length == 0 ? name : directory + "/" + name;
        }

        private static string NormalizeAlgorithm(string algorithm)
        {
            string value = (algorithm ?? string.Empty).Trim().ToLowerInvariant();
            if (value == "sha1new" || value == "sha256" || value == "sha256new") return value;
            throw new NotSupportedException("Unsupported Zero Install manifest algorithm: " + algorithm);
        }

        private static string HashFile(string path, string algorithm)
        {
            using (FileStream stream = File.OpenRead(path)) return ToHex(HashStream(stream, algorithm));
        }

        private static byte[] HashBytes(byte[] bytes, string algorithm)
        {
            using (var stream = new MemoryStream(bytes, false)) return HashStream(stream, algorithm);
        }

        private static byte[] HashStream(Stream stream, string algorithm)
        {
            using (HashAlgorithm hash = algorithm == "sha1new" ? (HashAlgorithm)SHA1.Create() : SHA256.Create())
                return hash.ComputeHash(stream);
        }

        private static string ToHex(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) result.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            return result.ToString();
        }

        private static string ToBase32(byte[] bytes)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            if (bytes.Length == 0) return string.Empty;
            var result = new StringBuilder((bytes.Length * 8 + 4) / 5);
            int buffer = bytes[0];
            int next = 1;
            int bitsLeft = 8;
            while (bitsLeft > 0 || next < bytes.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < bytes.Length)
                    {
                        buffer <<= 8;
                        buffer |= bytes[next++] & 0xff;
                        bitsLeft += 8;
                    }
                    else
                    {
                        buffer <<= 5 - bitsLeft;
                        bitsLeft = 5;
                    }
                }
                int index = 0x1f & (buffer >> (bitsLeft - 5));
                bitsLeft -= 5;
                result.Append(alphabet[index]);
            }
            return result.ToString();
        }
    }
}
