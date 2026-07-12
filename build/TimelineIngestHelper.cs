using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.VisualBasic.FileIO;

namespace ECHOTimelineIngestHelper
{
    internal static class Program
    {
        private static string _sqliteAssemblyPath = string.Empty;

        private static int Main(string[] args)
        {
            try
            {
                var parsed = ParseArgs(args);
                _sqliteAssemblyPath = GetArg(parsed, "sqlite");

                AppDomain.CurrentDomain.AssemblyResolve += CurrentDomain_AssemblyResolve;

                var mode = GetArg(parsed, "mode");
                var dbPath = GetArg(parsed, "db");
                var csvPath = GetArg(parsed, "csv");
                var tool = GetArg(parsed, "tool");
                var systemName = GetArg(parsed, "system");
                var fileType = GetArg(parsed, "filetype");
                var batchSize = 5000;
                if (parsed.ContainsKey("batch"))
                {
                    int parsedBatch;
                    if (int.TryParse(parsed["batch"], out parsedBatch) && parsedBatch > 0)
                    {
                        batchSize = parsedBatch;
                    }
                }

                if (!File.Exists(dbPath))
                {
                    Console.Error.WriteLine("Database path does not exist: " + dbPath);
                    return 2;
                }
                if (!File.Exists(csvPath))
                {
                    Console.Error.WriteLine("CSV path does not exist: " + csvPath);
                    return 3;
                }

                IngestStats stats;
                if (string.Equals(mode, "zimmerman-evtx", StringComparison.OrdinalIgnoreCase))
                {
                    stats = ProcessZimmermanEvtxCsv(dbPath, csvPath, tool, systemName, fileType, batchSize);
                    Console.WriteLine("ROWS_READ=" + stats.RowsRead.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_INSERTED=" + stats.RowsInserted.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_SKIPPED=" + stats.RowsSkipped.ToString(CultureInfo.InvariantCulture));
                    return 0;
                }
                if (string.Equals(mode, "zimmerman-mfte", StringComparison.OrdinalIgnoreCase))
                {
                    stats = ProcessZimmermanMfteCsv(dbPath, csvPath, tool, systemName, fileType, batchSize);
                    Console.WriteLine("ROWS_READ=" + stats.RowsRead.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_INSERTED=" + stats.RowsInserted.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_SKIPPED=" + stats.RowsSkipped.ToString(CultureInfo.InvariantCulture));
                    return 0;
                }
                if (string.Equals(mode, "zimmerman-propertystore", StringComparison.OrdinalIgnoreCase))
                {
                    stats = ProcessZimmermanPropertyStoreCsv(dbPath, csvPath, tool, systemName, fileType, batchSize);
                    Console.WriteLine("ROWS_READ=" + stats.RowsRead.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_INSERTED=" + stats.RowsInserted.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_SKIPPED=" + stats.RowsSkipped.ToString(CultureInfo.InvariantCulture));
                    return 0;
                }
                if (string.Equals(mode, "zimmerman-srum", StringComparison.OrdinalIgnoreCase))
                {
                    stats = ProcessZimmermanSrumCsv(dbPath, csvPath, tool, systemName, fileType, batchSize);
                    Console.WriteLine("ROWS_READ=" + stats.RowsRead.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_INSERTED=" + stats.RowsInserted.ToString(CultureInfo.InvariantCulture));
                    Console.WriteLine("ROWS_SKIPPED=" + stats.RowsSkipped.ToString(CultureInfo.InvariantCulture));
                    return 0;
                }

                Console.Error.WriteLine("Unsupported mode: " + mode);
                return 4;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Helper failed: " + ex);
                return 1;
            }
        }

        private static System.Reflection.Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            if (string.IsNullOrWhiteSpace(_sqliteAssemblyPath) || !File.Exists(_sqliteAssemblyPath))
            {
                return null;
            }

            var requestedName = new System.Reflection.AssemblyName(args.Name).Name;
            if (!string.Equals(requestedName, "System.Data.SQLite", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return System.Reflection.Assembly.LoadFrom(_sqliteAssemblyPath);
        }

        private sealed class IngestStats
        {
            public int RowsRead;
            public int RowsInserted;
            public int RowsSkipped;
        }

        private static IngestStats ProcessZimmermanEvtxCsv(
            string databasePath,
            string csvPath,
            string tool,
            string systemName,
            string fileType,
            int batchSize)
        {
            var fileName = Path.GetFileName(csvPath);
            var stats = new IngestStats();

            using (var connection = new SQLiteConnection("Data Source=" + databasePath + ";Version=3;"))
            {
                connection.Open();
                ExecutePragmas(connection);

                using (var parser = new TextFieldParser(csvPath, Encoding.UTF8))
                {
                    parser.TextFieldType = FieldType.Delimited;
                    parser.SetDelimiters(",");
                    parser.HasFieldsEnclosedInQuotes = true;

                    if (parser.EndOfData)
                    {
                        return stats;
                    }

                    var headers = parser.ReadFields();
                    if (headers == null || headers.Length == 0)
                    {
                        return stats;
                    }

                    var indexMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (var i = 0; i < headers.Length; i++)
                    {
                        if (!indexMap.ContainsKey(headers[i]))
                        {
                            indexMap.Add(headers[i], i);
                        }
                    }

                    using (var coreCommand = CreateCoreInsertCommand(connection))
                    using (var typeCommand = CreateTypeInsertCommand(connection, fileType))
                    {
                        ExecuteBatchedInsert(connection, batchSize, row =>
                        {
                            stats.RowsRead++;
                            if (row == null)
                            {
                                stats.RowsSkipped++;
                                return false;
                            }

                            var timestamp = FormatTimestamp(GetField(row, indexMap, "TimeCreated"));
                            var userName = GetField(row, indexMap, "UserName");

                            var eventDescription =
                                "Map Description " + EmptyField(GetField(row, indexMap, "MapDescription")) +
                                " with PayloadData1: " + EmptyField(GetField(row, indexMap, "PayloadData1")) +
                                " Data2: " + EmptyField(GetField(row, indexMap, "PayloadData2")) +
                                " Data3: " + EmptyField(GetField(row, indexMap, "PayloadData3")) +
                                " Data4: " + EmptyField(GetField(row, indexMap, "PayloadData4")) +
                                " Data5: " + EmptyField(GetField(row, indexMap, "PayloadData5")) +
                                " Data6: " + EmptyField(GetField(row, indexMap, "PayloadData6")) +
                                " Executable Info: " + EmptyField(GetField(row, indexMap, "ExecutableInfo")) +
                                " RemoteHost: " + EmptyField(GetField(row, indexMap, "RemoteHost"));

                            WriteNormalizedRow(
                                coreCommand,
                                typeCommand,
                                row,
                                headers,
                                timestamp,
                                systemName,
                                userName,
                                eventDescription,
                                tool,
                                fileName,
                                csvPath,
                                fileType
                            );
                            return true;
                        }, parser, stats, transaction =>
                        {
                            coreCommand.Transaction = transaction;
                            typeCommand.Transaction = transaction;
                        });
                    }
                }
            }

            return stats;
        }

        private static IngestStats ProcessZimmermanMfteCsv(
            string databasePath,
            string csvPath,
            string tool,
            string systemName,
            string fileType,
            int batchSize)
        {
            var fileName = Path.GetFileName(csvPath);
            var isJ = fileName.IndexOf("_MFTECmd_$J_Output.csv", StringComparison.OrdinalIgnoreCase) >= 0;
            var stats = new IngestStats();

            using (var connection = new SQLiteConnection("Data Source=" + databasePath + ";Version=3;"))
            {
                connection.Open();
                ExecutePragmas(connection);

                using (var parser = new TextFieldParser(csvPath, Encoding.UTF8))
                {
                    parser.TextFieldType = FieldType.Delimited;
                    parser.SetDelimiters(",");
                    parser.HasFieldsEnclosedInQuotes = true;
                    if (parser.EndOfData) { return stats; }

                    var headers = parser.ReadFields();
                    if (headers == null || headers.Length == 0) { return stats; }
                    var indexMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (var i = 0; i < headers.Length; i++) { if (!indexMap.ContainsKey(headers[i])) { indexMap.Add(headers[i], i); } }

                    using (var coreCommand = CreateCoreInsertCommand(connection))
                    using (var typeCommand = CreateTypeInsertCommand(connection, fileType))
                    {
                        ExecuteBatchedInsert(connection, batchSize, row =>
                        {
                            stats.RowsRead++;
                            if (row == null) { stats.RowsSkipped++; return false; }
                            string timestamp;
                            string eventDescription;
                            if (isJ)
                            {
                                var parentPath = EmptyField(GetField(row, indexMap, "ParentPath"));
                                var name = EmptyField(GetField(row, indexMap, "Name"));
                                var updateReasons = EmptyField(GetField(row, indexMap, "UpdateReasons"));
                                timestamp = FormatTimestamp(GetField(row, indexMap, "UpdateTimestamp"));
                                eventDescription = parentPath + "\\" + name + " updated with reason " + updateReasons;
                            }
                            else
                            {
                                var parentPath = EmptyField(GetField(row, indexMap, "ParentPath"));
                                var fileNameValue = EmptyField(GetField(row, indexMap, "FileName"));
                                var inUse = EmptyField(GetField(row, indexMap, "InUse"));
                                var siFn = EmptyField(GetField(row, indexMap, "SI<FN"));
                                timestamp = FormatTimestamp(GetField(row, indexMap, "Created0x10"));
                                eventDescription = parentPath + "\\" + fileNameValue + " created with In use: " + inUse + " and SI<FN: " + siFn;
                            }

                            WriteNormalizedRow(
                                coreCommand,
                                typeCommand,
                                row,
                                headers,
                                timestamp,
                                systemName,
                                null,
                                eventDescription,
                                tool,
                                fileName,
                                csvPath,
                                fileType
                            );
                            return true;
                        }, parser, stats, transaction =>
                        {
                            coreCommand.Transaction = transaction;
                            typeCommand.Transaction = transaction;
                        });
                    }
                }
            }
            return stats;
        }

        private static IngestStats ProcessZimmermanPropertyStoreCsv(
            string databasePath,
            string csvPath,
            string tool,
            string systemName,
            string fileType,
            int batchSize)
        {
            var fileName = Path.GetFileName(csvPath);
            var stats = new IngestStats();

            using (var connection = new SQLiteConnection("Data Source=" + databasePath + ";Version=3;"))
            {
                connection.Open();
                ExecutePragmas(connection);

                using (var parser = new TextFieldParser(csvPath, Encoding.UTF8))
                {
                    parser.TextFieldType = FieldType.Delimited;
                    parser.SetDelimiters(",");
                    parser.HasFieldsEnclosedInQuotes = true;
                    if (parser.EndOfData) { return stats; }

                    var headers = parser.ReadFields();
                    if (headers == null || headers.Length == 0) { return stats; }
                    var indexMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (var i = 0; i < headers.Length; i++) { if (!indexMap.ContainsKey(headers[i])) { indexMap.Add(headers[i], i); } }

                    using (var coreCommand = CreateCoreInsertCommand(connection))
                    using (var typeCommand = CreateTypeInsertCommand(connection, fileType))
                    {
                        ExecuteBatchedInsert(connection, batchSize, row =>
                        {
                            stats.RowsRead++;
                            if (row == null) { stats.RowsSkipped++; return false; }

                            var timestamp = FormatTimestamp(
                                Coalesce(
                                    GetField(row, indexMap, "LastModifiedTime"),
                                    GetField(row, indexMap, "LastModified"),
                                    GetField(row, indexMap, "ModifiedTime"),
                                    GetField(row, indexMap, "CreatedTime"),
                                    GetField(row, indexMap, "Timestamp"),
                                    GetField(row, indexMap, "DateCreated")
                                )
                            );

                            var eventDescription = BuildPropertyStoreDescription(row, indexMap);
                            var userName = TryExtractUserFromSourceFile(GetField(row, indexMap, "SourceFile"));

                            WriteNormalizedRow(
                                coreCommand,
                                typeCommand,
                                row,
                                headers,
                                timestamp,
                                systemName,
                                userName,
                                eventDescription,
                                tool,
                                fileName,
                                csvPath,
                                fileType
                            );
                            return true;
                        }, parser, stats, transaction =>
                        {
                            coreCommand.Transaction = transaction;
                            typeCommand.Transaction = transaction;
                        });
                    }
                }
            }

            return stats;
        }

        private static IngestStats ProcessZimmermanSrumCsv(
            string databasePath,
            string csvPath,
            string tool,
            string systemName,
            string fileType,
            int batchSize)
        {
            var fileName = Path.GetFileName(csvPath);
            var stats = new IngestStats();

            using (var connection = new SQLiteConnection("Data Source=" + databasePath + ";Version=3;"))
            {
                connection.Open();
                ExecutePragmas(connection);

                using (var parser = new TextFieldParser(csvPath, Encoding.UTF8))
                {
                    parser.TextFieldType = FieldType.Delimited;
                    parser.SetDelimiters(",");
                    parser.HasFieldsEnclosedInQuotes = true;
                    if (parser.EndOfData) { return stats; }

                    var headers = parser.ReadFields();
                    if (headers == null || headers.Length == 0) { return stats; }
                    var indexMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (var i = 0; i < headers.Length; i++) { if (!indexMap.ContainsKey(headers[i])) { indexMap.Add(headers[i], i); } }

                    using (var coreCommand = CreateCoreInsertCommand(connection))
                    using (var typeCommand = CreateTypeInsertCommand(connection, fileType))
                    {
                        ExecuteBatchedInsert(connection, batchSize, row =>
                        {
                            stats.RowsRead++;
                            if (row == null) { stats.RowsSkipped++; return false; }

                            var timestamp = FormatTimestamp(GetField(row, indexMap, "Timestamp"));
                            var userName = GetField(row, indexMap, "UserName");
                            var eventDescription = BuildSrumDescription(fileName, row, indexMap);

                            WriteNormalizedRow(
                                coreCommand,
                                typeCommand,
                                row,
                                headers,
                                timestamp,
                                systemName,
                                userName,
                                eventDescription,
                                tool,
                                fileName,
                                csvPath,
                                fileType
                            );
                            return true;
                        }, parser, stats, transaction =>
                        {
                            coreCommand.Transaction = transaction;
                            typeCommand.Transaction = transaction;
                        });
                    }
                }
            }

            return stats;
        }

        private static void ExecuteBatchedInsert(
            SQLiteConnection connection,
            int batchSize,
            Func<string[], bool> bindRow,
            TextFieldParser parser,
            IngestStats stats,
            Action<SQLiteTransaction> onTransactionChanged = null)
        {
            SQLiteTransaction transaction = null;
            try
            {
                transaction = connection.BeginTransaction();
                if (onTransactionChanged != null) { onTransactionChanged(transaction); }
                while (!parser.EndOfData)
                {
                    var row = parser.ReadFields();
                    if (!bindRow(row))
                    {
                        continue;
                    }

                    stats.RowsInserted++;
                    if ((stats.RowsInserted % batchSize) == 0)
                    {
                        transaction.Commit();
                        transaction.Dispose();
                        transaction = connection.BeginTransaction();
                        if (onTransactionChanged != null) { onTransactionChanged(transaction); }
                    }
                }
                transaction.Commit();
            }
            catch
            {
                if (transaction != null) { try { transaction.Rollback(); } catch { } }
                throw;
            }
            finally
            {
                if (transaction != null) { transaction.Dispose(); }
            }
        }

        private static void ExecutePragmas(SQLiteConnection connection)
        {
            var pragmas = new[]
            {
                "PRAGMA synchronous = OFF;",
                "PRAGMA journal_mode = MEMORY;",
                "PRAGMA temp_store = MEMORY;",
                "PRAGMA cache_size = -50000;",
                "PRAGMA mmap_size = 2147483648;",
                "PRAGMA page_size = 4096;",
                "PRAGMA cache_spill = FALSE;",
                "PRAGMA wal_autocheckpoint = 10000;",
                "PRAGMA busy_timeout = 120000;"
            };

            foreach (var pragma in pragmas)
            {
                using (var cmd = new SQLiteCommand(pragma, connection))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }

        private static SQLiteCommand CreateCoreInsertCommand(SQLiteConnection connection)
        {
            var command = new SQLiteCommand(
                "INSERT INTO events_core ('@timestamp', system_name, user_name, event_description, tool, file_name, source_file, file_type) " +
                "VALUES (@p_timestamp, @p_system_name, @p_user_name, @p_event_description, @p_tool, @p_file_name, @p_source_file, @p_file_type); " +
                "SELECT last_insert_rowid();",
                connection
            );
            command.Parameters.Add("@p_timestamp", DbType.String);
            command.Parameters.Add("@p_system_name", DbType.String);
            command.Parameters.Add("@p_user_name", DbType.String);
            command.Parameters.Add("@p_event_description", DbType.String);
            command.Parameters.Add("@p_tool", DbType.String);
            command.Parameters.Add("@p_file_name", DbType.String);
            command.Parameters.Add("@p_source_file", DbType.String);
            command.Parameters.Add("@p_file_type", DbType.String);
            return command;
        }

        private static string GetArtifactTypeTableName(string fileType)
        {
            var raw = string.IsNullOrWhiteSpace(fileType) ? "unknown" : fileType.ToLowerInvariant();
            var safe = Regex.Replace(raw, "[^a-z0-9_]", "_");
            if (string.IsNullOrWhiteSpace(safe))
            {
                safe = "unknown";
            }
            return "artifact_" + safe;
        }

        private static void EnsureArtifactTypeTable(SQLiteConnection connection, string tableName)
        {
            var sql = "CREATE TABLE IF NOT EXISTS [" + tableName + "] (" +
                      "event_id INTEGER PRIMARY KEY, " +
                      "attributes_json TEXT, " +
                      "FOREIGN KEY(event_id) REFERENCES events_core(event_id) ON DELETE CASCADE" +
                      ");";
            using (var cmd = new SQLiteCommand(sql, connection))
            {
                cmd.ExecuteNonQuery();
            }
        }

        private static SQLiteCommand CreateTypeInsertCommand(SQLiteConnection connection, string fileType)
        {
            var tableName = GetArtifactTypeTableName(fileType);
            EnsureArtifactTypeTable(connection, tableName);
            var sql = "INSERT OR REPLACE INTO [" + tableName + "] " +
                      "(event_id, attributes_json) " +
                      "VALUES (@event_id, @attributes_json);";
            var command = new SQLiteCommand(sql, connection);
            command.Parameters.Add("@event_id", DbType.Int64);
            command.Parameters.Add("@attributes_json", DbType.String);
            return command;
        }

        private static string BuildAttributesJson(string[] headers, string[] row)
        {
            const int maxAttributes = 64;
            const int maxValueLength = 1024;
            const int maxJsonLength = 8192;
            var first = true;
            var count = 0;
            var sb = new StringBuilder();
            sb.Append("{");
            for (var i = 0; i < headers.Length; i++)
            {
                var key = headers[i];
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }
                if (IsCoreKey(key))
                {
                    continue;
                }
                var value = i < row.Length ? row[i] : null;
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }
                var safeValue = Sanitize(value);
                if (safeValue.Length > maxValueLength)
                {
                    safeValue = safeValue.Substring(0, maxValueLength);
                }
                if (!first)
                {
                    sb.Append(",");
                }
                sb.Append("\"").Append(EscapeJson(key)).Append("\":\"").Append(EscapeJson(safeValue)).Append("\"");
                first = false;
                count++;
                if (count >= maxAttributes || sb.Length >= maxJsonLength)
                {
                    break;
                }
            }
            sb.Append("}");
            if (first)
            {
                return null;
            }
            var json = sb.ToString();
            if (json.Length > maxJsonLength)
            {
                json = json.Substring(0, maxJsonLength);
            }
            return json;
        }

        private static bool IsCoreKey(string key)
        {
            return string.Equals(key, "@timestamp", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "timestamp", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "system_name", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "user_name", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "event_description", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "tool", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "file_name", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "source_file", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "file_type", StringComparison.OrdinalIgnoreCase);
        }

        private static string EscapeJson(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }

        private static void WriteNormalizedRow(
            SQLiteCommand coreCommand,
            SQLiteCommand typeCommand,
            string[] row,
            string[] headers,
            string timestamp,
            string systemName,
            string userName,
            string eventDescription,
            string tool,
            string fileName,
            string sourceFile,
            string fileType)
        {
            SetParam(coreCommand, "@p_timestamp", timestamp);
            SetParam(coreCommand, "@p_system_name", systemName);
            SetParam(coreCommand, "@p_user_name", userName);
            SetParam(coreCommand, "@p_event_description", eventDescription);
            SetParam(coreCommand, "@p_tool", tool);
            SetParam(coreCommand, "@p_file_name", fileName);
            SetParam(coreCommand, "@p_source_file", sourceFile);
            SetParam(coreCommand, "@p_file_type", fileType);
            var eventId = Convert.ToInt64(coreCommand.ExecuteScalar(), CultureInfo.InvariantCulture);

            typeCommand.Parameters["@event_id"].Value = eventId;
            var attributesJson = BuildAttributesJson(headers, row);
            SetParam(typeCommand, "@attributes_json", attributesJson);
            typeCommand.ExecuteNonQuery();
        }

        private static string GetField(string[] row, Dictionary<string, int> indexMap, string name)
        {
            int idx;
            if (!indexMap.TryGetValue(name, out idx))
            {
                return null;
            }
            if (idx < 0 || idx >= row.Length)
            {
                return null;
            }
            return row[idx];
        }

        private static string EmptyField(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "<empty_field>";
            }
            return Sanitize(value);
        }

        private static string Coalesce(params string[] values)
        {
            for (var i = 0; i < values.Length; i++)
            {
                if (!string.IsNullOrWhiteSpace(values[i]))
                {
                    return values[i];
                }
            }
            return null;
        }

        private static string BuildPropertyStoreDescription(string[] row, Dictionary<string, int> indexMap)
        {
            var parentPath = GetField(row, indexMap, "ParentPath");
            var fileName = GetField(row, indexMap, "FileName");
            if (!string.IsNullOrWhiteSpace(parentPath) || !string.IsNullOrWhiteSpace(fileName))
            {
                return EmptyField(parentPath) + "\\" + EmptyField(fileName) + " property store record";
            }

            var name = GetField(row, indexMap, "Name");
            var value = GetField(row, indexMap, "Value");
            if (!string.IsNullOrWhiteSpace(name) || !string.IsNullOrWhiteSpace(value))
            {
                return "Property " + EmptyField(name) + " with value " + EmptyField(value);
            }

            return "PropertyStore record imported";
        }

        private static string BuildSrumDescription(string fileName, string[] row, Dictionary<string, int> indexMap)
        {
            if (fileName.IndexOf("_SrumECmd_AppResourceUseInfo", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum App Resource Usage shows executable " + EmptyField(GetField(row, indexMap, "ExeInfo")) +
                       " having background bytes written of " + EmptyField(GetField(row, indexMap, "BackgroundBytesWritten")) +
                       " and foreground bytes written as " + EmptyField(GetField(row, indexMap, "ForegroundBytesWritten")) +
                       " by user " + EmptyField(GetField(row, indexMap, "UserName"));
            }
            if (fileName.IndexOf("_SrumECmd_AppTimelineProvider", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum App Timeline Provider shows executable " + EmptyField(GetField(row, indexMap, "ExeInfo")) +
                       " having a timestamp of " + EmptyField(GetField(row, indexMap, "ExeTimestamp")) +
                       ", an Endtime of " + EmptyField(GetField(row, indexMap, "EndTime")) +
                       ", and duration of " + EmptyField(GetField(row, indexMap, "DurationMs")) +
                       " Ms by user " + EmptyField(GetField(row, indexMap, "UserName"));
            }
            if (fileName.IndexOf("_SrumECmd_NetworkUsages", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum Network Usage shows executable " + EmptyField(GetField(row, indexMap, "ExeInfo")) +
                       " having bytes received as " + EmptyField(GetField(row, indexMap, "BytesReceived")) +
                       " and bytes sent as " + EmptyField(GetField(row, indexMap, "BytesSent")) +
                       " by user " + EmptyField(GetField(row, indexMap, "UserName"));
            }
            if (fileName.IndexOf("_SrumECmd_EnergyUsage", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum Energy Usage";
            }
            if (fileName.IndexOf("_SrumECmd_NetworkConnections", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum Network Connections";
            }
            if (fileName.IndexOf("_SrumECmd_PushNotifications", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum Push Notification of " + EmptyField(GetField(row, indexMap, "ExeInfo")) +
                       " with description " + EmptyField(GetField(row, indexMap, "ExeInfoDescription"));
            }
            if (fileName.IndexOf("_SrumECmd_vfuprov", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Srum vfuprov information";
            }
            return "SRUM record imported";
        }

        private static string TryExtractUserFromSourceFile(string sourceFile)
        {
            if (string.IsNullOrWhiteSpace(sourceFile))
            {
                return null;
            }

            var match = Regex.Match(sourceFile, @"Users\\([^\\]+)\\", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : null;
        }

        private static string Sanitize(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            var sb = new StringBuilder(value.Length);
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if (c == '\r' || c == '\n' || c == '\t')
                {
                    sb.Append(' ');
                    continue;
                }
                if (c < 32 || c > 126)
                {
                    continue;
                }
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static string FormatTimestamp(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "1970-01-01 00:00:00.0000000";
            }

            DateTime dt;
            if (DateTime.TryParse(value, out dt))
            {
                return dt.ToString("yyyy-MM-dd HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
            }

            return "1970-01-01 00:00:00.0000000";
        }

        private static void SetParam(SQLiteCommand command, string name, string value)
        {
            command.Parameters[name].Value = string.IsNullOrEmpty(value) ? (object)DBNull.Value : value;
        }

        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < args.Length; i++)
            {
                var current = args[i];
                if (!current.StartsWith("--", StringComparison.Ordinal))
                {
                    continue;
                }

                var key = current.Substring(2);
                string value = string.Empty;
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    value = args[++i];
                }
                dict[key] = value;
            }
            return dict;
        }

        private static string GetArg(Dictionary<string, string> parsed, string key)
        {
            string value;
            if (!parsed.TryGetValue(key, out value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Missing required argument --" + key);
            }
            return value;
        }
    }
}
