using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using MongoDB.Driver;
using Npgsql;

namespace Net8_Desktop_InsecureApp_Plus.Services
{
    // CWE-256: Unprotected Storage of Credentials
    public class DatabaseService
    {
        // Credentials in plain text config
        private readonly string mongoConnection = "mongodb://admin:password123@localhost:27017/vulnerable";
        private readonly string postgresConnection = "Host=localhost;Username=postgres;Password=postgres123;Database=vulnerable";

        private MongoClient mongoClient;

        public DatabaseService()
        {
            try
            {
                mongoClient = new MongoClient(mongoConnection);
            }
            catch
            {
                // Ignore MongoDB connection errors for testing
            }
        }

        // CWE-89: NoSQL Injection
        public async Task<List<object>> SearchMongoDB(string userInput)
        {
            try
            {
                var database = mongoClient.GetDatabase("vulnerable");
                var collection = database.GetCollection<object>("users");

                // Building query with string concatenation
                var filter = "{ username: '" + userInput + "' }";
                var query = MongoDB.Bson.Serialization.BsonSerializer.Deserialize<MongoDB.Bson.BsonDocument>(filter);

                var results = await collection.Find(query).ToListAsync();
                return results;
            }
            catch
            {
                // Return empty list if MongoDB is not available
                return new List<object>();
            }
        }

        // CWE-89: PostgreSQL Injection
        public async Task<List<Dictionary<string, object>>> SearchPostgreSQL(string searchTerm)
        {
            var results = new List<Dictionary<string, object>>();

            try
            {
                using (var conn = new NpgsqlConnection(postgresConnection))
                {
                    await conn.OpenAsync();

                    // SQL injection vulnerability
                    string query = $"SELECT * FROM products WHERE name LIKE '%{searchTerm}%' OR description LIKE '%{searchTerm}%'";

                    using (var cmd = new NpgsqlCommand(query, conn))
                    {
                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var row = new Dictionary<string, object>();
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    row[reader.GetName(i)] = reader.GetValue(i);
                                }
                                results.Add(row);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Return empty list if PostgreSQL is not available
            }

            return results;
        }
    }

    // CWE-285: Improper Authorization
    public class AuthorizationService
    {
        private static List<string> adminUsers = new List<string> { "admin", "root", "administrator" };

        // Weak authorization check
        public bool IsAuthorized(string username, string resource)
        {
            // Case-sensitive check (vulnerability)
            if (adminUsers.Contains(username))
                return true;

            // Path-based authorization bypass
            if (resource.Contains("..") || resource.Contains("admin"))
                return true;

            // Weak regex pattern
            if (Regex.IsMatch(username, @".*admin.*", RegexOptions.IgnoreCase))
                return true;

            return false;
        }

        // CWE-307: Improper Restriction of Excessive Authentication Attempts
        private Dictionary<string, int> loginAttempts = new Dictionary<string, int>();

        public bool CheckLoginAttempt(string username)
        {
            // No real rate limiting
            if (!loginAttempts.ContainsKey(username))
                loginAttempts[username] = 0;

            loginAttempts[username]++;

            // Weak check - easily bypassed
            return loginAttempts[username] < 1000;
        }
    }

    // CWE-311: Missing Encryption of Sensitive Data
    public class DataStorageService
    {
        private readonly string dataPath = @"C:\VulnerableApp\Data\";

        public DataStorageService()
        {
            // Create directory if it doesn't exist
            try
            {
                Directory.CreateDirectory(dataPath);
            }
            catch { }
        }

        // Storing sensitive data in plain text
        public void SaveCreditCard(string cardNumber, string cvv, string expiry)
        {
            try
            {
                string data = $"Card: {cardNumber}, CVV: {cvv}, Expiry: {expiry}";
                File.WriteAllText(Path.Combine(dataPath, "creditcards.txt"), data);
            }
            catch { }
        }

        // Storing passwords in plain text
        public void SaveUserPassword(string username, string password)
        {
            try
            {
                string userData = $"{username}:{password}";
                File.AppendAllText(Path.Combine(dataPath, "passwords.txt"), userData + Environment.NewLine);
            }
            catch { }
        }

        // CWE-312: Cleartext Storage of Sensitive Information
        public void SaveApiKeys(Dictionary<string, string> apiKeys)
        {
            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(apiKeys);
                File.WriteAllText(Path.Combine(dataPath, "apikeys.json"), json);
            }
            catch { }
        }
    }

    // CWE-352: Cross-Site Request Forgery (CSRF)
    public class WebService
    {
        private HttpClient httpClient = new HttpClient();

        // No CSRF token validation
        public async Task<string> ProcessPayment(string accountId, decimal amount)
        {
            try
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("account", accountId),
                    new KeyValuePair<string, string>("amount", amount.ToString())
                });

                // No CSRF protection
                var response = await httpClient.PostAsync("https://payment.example.com/transfer", content);
                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                return $"Payment processing error: {ex.Message}";
            }
        }

        // CWE-319: Cleartext Transmission of Sensitive Information
        public async Task<string> SendCredentials(string username, string password)
        {
            try
            {
                // Sending credentials over HTTP
                var response = await httpClient.GetAsync($"http://api.example.com/login?user={username}&pass={password}");
                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                return $"Credential transmission error: {ex.Message}";
            }
        }
    }

    // CWE-330: Use of Insufficiently Random Values
    public class TokenService
    {
        private Random random = new Random();

        // Predictable token generation
        public string GenerateSessionToken()
        {
            return DateTime.Now.Ticks.ToString() + random.Next(1000, 9999).ToString();
        }

        // Weak password reset token
        public string GeneratePasswordResetToken(string email)
        {
            // Using email hash as token (predictable)
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(email + DateTime.Now.Date.ToString()));
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        // CWE-338: Use of Cryptographically Weak PRNG
        public string GenerateApiKey()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var key = new char[32];

            for (int i = 0; i < key.Length; i++)
            {
                key[i] = chars[random.Next(chars.Length)];
            }

            return new string(key);
        }
    }

    // CWE-306: Missing Authentication for Critical Function
    public class AdminService
    {
        // No authentication check
        public void DeleteAllUsers()
        {
            try
            {
                // Critical operation without authentication
                using (var conn = new SqlConnection("Server=localhost;Database=Users;Integrated Security=true;"))
                {
                    conn.Open();
                    var cmd = new SqlCommand("DELETE FROM Users", conn);
                    cmd.ExecuteNonQuery();
                }
            }
            catch { }
        }

        // No authentication for backup
        public void BackupDatabase(string backupPath)
        {
            try
            {
                // Critical operation without authentication
                File.Copy(@"C:\Database\main.db", backupPath, true);
            }
            catch { }
        }

        // CWE-425: Direct Request ('Forced Browsing')
        public string GetAdminPanel()
        {
            try
            {
                // Admin panel accessible without proper checks
                return File.ReadAllText(@"C:\Web\admin.html");
            }
            catch
            {
                return "<html><body><h1>Admin Panel</h1><p>Full admin access granted!</p></body></html>";
            }
        }
    }

    // CWE-434: Unrestricted Upload of File with Dangerous Type
    public class FileUploadService
    {
        public void UploadFile(byte[] fileData, string fileName)
        {
            try
            {
                // No file type validation
                string uploadPath = Path.Combine(@"C:\Uploads\", fileName);
                Directory.CreateDirectory(@"C:\Uploads\");
                File.WriteAllBytes(uploadPath, fileData);

                // Execute if it's an executable (extremely dangerous)
                if (fileName.EndsWith(".exe"))
                {
                    System.Diagnostics.Process.Start(uploadPath);
                }
            }
            catch { }
        }

        // CWE-73: External Control of File Name or Path
        public void SaveUploadedFile(string userProvidedPath, byte[] data)
        {
            try
            {
                // User controls the full path
                File.WriteAllBytes(userProvidedPath, data);
            }
            catch { }
        }
    }

    // CWE-362: Concurrent Execution using Shared Resource (Race Condition)
    public class ConcurrentService
    {
        private static int balance = 1000;
        private static object lockObj = new object();

        // Race condition vulnerability
        public void TransferMoney(int amount)
        {
            // No proper locking
            if (balance >= amount)
            {
                System.Threading.Thread.Sleep(100); // Simulate processing
                balance -= amount;
            }
        }

        // TOCTOU (Time-of-check Time-of-use) vulnerability
        public void ProcessFile(string filePath)
        {
            if (File.Exists(filePath))
            {
                System.Threading.Thread.Sleep(100); // Window for race condition
                try
                {
                    string content = File.ReadAllText(filePath); // File might be gone/changed
                    ProcessContent(content);
                }
                catch { }
            }
        }

        private void ProcessContent(string content) { }
    }

    // CWE-369: Divide By Zero
    public class CalculationService
    {
        public double Calculate(double numerator, double denominator)
        {
            // No zero check
            return numerator / denominator;
        }

        // CWE-190: Integer Overflow
        public int MultiplyNumbers(int a, int b)
        {
            // No overflow check
            return a * b;
        }
    }
}