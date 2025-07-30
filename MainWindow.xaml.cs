using Microsoft.Win32;
using Net8_Desktop_InsecureApp_Plus.Services;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Xml;

namespace Net8_Desktop_InsecureApp_Plus
{
    public partial class MainWindow : Window
    {
        // CWE-798: Hardcoded credentials (Multiple instances)
        private const string API_KEY = "sk-1234567890abcdef";
        private const string DB_PASSWORD = "admin123";
        private const string JWT_SECRET = "my-super-secret-key-123";
        private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string CONNECTION_STRING = "Server=localhost;Database=VulnDB;User Id=sa;Password=admin123;TrustServerCertificate=true;";

        private static HttpClient httpClient = new HttpClient();

        // Services instances
        private DatabaseService databaseService;
        private AuthorizationService authService;
        private DataStorageService dataStorageService;
        private WebService webService;
        private TokenService tokenService;
        private AdminService adminService;
        private FileUploadService fileUploadService;
        private ConcurrentService concurrentService;
        private CalculationService calculationService;

        public MainWindow()
        {
            InitializeComponent();
            ConfigureInsecureSettings();
            InitializeServices();
        }

        private void InitializeServices()
        {
            databaseService = new DatabaseService();
            authService = new AuthorizationService();
            dataStorageService = new DataStorageService();
            webService = new WebService();
            tokenService = new TokenService();
            adminService = new AdminService();
            fileUploadService = new FileUploadService();
            concurrentService = new ConcurrentService();
            calculationService = new CalculationService();
        }

        // CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
        private void ConfigureInsecureSettings()
        {
            // Disable security protocols
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            // Set insecure HTTP client
            httpClient.DefaultRequestHeaders.Add("Api-Key", API_KEY);
        }

        // CWE-89: SQL Injection (Multiple variants)
        private async void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            string username = txtUsername.Text;
            string password = txtPassword.Text;

            // Test authorization service
            bool isAuthorized = authService.IsAuthorized(username, "admin");

            // Test login attempts
            bool canAttempt = authService.CheckLoginAttempt(username);

            if (!canAttempt)
            {
                MessageBox.Show("Too many login attempts!");
                return;
            }

            // Generate insecure session token
            string sessionToken = tokenService.GenerateSessionToken();

            // Store password in plain text
            dataStorageService.SaveUserPassword(username, password);

            // Original SQL injection code
            string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";
            string query2 = String.Format("SELECT * FROM Users WHERE Email = '{0}'", username);
            string query3 = $@"
                SELECT u.*, r.* FROM Users u
                JOIN Roles r ON u.RoleId = r.Id
                WHERE u.Username = '{username}' 
                AND u.Password = '{GetMD5Hash(password)}'";

            using (SqlConnection conn = new SqlConnection(CONNECTION_STRING))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                try
                {
                    await conn.OpenAsync();
                    var reader = await cmd.ExecuteReaderAsync();
                    if (reader.HasRows)
                    {
                        MessageBox.Show($"Login successful!\nSession Token: {sessionToken}\nAuthorized: {isAuthorized}");
                        LogUserActivity(username, "LOGIN_SUCCESS");

                        // Test MongoDB injection
                        try
                        {
                            var mongoResults = await databaseService.SearchMongoDB(username);
                            MessageBox.Show($"Found {mongoResults.Count} MongoDB results");
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    // CWE-209: Information Exposure Through Error Messages
                    MessageBox.Show($"Database Error: {ex.ToString()}\nStack: {ex.StackTrace}");
                    File.AppendAllText("errors.log", $"{DateTime.Now}: {ex.ToString()}\n");
                }
            }
        }

        // CWE-78: OS Command Injection
        private async void btnExecute_Click(object sender, RoutedEventArgs e)
        {
            string userInput = txtCommand.Text;

            // Test calculation service with potential divide by zero
            try
            {
                double result = calculationService.Calculate(100, 0);
                MessageBox.Show($"Calculation result: {result}");
            }
            catch { }

            // Test integer overflow
            int overflow = calculationService.MultiplyNumbers(int.MaxValue, 2);

            // Original command injection code
            Process.Start("cmd.exe", $"/c {userInput}");
            Process.Start("powershell.exe", $"-Command {userInput}");

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + userInput,
                UseShellExecute = true,
                RedirectStandardOutput = false
            };
            Process.Start(psi);

            await File.AppendAllTextAsync("commands.log", $"{DateTime.Now}: Executed: {userInput}\n");
        }

        // CWE-611: XXE Injection
        private void btnParseXML_Click(object sender, RoutedEventArgs e)
        {
            string xmlContent = txtXmlInput.Text;

            // Test file upload with XML content
            fileUploadService.UploadFile(Encoding.UTF8.GetBytes(xmlContent), "upload.xml");

            // Original XXE code
            XmlDocument doc = new XmlDocument();
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver(),
                MaxCharactersFromEntities = long.MaxValue,
                MaxCharactersInDocument = long.MaxValue
            };

            using (XmlReader reader = XmlReader.Create(new StringReader(xmlContent), settings))
            {
                doc.Load(reader);
            }

            MessageBox.Show("XML parsed: " + doc.OuterXml);
        }

        // CWE-502: Deserialization of Untrusted Data
        private void btnDeserialize_Click(object sender, RoutedEventArgs e)
        {
            string serializedData = txtSerializedData.Text;

            // Generate weak API key
            string apiKey = tokenService.GenerateApiKey();
            MessageBox.Show($"Generated API Key: {apiKey}");

            try
            {
#pragma warning disable SYSLIB0011
                byte[] bytes = Convert.FromBase64String(serializedData);
                BinaryFormatter formatter = new BinaryFormatter();
                using (MemoryStream stream = new MemoryStream(bytes))
                {
                    var obj = formatter.Deserialize(stream);
                    MessageBox.Show("Deserialized: " + obj.ToString());
                }
#pragma warning restore SYSLIB0011
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
        }

        // CWE-22: Path Traversal
        private async void btnReadFile_Click(object sender, RoutedEventArgs e)
        {
            string fileName = txtFileName.Text;

            // Test PostgreSQL injection
            try
            {
                var pgResults = await databaseService.SearchPostgreSQL(fileName);
                MessageBox.Show($"PostgreSQL results: {pgResults.Count} rows");
            }
            catch { }

            // Test admin service without auth
            string adminPanel = adminService.GetAdminPanel();

            // Original path traversal code
            string filePath = Path.Combine(@"C:\Data\", fileName);

            if (File.Exists(filePath))
            {
                string content = await File.ReadAllTextAsync(filePath);
                txtFileContent.Text = content;

                // Test concurrent file access
                concurrentService.ProcessFile(filePath);

                File.Copy(filePath, Path.Combine(Path.GetTempPath(), fileName), true);
            }
        }

        // CWE-918: SSRF
        private async void btnFetchUrl_Click(object sender, RoutedEventArgs e)
        {
            string url = txtUrl.Text;

            // Test sending credentials over HTTP
            try
            {
                await webService.SendCredentials("testuser", "testpass");
            }
            catch { }

            try
            {
                var response = await httpClient.GetStringAsync(url);
                txtResult.Text = response;
                await File.AppendAllTextAsync("urls.log", $"{DateTime.Now}: Accessed {url}\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.ToString());
            }
        }

        // CWE-94: Code Injection
        private void btnEvaluate_Click(object sender, RoutedEventArgs e)
        {
            string expression = txtExpression.Text;

            // Test concurrent money transfer (race condition)
            concurrentService.TransferMoney(100);

            // Original code injection
            var provider = new Microsoft.CSharp.CSharpCodeProvider();
            var parameters = new System.CodeDom.Compiler.CompilerParameters
            {
                GenerateExecutable = false,
                GenerateInMemory = true
            };
            parameters.ReferencedAssemblies.Add("System.dll");

            string code = $@"
                using System;
                public class Evaluator
                {{
                    public static object Evaluate()
                    {{
                        return {expression};
                    }}
                }}";

            var results = provider.CompileAssemblyFromSource(parameters, code);
            if (!results.Errors.HasErrors)
            {
                var assembly = results.CompiledAssembly;
                var evaluatorType = assembly.GetType("Evaluator");
                var evaluateMethod = evaluatorType.GetMethod("Evaluate");
                var evalResult = evaluateMethod.Invoke(null, null);
                MessageBox.Show("Result: " + evalResult);
            }
        }

        // CWE-79: XSS in WebBrowser
        private void btnDisplayHtml_Click(object sender, RoutedEventArgs e)
        {
            string userHtml = txtHtmlInput.Text;

            // Save API keys in plain text
            var apiKeys = new Dictionary<string, string>
            {
                { "stripe", "sk_test_123456" },
                { "aws", AWS_ACCESS_KEY },
                { "github", "ghp_1234567890abcdef" }
            };
            dataStorageService.SaveApiKeys(apiKeys);

            // No HTML encoding
            string html = "<html><body><h1>User Input:</h1>" + userHtml + "</body></html>";
            webBrowser.NavigateToString(html);
        }

        // CWE-259: Hard-coded Password
        private async void btnValidateAdmin_Click(object sender, RoutedEventArgs e)
        {
            if (ValidateAdminAccess())
            {
                MessageBox.Show("Admin access granted!");

                // Test payment processing without CSRF
                try
                {
                    string result = await webService.ProcessPayment("12345", 1000.00m);
                    MessageBox.Show($"Payment processed: {result}");
                }
                catch { }

                // Test admin operations without auth
                adminService.BackupDatabase(@"C:\Temp\backup.db");
            }
            else
            {
                MessageBox.Show("Invalid password!");

                // Generate password reset token
                string resetToken = tokenService.GeneratePasswordResetToken(txtAdminPassword.Password);
                MessageBox.Show($"Reset token: {resetToken}");
            }
        }

        // CWE-259: Hard-coded Password
        private bool ValidateAdminAccess()
        {
            return txtAdminPassword.Password == "SuperSecret123!";
        }

        // CWE-295: Certificate Validation Bypass
        private void btnHttpsRequest_Click(object sender, RoutedEventArgs e)
        {
            ServicePointManager.ServerCertificateValidationCallback =
                (sender, certificate, chain, errors) => true;

            using (WebClient client = new WebClient())
            {
                string result = client.DownloadString("https://example.com");
                MessageBox.Show("Downloaded: " + result.Substring(0, Math.Min(100, result.Length)));
            }
        }

        // CWE-327: Weak Cryptography
        private string GetMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // CWE-321: Hard-coded Cryptographic Key
        private string EncryptDataAES(string plainText)
        {
            byte[] key = Encoding.UTF8.GetBytes("ThisIsMySecretKey12345678901234!");
            byte[] iv = Encoding.UTF8.GetBytes("1234567890123456");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.ECB; // Insecure mode

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
                return Convert.ToBase64String(encrypted);
            }
        }

        // CWE-73: External Control of File Name
        private void btnSaveFile_Click(object sender, RoutedEventArgs e)
        {
            string fileName = txtSaveFileName.Text;
            string content = txtSaveContent.Text;

            // Save credit card info in plain text
            dataStorageService.SaveCreditCard("4111111111111111", "123", "12/25");

            // Use file upload service with user-controlled path
            fileUploadService.SaveUploadedFile(fileName, Encoding.UTF8.GetBytes(content));

            // Original code
            File.WriteAllText(fileName, content);
            MessageBox.Show("File saved!");
        }

        // CWE-117: Log Injection
        private void LogUserActivity(string username, string action)
        {
            string token = GenerateInsecureToken();
            string logEntry = $"{DateTime.Now}|{username}|{action}|{token}";
            File.AppendAllText("activity.log", logEntry + Environment.NewLine);
        }

        // CWE-331: Insufficient Entropy
        private string GenerateInsecureToken()
        {
            Random rand = new Random();
            return rand.Next(1000000, 9999999).ToString();
        }

        // CWE-759: No Salt in Password Hash
        private string HashPasswordInsecure(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }

        // CWE-613: Insufficient Session Expiration
        private static Dictionary<string, DateTime> sessions = new Dictionary<string, DateTime>();

        private string CreateSession(string username)
        {
            string sessionId = Guid.NewGuid().ToString();
            sessions[sessionId] = DateTime.Now.AddYears(10); // 10 year session!
            return sessionId;
        }

        // Additional event handlers for new UI elements
        private async void btnDatabaseSearch_Click(object sender, RoutedEventArgs e)
        {
            string searchTerm = txtSearchTerm.Text;
            UpdateStatus($"Searching databases for: {searchTerm}");

            try
            {
                // PostgreSQL injection
                var pgResults = await databaseService.SearchPostgreSQL(searchTerm);
                UpdateStatus($"PostgreSQL returned {pgResults.Count} results");
            }
            catch (Exception ex)
            {
                UpdateStatus($"Database search error: {ex.Message}");
            }
        }

        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            string plainText = txtPlainText.Text;
            string encrypted = EncryptDataAES(plainText);
            txtEncrypted.Text = $"Encrypted (ECB/Hardcoded key): {encrypted}";

            // Also test weak hashing
            string md5Hash = GetMD5Hash(plainText);
            string unsaltedHash = HashPasswordInsecure(plainText);
            UpdateStatus($"MD5: {md5Hash}, SHA256 (no salt): {unsaltedHash}");
        }

        private void btnBrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                txtSelectedFile.Text = openFileDialog.FileName;
                txtSelectedFile.Tag = openFileDialog.FileName;
            }
        }

        private void btnUploadFile_Click(object sender, RoutedEventArgs e)
        {
            if (txtSelectedFile.Tag != null)
            {
                string filePath = txtSelectedFile.Tag.ToString();
                byte[] fileData = File.ReadAllBytes(filePath);
                string fileName = Path.GetFileName(filePath);

                // Unrestricted file upload with auto-execution
                fileUploadService.UploadFile(fileData, fileName);
                UpdateStatus($"Uploaded file: {fileName} (unrestricted, may auto-execute)");
            }
        }

        private void btnDeleteUsers_Click(object sender, RoutedEventArgs e)
        {
            // Critical operation without authentication
            adminService.DeleteAllUsers();
            UpdateStatus("CRITICAL: Deleted all users without authentication!");
        }

        private void btnBackupDB_Click(object sender, RoutedEventArgs e)
        {
            // Backup without authentication
            string backupPath = @"C:\Temp\backup_" + DateTime.Now.Ticks + ".db";
            adminService.BackupDatabase(backupPath);
            UpdateStatus($"Database backed up to: {backupPath} (no auth required)");
        }

        private void btnAccessAdmin_Click(object sender, RoutedEventArgs e)
        {
            // Direct admin panel access
            string adminContent = adminService.GetAdminPanel();
            UpdateStatus($"Admin panel accessed without authentication. Content length: {adminContent.Length}");
        }

        private void btnClearStatus_Click(object sender, RoutedEventArgs e)
        {
            txtStatus.Clear();
        }

        private void UpdateStatus(string message)
        {
            if (txtStatus != null)
            {
                txtStatus.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                txtStatus.ScrollToEnd();
            }
        }
    }
}