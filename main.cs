using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Net.Security;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Text;
using System.Threading;

namespace SimpleAntivirus
{
    public partial class AntivirusForm : Form
    {
        private List<string> virusSignatures = new List<string>
        {
            "malware", "trojan", "ransom", "exploit", "payload",
            "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
            "certutil -decode", "powershell -enc", "rundll32 javascript",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        };

        private readonly Dictionary<string, byte[][]> fileTypeSignatures = new Dictionary<string, byte[][]>
        {
            { ".exe", new byte[][] { new byte[] { 0x4D, 0x5A }, new byte[] { 0x50, 0x45, 0x00, 0x00 } }},
            { ".dll", new byte[][] { new byte[] { 0x4D, 0x5A }, new byte[] { 0x50, 0x45, 0x00, 0x00 } }},
            { ".sys", new byte[][] { new byte[] { 0x4D, 0x5A }, new byte[] { 0x50, 0x45, 0x00, 0x00 } }}
        };

        private readonly HashSet<string> trustedPublishers = new HashSet<string>
        {
            "Microsoft Windows", "Microsoft Corporation", "Google LLC", 
            "Adobe Inc.", "Mozilla Corporation"
        };

        private NotifyIcon notifyIcon;
        private Panel mainPanel;
        private Button btnSelectFile;
        private Button btnScan;
        private Button btnScanDisk;
        private RichTextBox txtResult;
        private System.Windows.Forms.Timer animationTimer;

        private class ScanResult
        {
            public bool IsSafe { get; set; } = true;
            public List<string> Reasons { get; set; } = new List<string>();
            public List<string> TechnicalDetails { get; set; } = new List<string>();
        }

        public AntivirusForm()
        {
            InitializeComponent();
            SetupSecurityWarnings();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();

            
            this.Text = "32 bit - File scanner";
            this.Size = new Size(800, 600);
            this.MinimumSize = new Size(500, 300);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.White;
            this.Resize += Form_Resize;

            mainPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(240, 245, 255),
                Padding = new Padding(20)
            };
            mainPanel.Paint += MainPanel_Paint;

            var buttonPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 50,
                AutoSize = true,
                Padding = new Padding(0),
                Margin = new Padding(0)
            };

            btnSelectFile = CreateButton("Выбрать файл", BtnSelectFile_Click);
            btnScan = CreateButton("Сканировать файл", BtnScan_Click);
            btnScanDisk = CreateButton("Сканировать диск", BtnScanDisk_Click);

            txtResult = new RichTextBox
            {
                Multiline = true,
                Dock = DockStyle.Fill,
                ReadOnly = true,
                ScrollBars = RichTextBoxScrollBars.ForcedVertical,
                Font = new Font("Segoe UI", 9F),
                BackColor = Color.White,
                BorderStyle = BorderStyle.None,
                Margin = new Padding(0, 10, 0, 0),
                DetectUrls = true
            };

            buttonPanel.Controls.AddRange(new[] { btnSelectFile, btnScan, btnScanDisk });
            mainPanel.Controls.Add(txtResult);
            mainPanel.Controls.Add(buttonPanel);
            this.Controls.Add(mainPanel);

            notifyIcon = new NotifyIcon
            {
                Visible = true,
                Icon = SystemIcons.Shield
            };

            animationTimer = new System.Windows.Forms.Timer { Interval = 50 };
            animationTimer.Tick += AnimationTimer_Tick;

            this.ResumeLayout(false);
        }

        private Button CreateButton(string text, EventHandler handler)
        {
            var btn = new Button
            {
                Text = text,
                Size = new Size(150, 40),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(51, 122, 183),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10F),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 10, 0),
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.Click += handler;
            btn.MouseEnter += Button_MouseEnter;
            btn.MouseLeave += Button_MouseLeave;
            return btn;
        }

        private void MainPanel_Paint(object sender, PaintEventArgs e)
        {
            using (var brush = new LinearGradientBrush(
                mainPanel.ClientRectangle,
                Color.FromArgb(240, 245, 255),
                Color.FromArgb(230, 235, 250),
                LinearGradientMode.Vertical))
            {
                e.Graphics.FillRectangle(brush, mainPanel.ClientRectangle);
            }
        }

        private void SetupSecurityWarnings()
        {
            ServicePointManager.ServerCertificateValidationCallback += ValidateServerCertificate;
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, 
            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                string url = (sender as HttpWebRequest)?.RequestUri.ToString() ?? "Неизвестный URL";
                ShowNotification("Предупреждение безопасности", 
                    $"Небезопасное соединение: {url}", ToolTipIcon.Warning);
                return false;
            }
            return true;
        }

        private void ShowNotification(string title, string message, ToolTipIcon icon)
        {
            notifyIcon.ShowBalloonTip(3000, title, message, icon);
        }

        private void BtnSelectFile_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Все файлы (*.*)|*.*";
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    txtResult.Text = $"Выбран файл: {openFileDialog.FileName}";
                    txtResult.Tag = openFileDialog.FileName;
                }
            }
        }

        private void Form_Resize(object sender, EventArgs e)
        {
            this.Refresh();
        }

        private void AnimationTimer_Tick(object sender, EventArgs e)
        {
        }

        private void Button_MouseEnter(object sender, EventArgs e)
        {
            var btn = (Button)sender;
            btn.BackColor = Color.FromArgb(40, 96, 144);
        }

        private void Button_MouseLeave(object sender, EventArgs e)
        {
            var btn = (Button)sender;
            btn.BackColor = Color.FromArgb(51, 122, 183);
        }

        private bool ScanFile(string filePath, bool isDiskScan = false)
        {
            var result = new ScanResult();
            try
            {
                var fileInfo = new FileInfo(filePath);
                result.TechnicalDetails.Add($"Размер: {fileInfo.Length / 1024} KB");
                result.TechnicalDetails.Add($"Создан: {fileInfo.CreationTime:dd.MM.yyyy HH:mm}");
                result.TechnicalDetails.Add($"Изменен: {fileInfo.LastWriteTime:dd.MM.yyyy HH:mm}");

                string extension = Path.GetExtension(filePath).ToLower();
                string[] riskyExtensions = { ".exe", ".dll", ".bat", ".ps1", ".js", ".vbs" };

                if (riskyExtensions.Contains(extension))
                {
                    if (CheckDigitalSignature(fileInfo, result))
                        return true;

                    if (CheckFileContent(filePath, extension, result))
                        return false;

                    if (CheckEntropy(fileInfo, result))
                        return false;
                }

                return result.IsSafe;
            }
            finally
            {
                if (!result.IsSafe)
                    ShowScanResult(filePath, result);
            }
        }

        private bool CheckDigitalSignature(FileInfo fileInfo, ScanResult result)
        {
            try
            {
                var cert = new X509Certificate2(fileInfo.FullName);
                if (cert.Verify() && trustedPublishers.Any(p => cert.Subject.Contains(p)))
                {
                    result.TechnicalDetails.Add($"Цифровая подпись: {cert.Subject}");
                    return true;
                }
            }
            catch
            {
                result.TechnicalDetails.Add("Цифровая подпись: отсутствует или недействительна");
            }
            return false;
        }

        private bool CheckFileContent(string filePath, string extension, ScanResult result)
        {
            if (new[] { ".bat", ".ps1", ".js", ".vbs" }.Contains(extension))
            {
                string content = File.ReadAllText(filePath);
                foreach (var signature in virusSignatures.Where(s => content.Contains(s)))
                {
                    result.Reasons.Add($"Обнаружена вредоносная команда: {signature}");
                    result.Reasons.Add($"Контекст: {GetSignatureContext(content, signature)}");
                    result.IsSafe = false;
                }
            }
            return !result.IsSafe;
        }

        private string GetSignatureContext(string content, string signature)
        {
            int index = content.IndexOf(signature);
            int start = Math.Max(0, index - 50);
            int end = Math.Min(content.Length, index + signature.Length + 50);
            return content.Substring(start, end - start).Replace("\n", " ");
        }

        private bool CheckEntropy(FileInfo fileInfo, ScanResult result)
        {
            if (fileInfo.Length > 1024 * 1024)
            {
                byte[] data = File.ReadAllBytes(fileInfo.FullName);
                double entropy = CalculateEntropy(data);
                if (entropy > 7.8)
                {
                    result.Reasons.Add($"Высокая энтропия ({entropy:F2}): файл может быть зашифрован или упакован");
                    result.IsSafe = false;
                }
            }
            return !result.IsSafe;
        }

        private double CalculateEntropy(byte[] data)
        {
            var frequencies = new int[256];
            foreach (byte b in data) frequencies[b]++;

            double entropy = 0;
            foreach (int freq in frequencies.Where(f => f > 0))
            {
                double probability = (double)freq / data.Length;
                entropy -= probability * Math.Log(probability, 2);
            }
            return entropy;
        }

        private void ShowScanResult(string filePath, ScanResult result)
        {
            this.Invoke((MethodInvoker)delegate
            {
                AppendResult($"\n🔍 Файл: {filePath}", Color.Blue);
                AppendResult("\n⚠️ Обнаружены проблемы:", Color.Red);
                
                foreach (var reason in result.Reasons)
                    AppendResult($"\n   • {reason}", Color.DarkRed);
                
                AppendResult("\n🔧 Технические детали:", Color.Gray);
                foreach (var detail in result.TechnicalDetails)
                    AppendResult($"\n   • {detail}", Color.DarkGray);
                
                AppendResult("\n" + new string('═', 80) + "\n", Color.Silver);
            });
        }

        private void AppendResult(string text, Color color)
        {
            txtResult.SelectionStart = txtResult.TextLength;
            txtResult.SelectionColor = color;
            txtResult.AppendText(text);
            txtResult.ScrollToCaret();
        }

        private void BtnScan_Click(object sender, EventArgs e)
        {
            if (txtResult.Tag is string filePath)
            {
                bool isSafe = ScanFile(filePath);
                AppendResult(isSafe ? "\n✅ Файл безопасен\n" : "\n⛔ Файл содержит угрозы!\n", 
                    isSafe ? Color.Green : Color.Red);
            }
        }

        private void BtnScanDisk_Click(object sender, EventArgs e)
        {
            using (var folderDialog = new FolderBrowserDialog())
            {
                if (folderDialog.ShowDialog() == DialogResult.OK)
                {
                    new Thread(() => ScanDirectory(folderDialog.SelectedPath)).Start();
                }
            }
        }

        private void ScanDirectory(string path)
        {
            try
            {
                foreach (string file in Directory.GetFiles(path))
                {
                    try { ScanFile(file, true); }
                    catch { /* Игнорируем ошибки доступа */ }
                }
                foreach (string dir in Directory.GetDirectories(path))
                {
                    ScanDirectory(dir);
                }
            }
            catch { /* Игнорируем ошибки доступа */ }
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new AntivirusForm());
        }
    }
}