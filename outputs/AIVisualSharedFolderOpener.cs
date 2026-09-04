using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class AIVisualSharedFolderOpener
{
    private const string SchemePrefix = "aivisual-folder:open?path64=";
    private const string SharedRoot = @"\\192.168.2.6\设计师文件";
    private const string InstalledFileName = "AIVisualSharedFolderOpener.exe";

    [STAThread]
    private static void Main(string[] args)
    {
        try
        {
            if (args.Length == 1
                && (args[0] == "--configure-browsers" || args[0] == "--configure-360"))
            {
                ConfigureBrowsersAfterExit();
                return;
            }

            if (args.Length == 1 && args[0].StartsWith(SchemePrefix, StringComparison.OrdinalIgnoreCase))
            {
                OpenSharedFolder(args[0].Substring(SchemePrefix.Length));
                return;
            }

            InstallForCurrentUser();
        }
        catch (Exception error)
        {
            MessageBox.Show(
                error.Message,
                "AI视觉中台",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }

    private static void InstallForCurrentUser()
    {
        string installDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AIVisualConsole");
        string installedPath = Path.Combine(installDirectory, InstalledFileName);
        string currentPath = Application.ExecutablePath;

        Directory.CreateDirectory(installDirectory);
        if (!string.Equals(currentPath, installedPath, StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(currentPath, installedPath, true);
        }

        using (RegistryKey protocol = Registry.CurrentUser.CreateSubKey(
            @"Software\Classes\aivisual-folder"))
        {
            protocol.SetValue("", "URL:AI视觉中台共享盘路径");
            protocol.SetValue("URL Protocol", "");
        }

        using (RegistryKey command = Registry.CurrentUser.CreateSubKey(
            @"Software\Classes\aivisual-folder\shell\open\command"))
        {
            command.SetValue("", "\"" + installedPath + "\" \"%1\"");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = installedPath,
            Arguments = "--configure-browsers",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });

        MessageBox.Show(
            "安装成功。请完全退出并重新打开一次正在使用的浏览器。支持 360 极速浏览器、Google Chrome 和 Microsoft Edge；之后点击将直接打开交付目录，不再询问。",
            "AI视觉中台",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private static void ConfigureBrowsersAfterExit()
    {
        string[] processNames = { "360chrome", "chrome", "msedge" };
        string[] userDataPaths =
        {
            @"360Chrome\Chrome\User Data",
            @"Google\Chrome\User Data",
            @"Microsoft\Edge\User Data"
        };
        bool[] completed = new bool[processNames.Length];
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        DateTime deadline = DateTime.UtcNow.AddHours(24);
        while (DateTime.UtcNow < deadline)
        {
            bool allCompleted = true;
            for (int index = 0; index < processNames.Length; index++)
            {
                if (completed[index])
                {
                    continue;
                }

                allCompleted = false;
                string userData = Path.Combine(localAppData, userDataPaths[index]);
                if (!Directory.Exists(userData))
                {
                    completed[index] = true;
                    continue;
                }

                if (Process.GetProcessesByName(processNames[index]).Length == 0)
                {
                    ConfigureBrowserProfiles(userData);
                    completed[index] = true;
                }
            }

            if (allCompleted)
            {
                return;
            }

            Thread.Sleep(2000);
        }
    }

    private static void ConfigureBrowserProfiles(string userData)
    {
        foreach (string profileDirectory in Directory.GetDirectories(userData))
        {
            string profileName = Path.GetFileName(profileDirectory);
            if (!string.Equals(profileName, "Default", StringComparison.OrdinalIgnoreCase)
                && !profileName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string preferencesPath = Path.Combine(profileDirectory, "Preferences");
            if (File.Exists(preferencesPath))
            {
                AllowProtocolForConsoleOrigins(preferencesPath);
            }
        }
    }

    internal static void AllowProtocolForConsoleOrigins(string preferencesPath)
    {
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;
        Dictionary<string, object> root = serializer.Deserialize<Dictionary<string, object>>(
            File.ReadAllText(preferencesPath, Encoding.UTF8));
        Dictionary<string, object> protocolHandler = GetOrCreateDictionary(root, "protocol_handler");
        Dictionary<string, object> allowedPairs = GetOrCreateDictionary(
            protocolHandler,
            "allowed_origin_protocol_pairs");

        foreach (string origin in new[]
        {
            "http://192.168.2.59:8080",
            "http://192.168.2.59:8081",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8081",
            "http://localhost:8080",
            "http://localhost:8081"
        })
        {
            Dictionary<string, object> protocols = GetOrCreateDictionary(allowedPairs, origin);
            protocols["aivisual-folder"] = true;
        }

        File.Copy(preferencesPath, preferencesPath + ".aivisual-backup", true);
        File.WriteAllText(preferencesPath, serializer.Serialize(root), new UTF8Encoding(false));
    }

    private static Dictionary<string, object> GetOrCreateDictionary(
        Dictionary<string, object> parent,
        string key)
    {
        object value;
        Dictionary<string, object> dictionary;
        if (parent.TryGetValue(key, out value)
            && (dictionary = value as Dictionary<string, object>) != null)
        {
            return dictionary;
        }

        dictionary = new Dictionary<string, object>();
        parent[key] = dictionary;
        return dictionary;
    }

    private static void OpenSharedFolder(string encodedPath)
    {
        string base64 = encodedPath.Replace('-', '+').Replace('_', '/');
        while (base64.Length % 4 != 0)
        {
            base64 += "=";
        }

        string decodedPath = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        string fullPath = Path.GetFullPath(decodedPath.Replace('/', '\\')).TrimEnd('\\');
        string root = SharedRoot.TrimEnd('\\');
        bool isRoot = string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase);
        bool isChild = fullPath.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
        if (!isRoot && !isChild)
        {
            throw new InvalidOperationException("该路径不在公司共享盘范围内。");
        }

        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException("共享盘路径不存在，或当前电脑没有访问权限。");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = fullPath,
            UseShellExecute = true
        });
    }
}
