using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Threading;
using System.Management;
using System.ServiceProcess;
using System.Linq;
using Microsoft.Win32;
using System.IO;

namespace TaskMgr
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            new Thread(LoadThread).Start();

            MessageBox.Show("Tip (not an error report!) :\nThis app needs 4.7.2 or higher version of .NET framework, if any unexpected error occurred, check your version of .NET, if it's too low, update .NET.", "Notice");
        }
        [DllImport("KERNEL32.DLL ")]
        public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processid);
        [DllImport("KERNEL32.DLL ")]
        public static extern int CloseHandle(IntPtr handle);
        [DllImport("KERNEL32.DLL ")]
        public static extern int Process32First(IntPtr handle, ref ProcessEntry32 pe);
        [DllImport("KERNEL32.DLL ")]
        public static extern int Process32Next(IntPtr handle, ref ProcessEntry32 pe);
        [DllImport("ntdll.dll")]
        private static extern uint NtSuspendProcess([In] IntPtr processHandle);
        [DllImport("ntdll.dll")]
        private static extern uint NtResumeProcess([In] IntPtr processHandle);
        [DllImport("KERNEL32.dll")]
        public static extern int OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);
        [DllImport("KERNEL32.dll", CharSet = CharSet.Ansi)]
        public static extern bool CreateProcess(StringBuilder lpApplicationName, StringBuilder lpCommandLine, SECURITY_ATTRIBUTES lpProcessAttributes, SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, StringBuilder lpEnvironment, StringBuilder lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
        [System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            public int nLength;
            public string lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public int lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public int wShowWindow;
            public int cbReserved2;
            public byte lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessEntry32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        };

        public class Proc
        {
            public string Name { get; set; }

            public uint PID { get; set; }

            public uint PPID { get; set; }
        }

        public class Serv
        {
            public string Name { get; set; }

            public string Status { get; set; }
        }

        public class Startup
        {
            public string Name { get; set; }

            public string Command { get; set; }

            public RegistryKey reg { get; set; }
        }

        private Proc pro;

        private Serv srv;

        private Startup su;

        private int selIndex = 0;
        static double GetProcessCPUUsage(int PID)
        {
            try
            {
                var proc = Process.GetProcessById(PID);
                var prevTime = proc.TotalProcessorTime;
                Thread.Sleep(1000);
                var curTime = proc.TotalProcessorTime;
                double Val = (double)(curTime - prevTime).TotalMilliseconds / (double)1000 / (double)Environment.ProcessorCount * 100;
                return Val;
            }
            catch
            {
                return 0;
            }
        }
        private static string GetProcessUserName(int PID)
        {
            string UserName = string.Empty;
            try {
                foreach (ManagementObject item in new ManagementObjectSearcher("Select * from Win32_Process WHERE processID=" + PID).Get())
                {
                    ManagementBaseObject inPar = null;
                    ManagementBaseObject outPar = null;
                    inPar = item.GetMethodParameters("GetOwner");
                    outPar = item.InvokeMethod("GetOwner", inPar, null);
                    UserName = Convert.ToString(outPar["User"]);
                    break;
                }
            }
            catch
            {
                UserName = "SYSTEM";
            }

            return UserName;
        }

        private static void GetStartUpsFromRegistry(RegistryKey key, String str, List<Startup> startups)
        {
            RegistryKey aimdir = key.OpenSubKey(str, true);

            string[] subvalueNames = aimdir.GetValueNames();

            foreach (string valueName in subvalueNames)
            {
                startups.Add(new Startup() { Name = valueName, Command = (string)aimdir.GetValue(valueName), reg = key });
            }

            string[] subkeyNames = aimdir.GetSubKeyNames();

            foreach (string keyName in subkeyNames)
            {
                GetStartUpsFromRegistry(aimdir, keyName, startups);
            }

            aimdir.Close();
        }

        /*private static void GetStartUpsFromFolder(DirectoryInfo di, List<Startup> startups)
        {
            FileInfo[] fis = di.GetFiles();
            for (int i = 0; i < fis.Length; i++)
            {
                startups.Add(new Startup() { Name = fis[i].FullName, Command = fis[i].FullName, reg = null });
            }
            DirectoryInfo[] dis = di.GetDirectories();
            for (int i = 0; i < dis.Length; i++)
            {
                GetStartUpsFromFolder(dis[i], startups);
            }
        }*/

        private void LoadThread()
        {
            while (true)
            {
                try
                {
                    Processes.Dispatcher.Invoke(LoadProcs);
                    Services.Dispatcher.Invoke(LoadServices);
                    Startups.Dispatcher.Invoke(LoadStartups);
                    Thread.Sleep(1000);
                } catch
                {
                    return;
                }
            }
        }

        private void LoadProcs()
        {
            IntPtr handle = CreateToolhelp32Snapshot(0x2, 0);
            List<Proc> items = new List<Proc>();
            if ((int)handle > 0)
            {
                ProcessEntry32 pe32 = new ProcessEntry32();
                pe32.dwSize = (uint)Marshal.SizeOf(pe32);
                int bMore = Process32First(handle, ref pe32);
                while (bMore == 1)
                {
                    IntPtr temp = Marshal.AllocHGlobal((int)pe32.dwSize);
                    Marshal.StructureToPtr(pe32, temp, true);
                    ProcessEntry32 pe = (ProcessEntry32)Marshal.PtrToStructure(temp, typeof(ProcessEntry32));
                    Marshal.FreeHGlobal(temp);
                    items.Add(new Proc() { Name = pe.szExeFile, PID = pe.th32ProcessID, PPID = pe.th32ParentProcessID });
                    bMore = Process32Next(handle, ref pe32);
                }
                selIndex = Processes.SelectedIndex;
                Processes.ItemsSource = items;
                Processes.SelectedIndex = selIndex;
                CloseHandle(handle);
            }
        }

        private void LoadServices()
        {
            ServiceController[] serviceList = ServiceController.GetServices();
            serviceList = serviceList.OrderBy(m => m.DisplayName).ToArray();
            List<Serv> items = new List<Serv>();
            foreach (ServiceController sc in serviceList)
            {
                items.Add(new Serv() { Name = sc.ServiceName, Status = sc.Status.ToString() });
            }
            selIndex = Services.SelectedIndex;
            Services.ItemsSource = items;
            Services.SelectedIndex = selIndex;
        }

        private void LoadStartups()
        {
            List<Startup> SUs = new List<Startup>();
            GetStartUpsFromRegistry(Registry.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", SUs);
            GetStartUpsFromRegistry(Registry.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", SUs);
            /*string strStartup = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            strStartup += "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
            DirectoryInfo di = new DirectoryInfo(strStartup);
            GetStartUpsFromFolder(di, SUs);*/
            selIndex = Startups.SelectedIndex;
            Startups.ItemsSource = SUs;
            Startups.SelectedIndex = selIndex;
        }

        private void Processes_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            pro = Processes.SelectedItem as Proc;
        }

        private void Services_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            srv = Services.SelectedItem as Serv;
        }

        private void Startups_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            su = Startups.SelectedItem as Startup;
        }

        private void MoreInfo_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                MessageBox.Show("CPU Usage:" + GetProcessCPUUsage((int)pro.PID).ToString() + "%\nUser Name:" + GetProcessUserName((int)pro.PID), "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        private void Kill_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                var proc = Process.GetProcessById((int)pro.PID);
                proc.Kill();
            }
        }

        private void Suspend_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                IntPtr hProc = (IntPtr)OpenProcess(0x1F0FFF, false, (int)pro.PID);
                NtSuspendProcess(hProc);
            }
        }

        private void Resume_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                IntPtr hProc = (IntPtr)OpenProcess(0x1F0FFF, false, (int)pro.PID);
                NtResumeProcess(hProc);
            }
        }

        private void sCritical_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                IntPtr hProc = (IntPtr)OpenProcess(0x1F0FFF, false, (int)pro.PID);
                int isCritical = 1;
                Process.EnterDebugMode();
                if (hProc != null)
                {
                    NtSetInformationProcess(hProc, 0x1D, ref isCritical, sizeof(int));
                }
            }
        }

        private void cCritical_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                IntPtr hProc = (IntPtr)OpenProcess(0x1F0FFF, false, (int)pro.PID);
                int isCritical = 0;
                Process.EnterDebugMode();
                if (hProc != null)
                {
                    NtSetInformationProcess(hProc, 0x1D, ref isCritical, sizeof(int));
                }
            }
        }

        private void Location_Click(object sender, RoutedEventArgs e)
        {
            if (pro != null && pro is Proc)
            {
                try
                {
                    var proc = Process.GetProcessById((int)pro.PID);
                    if (proc != null)
                    {
                        Process process = new Process();
                        process.StartInfo.FileName = "explorer.exe";
                        process.StartInfo.Arguments = "/select,\"" + proc.MainModule.FileName + "\"";
                        process.Start();
                    }
                } catch {
                    return;
                }
            }
        }

        private void Start_Click(object sender, RoutedEventArgs e)
        {
            if (srv != null && srv is Serv)
            {
                try
                {
                    string serviceName = srv.Name;
                    ServiceController sc = new ServiceController(serviceName);
                    if ((sc.Status.Equals(ServiceControllerStatus.Stopped)) || (sc.Status.Equals(ServiceControllerStatus.StopPending)))
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running);
                        sc.Refresh();
                    }
                }
                catch
                {
                    return;
                }
            }
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            if (srv != null && srv is Serv)
            {
                try
                {
                    string serviceName = srv.Name;
                    ServiceController sc = new ServiceController(serviceName);
                    if (sc.Status.Equals(ServiceControllerStatus.Running))
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped);
                        sc.Refresh();
                    }
                }
                catch
                {
                    return;
                }
            }
        }

        private void Restart_Click(object sender, RoutedEventArgs e)
        {
            if (srv != null && srv is Serv)
            {
                try
                {
                    string serviceName = srv.Name;
                    ServiceController sc = new ServiceController(serviceName);
                    if (sc.Status.Equals(ServiceControllerStatus.Running))
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped);
                        sc.Refresh();
                    }
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                    sc.Refresh();

                }
                catch
                {
                    return;
                }
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (su != null && su is Startup)
            {
                RegistryKey key = su.reg.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
                if (key != null)
                {
                    key.DeleteValue(su.Name);
                }
                key.Close();
            }
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.OpenFileDialog dialog = new System.Windows.Forms.OpenFileDialog();
            dialog.Multiselect = false;
            dialog.Title = "Select File";
            dialog.Filter = "All Files(*.*)|*.*";
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                filename.Text = dialog.FileName;
            }
        }

        private void Run_Click(object sender, RoutedEventArgs e)
        {
            STARTUPINFO sInfo = new STARTUPINFO();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            CreateProcess(null, new StringBuilder(filename.Text), null, null, false, 0, null, null, ref sInfo, ref pInfo);
        }

        private void EasterEgg(object sender, RoutedEventArgs e)
        {
            LinearGradientBrush brush = new LinearGradientBrush();
            Random r = new Random(Guid.NewGuid().GetHashCode());
            int val = r.Next(0, 100);
            double _val = (double)val / 100;
            brush.GradientStops.Add(new GradientStop(Colors.LightBlue, _val));
            brush.GradientStops.Add(new GradientStop(Colors.LightGoldenrodYellow, 1 - _val));
            brush.GradientStops.Add(new GradientStop(Colors.Azure, _val / 2));
            About.Background = brush;
        }
    }
}
