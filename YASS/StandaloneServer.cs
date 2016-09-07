// YASS - Yet another Shadowsocks
// Copyright (C) 2016 dantmnf
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using NDesk.Options;
using log4net;
using log4net.Core;
using Newtonsoft.Json.Linq;
using YASS.AlgorithmProvider;

[assembly: log4net.Config.XmlConfigurator(Watch = true)]

namespace YASS
{
    class StandaloneServer
    {
        class ServerConfiguration
        {
            public IPAddress ListenAddress;
            public int ListenPort;
            public string CipherName;
            public string Password;
            public int Timeout;
            public TcpRelayServer.ServerHmacPolicy HmacPolicy;
            public bool UdpServer;

            public static ServerConfiguration ReadFromJObject(JObject config)
            {
                //let 0.0.0.0 or ::0 worked
                IPAddress ip = null;
                if(config["server"].ToString() == "0.0.0.0" && config["server"].ToString() != "::0")
                    ip = IPAddress.Any;
                else if(config["server"].ToString() == "::0")
                    ip = IPAddress.IPv6Any;
                else
                    ip = Dns.GetHostAddresses(config["server"].ToString())[0];
                var result = new ServerConfiguration
                {
                    ListenAddress = ip,
                    ListenPort = int.Parse(config["server_port"].ToString()),
                    Password = config["password"].ToString(),
                    CipherName = config["method"].ToString(),
                    Timeout = int.Parse(config["timeout"].ToString()),
                    HmacPolicy = config["auth"].ToObject<bool>() ?
                        TcpRelayServer.ServerHmacPolicy.Mandatory :
                        TcpRelayServer.ServerHmacPolicy.OptIn,
                    UdpServer = config["udp"].ToObject<bool>(),
                };
                return result;
            }

            public static ServerConfiguration ReadFromJsonFile(string filename)
            {
                return ReadFromJObject(JObject.Parse(File.ReadAllText(filename)));
            }

            public static ServerConfiguration ReadFromAppSettings()
            {
                var result = new ServerConfiguration
                {
                    ListenAddress = Dns.GetHostAddresses(Properties.Settings.Default.ServerAddress)[0],
                    ListenPort = Properties.Settings.Default.ServerPort,
                    Password = Properties.Settings.Default.Password,
                    CipherName = Properties.Settings.Default.Cipher,
                    Timeout = Properties.Settings.Default.Timeout,
                    HmacPolicy = Properties.Settings.Default.MandatoryHmac ?
                        TcpRelayServer.ServerHmacPolicy.Mandatory :
                        TcpRelayServer.ServerHmacPolicy.OptIn,
                    UdpServer = Properties.Settings.Default.UdpServer,
                };
                
                return result;
            }

        }

        private static readonly ILog logger = LogManager.GetLogger("StandaloneServer");

        public static void Main(string[] args)
        {
            string configFile = null;
            var printHelp = false;
            var optionParser = new OptionSet()
            {
                {"c|config=", s => configFile = s },
                {"v|loglevel=", ChangeLogLevel },
                {"h|help", _ => printHelp = true }
            };
            optionParser.Parse(args);
            if (printHelp)
            {
                var file = typeof(StandaloneServer).Assembly.Location;
                var argv0 = Path.GetFileNameWithoutExtension(file);
                Console.WriteLine("Usage: {0} [paramters]", argv0);
                Console.WriteLine("  -c, --config=file       read configuration from file instead of AppSettings");
                Console.WriteLine("  -v, --loglevel=LEVEL    set loglevel to LEVEL (ALL, DEBUG, INFO, WARN, ERROR, FATAL)");
                Console.WriteLine("  -h, --help              print this message");
                return;
            }
            try
            {
                var config = configFile != null
                    ? ServerConfiguration.ReadFromJsonFile(configFile)
                    : ServerConfiguration.ReadFromAppSettings();
                var provider = MultiAlgorithmProvider.FindAndCreate();
                var tcpRelayServer = new TcpRelayServer(config.ListenAddress, config.ListenPort, config.CipherName,
                    Encoding.UTF8.GetBytes(config.Password), config.Timeout)
                {
                    AlgorithmProvider = provider,
                    HmacPolicy = config.HmacPolicy,
                };
                var udpRelayServer = new UdpRelayServer(config.ListenAddress, config.ListenPort, config.CipherName,
                    Encoding.UTF8.GetBytes(config.Password))
                {
                    AlgorithmProvider = provider
                };
                bool stopping = false;
                Console.CancelKeyPress += (sender, e) =>
                {
                    if (!stopping)
                        tcpRelayServer.StopListening();
                    else
                        tcpRelayServer.KillAllClients();
                    e.Cancel = true;
                    stopping = true;
                };

                var tcpServerTask = tcpRelayServer.StartListeningAsync();
                var udpServerTask = udpRelayServer.StartServerAsync();
                // tcpServerTask.Wait();
                Task.WaitAny(tcpServerTask, udpServerTask);
                tcpServerTask = tcpRelayServer.WaitForAllClients();
                logger.Info("press Ctrl-C again to force stop");
                tcpServerTask.Wait();
                udpRelayServer.StopServer();
            }
            catch (Exception e)
            {
                logger.Fatal(e);
                Environment.Exit(1);
            }

        }


        private static void ChangeLogLevel(string level)
        {
            level = level.ToUpper();
            var newLevel = Level.All;
            switch (level)
            {
                case "ALL":
                    break;
                case "DEBUG":
                    newLevel = Level.Debug;
                    break;
                case "INFO":
                    newLevel = Level.Info;
                    break;
                case "WARN":
                    newLevel = Level.Warn;
                    break;
                case "ERROR":
                    newLevel = Level.Error;
                    break;
                case "FATAL":
                    newLevel = Level.Fatal;
                    break;
                default:
                    logger.Warn("invalid loglevel, setting loglevel to ALL.");
                    break;
            }

            ((log4net.Repository.Hierarchy.Hierarchy)LogManager.GetRepository()).Root.Level = newLevel;
            ((log4net.Repository.Hierarchy.Hierarchy)LogManager.GetRepository()).RaiseConfigurationChanged(EventArgs.Empty);
        }

    }
}
