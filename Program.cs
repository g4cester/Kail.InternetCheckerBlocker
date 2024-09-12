using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using tik4net;

namespace Kail.InternetCheckerBlocker
{
    internal class Program
    {
        private static TimeSpan onlineTime = TimeSpan.Zero;
        private static bool isBlocked = false;
        private const string monitoredIp = "192.168.8.78";
        private const string routerIp = "192.168.8.1";
        private const string mikrotikUsername = "admin";
        private const string mikrotikPassword = "passi";
        private static string httpBlockPage = "<html><body><h1>Internet Zablokowany</h1></body></html>";
        public static async Task Main(string[] args)
        {
            // Start HTTP server
            Task.Run(() => StartHttpServer());

            while (true)
            {
                if (await IsHostOnline(monitoredIp))
                {
                    onlineTime += TimeSpan.FromMinutes(1);
                    Console.WriteLine($"Host {monitoredIp} online for {onlineTime.TotalHours} hours.");
                }

                if (onlineTime.TotalMinutes >= 2 && !isBlocked)
                {
                    BlockInternet();
                    isBlocked = true;
                }

                if (DateTime.Now.Hour == 0 && DateTime.Now.Minute == 0)
                {
                    UnblockInternet();
                    isBlocked = false;
                    onlineTime = TimeSpan.Zero;
                }

                await Task.Delay(TimeSpan.FromMinutes(1));
            }
        }

        private static async Task<bool> IsHostOnline(string ipAddress)
        {
            Ping ping = new Ping();
            try
            {
                PingReply reply = await ping.SendPingAsync(ipAddress, 1000);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        private static void BlockInternet()
        {
            using (var tikConnection = ConnectionFactory.OpenConnection(TikConnectionType.Api, routerIp, mikrotikUsername, mikrotikPassword))
            {
                // 1. Block all internet access for the monitored IP
                tikConnection.CreateCommandAndParameters("/ip/firewall/filter/add",
                    "chain", "forward",
                    "src-address", monitoredIp,
                    "action", "drop",
                    "comment", "Block internet for " + monitoredIp).ExecuteNonQuery();

                // 2. Redirect HTTP traffic to our local HTTP server (port 8085)
                tikConnection.CreateCommandAndParameters("/ip/firewall/nat/add",
                    "chain", "dstnat",
                    "protocol", "tcp",
                    "dst-port", "80",
                    "src-address", monitoredIp,
                    "action", "dst-nat",
                    "to-addresses", "192.168.8.40",  // Local address of the machine running the HTTP server
                    "to-ports", "8085",
                    "comment", "Redirect HTTP traffic to block page").ExecuteNonQuery();
            }
            Console.WriteLine($"Blocked internet access and redirected HTTP for {monitoredIp}");
        }

        private static void UnblockInternet()
        {
            using (var tikConnection = ConnectionFactory.OpenConnection(TikConnectionType.Api, routerIp, mikrotikUsername, mikrotikPassword))
            {
                // Remove blocking rule
                tikConnection.CreateCommandAndParameters("/ip/firewall/filter/remove",
                    "where", "comment=Block internet for " + monitoredIp).ExecuteNonQuery();

                // Remove NAT redirect rule
                tikConnection.CreateCommandAndParameters("/ip/firewall/nat/remove",
                    "where", "comment=Redirect HTTP traffic to block page").ExecuteNonQuery();
            }
            Console.WriteLine($"Unblocked internet access for {monitoredIp}");
        }

        private static void StartHttpServer()
        {
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://*:8085/"); // Listen on all network interfaces
            try
            {
                listener.Start();
                Console.WriteLine("HTTP server started on port 8085.");
            }
            catch (HttpListenerException ex)
            {
                Console.WriteLine("Failed to start HTTP server: " + ex.Message);
                return;
            }

            while (true)
            {
                var context = listener.GetContext();
                var response = context.Response;
                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(httpBlockPage);
                response.ContentLength64 = buffer.Length;
                var output = response.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
        }
    }
}
