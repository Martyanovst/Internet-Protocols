using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace asTracer
{
    public static class Program
    {
        private const string WhoisServer = "whois.ripe.net";
        private static readonly Regex AsPattern = new Regex(@"origin: \s+(AS\d+)", RegexOptions.Compiled);
        private static readonly Regex CountryPattern = new Regex(@"country: \s+(\w+)", RegexOptions.Compiled);
        private static readonly Regex HolderPattern = new Regex(@"descr: \s+(.+)\n", RegexOptions.Compiled);


        public static void Main(string[] args)
        {
            var ipOrDomen = args[0];
            var ips = TraceRoute(ipOrDomen);
            foreach (var address in ips)
                Console.WriteLine(GetWhoisInformation(WhoisServer, address));
        }

        private static IEnumerable<IPAddress> TraceRoute(string address)
        {
            var result = new List<IPAddress>();
            var options = new PingOptions(1, false);
            var emptyBuffer = new byte[1024];

            try
            {
                using (var pinger = new Ping())
                {
                    var ping = pinger.Send(address, 120, emptyBuffer, options);

                    while (ping?.Status != IPStatus.Success)
                    {
                        options.Ttl++;
                        ping = pinger.Send(address, 120, emptyBuffer, options);
                        if (ping?.Address != null)
                            result.Add(ping.Address);
                    }
                }
            }
            catch
            {
                Console.WriteLine("Sorry, something goes wrong, Please try again.");
            }

            return result;
        }

        private static string GetWhoisInformation(string whoisServer, IPAddress url)
        {
            var builder = new StringBuilder();
            try
            {
                using (var tcpClinetWhois = new TcpClient(whoisServer, 43))
                {
                    using (var networkStreamWhois = tcpClinetWhois.GetStream())
                    {
                        using (var bufferedStreamWhois = new BufferedStream(networkStreamWhois))
                        {
                            using (var streamWriter = new StreamWriter(bufferedStreamWhois))
                            {
                                streamWriter.WriteLine($"-a {url}");
                                streamWriter.Flush();
                                var streamReaderReceive = new StreamReader(bufferedStreamWhois);
                                while (!streamReaderReceive.EndOfStream)
                                    builder.AppendLine(streamReaderReceive.ReadLine());
                            }
                        }
                    }
                }
            }
            catch
            {
                return "Failed.";
            }

            var data = builder.ToString();
            builder.Clear();

            var asn = AsPattern.Match(data).Groups[1].Value;
            var country = CountryPattern.Match(data).Groups[1].Value;
            var holder = HolderPattern.Match(data).Groups[1].Value;

            builder.Append(url + "---");
            builder.Append(string.IsNullOrEmpty(asn) ? "* * *" : asn);
            builder.Append("---");
            builder.Append(country + "---" + holder);

            return builder.ToString();
        }
    }
}