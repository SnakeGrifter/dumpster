using System;
using System.Collections.Generic;
using SharpPcap;
using Discord;
using Discord.Commands;
using Discord.WebSocket;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using tutBot;
using System.Threading;


namespace Example6
{
    public class Pong : ModuleBase<SocketCommandContext>
    {
        [Command("pong")]
        public async Task PongAsync()
        {
            var embed2 = new EmbedBuilder();

            embed2.WithUrl("https://www.reddit.com/r/bladeandsoul/comments/bjftg7/may_1st_eu_after_maintenance/?ref=share&ref_source=link");
            embed2.WithColor(255, 0, 0);
                
            Context.Guild.GetTextChannel(573201658654359562).SendMessageAsync("", false, embed2.Build());

        }
    }
    public class Ping : ModuleBase<SocketCommandContext>
    {
        [Command("ping")]
        public async Task PingAsync()
        {
            void twerk1()
            {
                string ver = SharpPcap.Version.VersionString;
                // Print SharpPcap version 
                Console.WriteLine("SharpPcap {0}, Example6.DumpTCP.cs", ver);
                Console.WriteLine();

                // Retrieve the device list 
                var devices = CaptureDeviceList.Instance;

                //If no device exists, print error 
                if (devices.Count < 1)
                {
                    Console.WriteLine("No device found on this machine");
                    return;
                }

                Console.WriteLine("The following devices are available on this machine:");
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine();

                int i = 0;

                // Scan the list printing every entry 
                foreach (var dev in devices)
                {
                    // Description 
                    Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                    i++;
                }

                Console.WriteLine();
                Console.Write("-- Please choose a device to capture: ");
                //i = int.Parse(Console.ReadLine());

                var device = devices[0];

                //Register our handler function to the 'packet arrival' event
                device.OnPacketArrival +=
                    new PacketArrivalEventHandler(device_OnPacketArrival);
                
                // Open the device for capturing
                int readTimeoutMilliseconds = 100;
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                //tcpdump filter to capture only TCP/IP packets
                string filter = "src net 52.28.190.106 ||" + // chat
                               " src net 64.25.44.111 ||" + // not much
                               " src net 52.29.102.201 ||" + // not much
                               " src net 172.217.22.174 ||" + // -
                               " src net 163.171.134.108 ||" + // port 80 stuff
                               " src net 54.201.245.188 ||" + // -
                               " src net 216.58.211.142 ||" + // -
                               " src net 64.25.35.63 ||" + // -
                               " src net 54.186.116.112 ||" + // -
                               " src net 52.57.232.129 ||" + // -
                               " src net 18.194.180.254 ||" + // open world lots of activity
                               " src net 64.25.44.10 ||" + // -
                               " src net 18.197.30.128 ||" + // -
                               " src net 52.28.213.12 ||" + // -
                               " src net 54.203.23.54 ||" + // -
                               " src net 35.158.170.41 ||" + // instance activity
                               " src net 64.25.35.30 ||" + // launcher has it
                               " src net 18.196.86.52"; // launcher has it
                device.Filter = filter;

                Console.WriteLine();
                Console.WriteLine
                    ("-- The following tcpdump filter will be applied: \"{0}\"",
                    filter);
                Console.WriteLine
                    ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                    device.Description);
                // Start capture 'INFINTE' number of packets
                device.Capture();
                // Close the pcap device
                // (Note: this line will never be called since
                //  we're capturing infinite number of packets
                device.Close();
            }
            
            Thread thread1 = new Thread(twerk1);
            thread1.Start();

            //await Context.Channel.SendMessageAsync("testoc");
        }
        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            int lim = 0;
            //var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                /*if (srcIp.ToString() == "35.158.170.41")
                {
                    for (int x = 0; x < len; x++)
                    {
                        if ((char)(e.Packet.Data[x]) >= 32 && (char)(e.Packet.Data[x]) <= 126)
                        {
                            if ((char)(e.Packet.Data[x]) == '\a' || (char)(e.Packet.Data[x]) == '\b' || (char)(e.Packet.Data[x]) == '\f' || (char)(e.Packet.Data[x]) == '\n' || (char)(e.Packet.Data[x]) == '\r' || (char)(e.Packet.Data[x]) == '\t' || (char)(e.Packet.Data[x]) == '\v')
                                Console.Write(".");
                            else
                                Console.Write((char)(e.Packet.Data[x]));
                        }
                    }
                    Console.WriteLine("\n");
                }*/

                //Console.WriteLine("{0}:{1}:{2},{3} Len={4} {5}:{6} -> {7}:{8}", 
                //time.Hour, time.Minute, time.Second, time.Millisecond, len,
                //"52.28.190.106", srcPort, dstIp, dstPort);

                if (len > 80 && srcIp.ToString() == "52.28.190.106")
                {
                    string aString = Encoding.BigEndianUnicode.GetString(e.Packet.Data, 80, len - 80);

                    string bString = Encoding.BigEndianUnicode.GetString(e.Packet.Data, 80, len - 80);
                    lim = bString.IndexOf("@");
                    if (lim > -1)
                    {
                        if (26 + lim < bString.Length)
                        {
                            aString = bString.Remove(0, 22 + lim);
                            bString = bString.Remove(0, 26 + lim);
                        }
                    }
                    lim = bString.IndexOf(":");

                    if ((aString[2] == '8' || aString[2] == '0') && lim > -1 && (bString.IndexOf("<?xml") < 0 && bString.IndexOf("<marking mapId") < 0 && bString.IndexOf("<drawing mapId") < 0))
                    {
                        bString = bString.Replace("\ufffd", " ");
                        bString = bString.Replace("&apos;", "'");
                        bString = bString.Replace("<link id='boss-challenge:Night_windplain_score'/>", "**MSP**");

                        bString = bString.Replace("<link id='dungeon:Dungeon_CheonMyungHatchery'/>", "**Brood Chamber**");
                        bString = bString.Replace("<link id='dungeon:Dungeon_ChunMyungJiWii'/>", "**Heaven's Mandate**");
                        bString = bString.Replace("<link id='dungeon:Dungeon_DongHae_chungkak_B_mini_50lv'/>", "**Cold Storage**");

                        bString = bString.Replace("<link id='raid-dungeon:raid_SecretRoom'/>", "**Snowjade Fortress**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_InfinityChamberRaid'/>", "**Fallen Aransu School**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_PaCheonSeongDo'/>", "**Skybreak Spire**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_NaryuAnnex_02'/>", "**Hall of the Templar**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_NaryuAnnex_01'/>", "**Hall of the Keeper**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_VortexTemple'/>", "**Temple of Eluvum**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_PaCheonSeonDo_Lite'/>", "**Dawn of Khanda Vihar**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_JeokpaewangRaid'/>", "**Scion's Keep**");
                        bString = bString.Replace("<link id='raid-dungeon:raid_NaryuTomb'/>", "**Nightfall Sanctuary**");

                        bString = bString.Replace("<guild-member-area geo-zone='77'/>", "Entering **Ring of Reckoning**");

                        bString = bString.Replace("<guild-member-area geo-zone='956'/>", "Entering **Burning Mausoleum Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='955'/>", "Entering **Desolate Masoleum Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='952'/>", "Entering **Brood Chamber Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='951'/>", "Entering **Dreamsong Theater Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='950'/>", "Entering **The Shadowmoor Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='948'/>", "Entering **Sandstorm Temple Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='947'/>", "Entering **Ransacked Treasury Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='945'/>", "Entering **Drowning Deeps Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='942'/>", "Entering **Hollow's Heart Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='944'/>", "Entering **Starstone Mines Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='940'/>", "Entering **Ebondrake Lair Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='939'/>", "Entering **Irontech Forge Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='937'/>", "Entering **Naryu Sanctum Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='817'/>", "Entering **Naryu Foundry Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='815'/>", "Entering **Desolate Tomb Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='812'/>", "Entering **Ebondrake Citadel Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='807'/>", "Entering **Sogun's Lament Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='813'/>", "Entering **The Shattered Masts Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='810'/>", "Entering **Sundered Nexus Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='811'/>", "Entering **Gloomdross Incursion Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='814'/>", "Entering **Cold Storage Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='808'/>", "Entering **Avalanche Den Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='809'/>", "Entering **Awakened Necropolis Gateway**");
                        bString = bString.Replace("<guild-member-area geo-zone='932'/>", "Entering **Heaven's Mandate Gateway**");

                        bString = bString.Replace("<guild-member-area geo-zone='7316'/>", "Entering **Burning Mausoleum**");
                        bString = bString.Replace("<guild-member-area geo-zone='7311'/>", "Entering **Desolate Masoleum**");
                        bString = bString.Replace("<guild-member-area geo-zone='6272'/>", "Entering **Brood Chamber - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6273'/>", "Entering **Brood Chamber - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6372'/>", "Entering **Dreamsong Theater - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6373'/>", "Entering **Dreamsong Theater - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6252'/>", "Entering **The Shadowmoor - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6253'/>", "Entering **The Shadowmoor - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6618'/>", "Entering **Sandstorm Temple - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6619'/>", "Entering **Sandstorm Temple - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6232'/>", "Entering **Ransacked Treasury - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6233'/>", "Entering **Ransacked Treasury - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6613'/>", "Entering **Drowning Deeps - 1/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6614'/>", "Entering **Drowning Deeps - 2/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6615'/>", "Entering **Drowning Deeps - 3/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6222'/>", "Entering **Hollow's Heart - 1/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6225'/>", "Entering **Hollow's Heart - 2/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6223'/>", "Entering **Hollow's Heart - 3/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6601'/>", "Entering **Starstone Mines**");
                        bString = bString.Replace("<guild-member-area geo-zone='6212'/>", "Entering **Ebondrake Lair - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6213'/>", "Entering **Ebondrake Lair - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6353'/>", "Entering **Irontech Forge - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6354'/>", "Entering **Irontech Forge - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6203'/>", "Entering **Naryu Sanctum - 1/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6204'/>", "Entering **Naryu Sanctum - 2/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6205'/>", "Entering **Naryu Sanctum - 3/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='4443'/>", "Entering **Naryu Foundry**");
                        bString = bString.Replace("<guild-member-area geo-zone='5925'/>", "Entering **Desolate Tomb**");
                        bString = bString.Replace("<guild-member-area geo-zone='4743'/>", "Entering **Ebondrake Citadel**");
                        bString = bString.Replace("<guild-member-area geo-zone='5903'/>", "Entering **Sogun's Lament**");
                        bString = bString.Replace("<guild-member-area geo-zone='4746'/>", "Entering **The Shattered Masts**");
                        bString = bString.Replace("<guild-member-area geo-zone='5917'/>", "Entering **Sundered Nexus - B1**");
                        bString = bString.Replace("<guild-member-area geo-zone='4738'/>", "Entering **Gloomdross Incursion**");
                        bString = bString.Replace("<guild-member-area geo-zone='4732'/>", "Entering **Cold Storage - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='4734'/>", "Entering **Cold Storage - 2/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='5911'/>", "Entering **Avalanche Den**");
                        bString = bString.Replace("<guild-member-area geo-zone='5908'/>", "Entering **Awakened Necropolis**");
                        bString = bString.Replace("<guild-member-area geo-zone='5163'/>", "Entering **Heaven's Mandate**");

                        bString = bString.Replace("<guild-member-area geo-zone='7380'/>", "Entering **Moon Refuge**");
                        bString = bString.Replace("<guild-member-area geo-zone='5600'/>", "Entering **Zaiwei - South District**");
                        bString = bString.Replace("<guild-member-area geo-zone='4900'/>", "Entering **Mushin's Hall - First Floor**");
                        bString = bString.Replace("<guild-member-area geo-zone='6400'/>", "Entering **Celestial Basin**");
                        bString = bString.Replace("<guild-member-area geo-zone='6100'/>", "Entering **Dasari Palace Gardens**");
                        bString = bString.Replace("<guild-member-area geo-zone='6517'/>", "Entering **Ajanara Monastery**");
                        bString = bString.Replace("<guild-member-area geo-zone='6624'/>", "Entering **Emperor's Tomb**");

                        bString = bString.Replace("<guild-member-area geo-zone='6431'/>", "Entering **Outlaw Island - Bomani**");
                        bString = bString.Replace("<guild-member-area geo-zone='6432'/>", "Entering **Outlaw Island - Maksun**");
                        bString = bString.Replace("<guild-member-area geo-zone='6433'/>", "Entering **Outlaw Island - Slashimi**");
                        bString = bString.Replace("<guild-member-area geo-zone='6434'/>", "Entering **Outlaw Island - Juna**");
                        bString = bString.Replace("<guild-member-area geo-zone='6435'/>", "Entering **Outlaw Island - Yeoharan**");

                        bString = bString.Replace("<guild-member-area geo-zone='6585'/>", "Entering **Circle of Sundering - First Boss**");
                        bString = bString.Replace("<guild-member-area geo-zone='6586'/>", "Entering **Circle of Sundering - Juwol**");
                        bString = bString.Replace("<guild-member-area geo-zone='6587'/>", "Entering **Circle of Sundering - Dochun**");
                        bString = bString.Replace("<guild-member-area geo-zone='6588'/>", "Entering **Circle of Sundering - Master Hong**");

                        bString = bString.Replace("<guild-member-area geo-zone='6636'/>", "Entering **Den of the Ancients - Hachi / Machi**");
                        bString = bString.Replace("<guild-member-area geo-zone='6638'/>", "Entering **Den of the Ancients - M'ao**");

                        bString = bString.Replace("<guild-member-area geo-zone='6420'/>", "Entering **Temple of Eluvium - 1/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6421'/>", "Entering **Temple of Eluvium - 2/3**");
                        bString = bString.Replace("<guild-member-area geo-zone='6425'/>", "Entering **Temple of Eluvium - 3/3**");

                        bString = bString.Replace("<guild-member-area geo-zone='6363'/>", "Entering **Scion's Keep - 1/2**");
                        bString = bString.Replace("<guild-member-area geo-zone='6361'/>", "Entering **Scion's Keep - 2/2**");

                        bString = bString.Replace("<guild-member-area geo-zone='4451'/>", "Entering **Skybreak Spire - 1/4**");
                        bString = bString.Replace("<guild-member-area geo-zone='4452'/>", "Entering **Skybreak Spire - 2/4**");
                        bString = bString.Replace("<guild-member-area geo-zone='4453'/>", "Entering **Skybreak Spire - 3/4**");
                        bString = bString.Replace("<guild-member-area geo-zone='4454'/>", "Entering **Skybreak Spire - 4/4**");

                        bString = bString.Replace("<guild-member-area geo-zone='6261'/>", "Entering **Hall of the Keeper**");
                        bString = bString.Replace("<guild-member-area geo-zone='6263'/>", "Entering **Hall of the Templar**");
                        bString = bString.Replace("<guild-member-area geo-zone='6437'/>", "Entering **Fallen Aransu School**");
                        bString = bString.Replace("<guild-member-area geo-zone='6439'/>", "Entering **Snowjade Fortress**");

                        var embed = new EmbedBuilder();

                        if (aString[2] == '8' && bString.IndexOf("/") > -1)
                        {
                            embed.AddField(bString.Remove(lim, bString.Length - lim), bString.Remove(0, lim + 14))
                                .WithColor(Color.Green);
                            Context.Guild.GetTextChannel(569813709539508230).SendMessageAsync("", false, embed.Build());
                        }
                        else if (aString[0] == '6' && aString[2] == '0')
                        {
                            embed.AddField(bString.Remove(lim, bString.Length - lim), bString.Remove(0, lim + 5))
                                .WithColor(Color.Purple);
                            Context.Guild.GetTextChannel(569833068572049408).SendMessageAsync("", false, embed.Build());
                        }
                        Context.Channel.SendMessageAsync("", false, embed.Build());
                        //Context.Channel.SendMessageAsync("\u200B");
                    }
                }
                //Console.Write("\n");
            }
        }
    }









    public class DumpTCP
    {
        public static void Main(string[] args)
        {
            new Program().RunBotAsync().GetAwaiter().GetResult();
            /*//Thread thread1 = new Thread();
            //new Program().RunBotAsync().GetAwaiter().GetResult();
            string ver = SharpPcap.Version.VersionString;
            // Print SharpPcap version 
            Console.WriteLine("SharpPcap {0}, Example6.DumpTCP.cs", ver);
            Console.WriteLine();

            // Retrieve the device list 
            var devices = CaptureDeviceList.Instance;

            //If no device exists, print error 
            if(devices.Count<1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }
            
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i=0;

            // Scan the list printing every entry 
            foreach(var dev in devices)
            {
                // Description 
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse( Console.ReadLine() );

            var device = devices[i];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += 
                new PacketArrivalEventHandler( device_OnPacketArrival );

            // Open the device for capturing
            int readTimeoutMilliseconds = 10;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //tcpdump filter to capture only TCP/IP packets
            string filter = "src net 52.28.190.106";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine
                ("-- The following tcpdump filter will be applied: \"{0}\"", 
                filter);
            Console.WriteLine
                ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);

            // Start capture 'INFINTE' number of packets
            device.Capture();
            // Close the pcap device
            // (Note: this line will never be called since
            //  we're capturing infinite number of packets
            device.Close();
        }*/

        /// <summary>
        /// Prints the time, length, src ip, src port, dst ip and dst port
        /// for each TCP/IP packet received on the network
        /// </summary>
        /// 







        /*private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {           
            //var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
            if(tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                //Console.WriteLine("{0}:{1}:{2},{3} Len={4} {5}:{6} -> {7}:{8}", 
                //time.Hour, time.Minute, time.Second, time.Millisecond, len,
                //"52.28.190.106", srcPort, dstIp, dstPort);

                for (int i = 0; i < len; i++)
                    if (e.Packet.Data[i] >= 32 && e.Packet.Data[i] <= 128)
                    {
                        Console.Write((char)e.Packet.Data[i]);
                    }
                
                Console.Write("\n");
                Console.Write("\n");

            }*/
        }
    }
}
