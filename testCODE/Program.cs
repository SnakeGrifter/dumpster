using System;
using System.Collections.Generic;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;

namespace Program
{
    public class SnifferWorld : Sniffer
    {
        static readonly PacketMgr packetmgr = Singleton<PacketMgr>.Instance;

        public SnifferWorld()
        {
            AddListenHostConnectionInfo("80.239.149.99", 3724, "EU-Magtheridon"); // Magtheridon eu
            AddListenHostConnectionInfo("80.239.149.103", 3724, "EU-The Maelstrom"); // The Maelstrom eu
            AddListenHostConnectionInfo("80.239.233.88", 3724, "EU-Stormscale");
        }
        public override void Connected(Connection conn)
        {
            packetmgr.Reset(conn.Identifier); // reset key info and logs.
        }

        public override void AddClientData(byte[] buffer)
        {
            var data = new byte[buffer.Length];
            buffer.CopyTo(data, 0);
            packetmgr.AddTcpPacket(PacketType.Client, data);

        }
        public override void AddHostData(byte[] buffer)
        {
            var data = new byte[buffer.Length];
            buffer.CopyTo(data, 0);
            packetmgr.AddTcpPacket(PacketType.Server, data);

        }



    }