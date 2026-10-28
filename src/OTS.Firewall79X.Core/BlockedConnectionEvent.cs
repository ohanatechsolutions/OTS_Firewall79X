using System.Net;

namespace OTS.Firewall79X.Core;

/// <summary>Validated inbound TCP Windows Filtering Platform event 5157 metadata.
/// 5157 SourceAddress/SourcePort are the local endpoint and DestAddress/DestPort
/// describe the remote endpoint. SourcePort is the targeted LOCAL listening port.
/// This parser is intentionally not a packet firewall or packet inspection engine.
/// </summary>
public static class BlockedConnectionEvent
{
    public sealed record InboundTcp(string LocalAddress,int LocalPort,string RemoteAddress,int RemotePort);

    public static bool TryParseInboundTcp(
        string? direction,string? sourceAddress,string? sourcePort,
        string? destinationAddress,string? destinationPort,string? protocol,
        out InboundTcp? connection)
    {
        connection=null;
        if(direction!="%%14592" || protocol!="6" ||
           !IPAddress.TryParse(sourceAddress,out var local) ||
           !IPAddress.TryParse(destinationAddress,out var remote) ||
           remote.IsIPv4MappedToIPv6 || !NetworkAbuseWindow.EligiblePublicSource(destinationAddress) ||
           !int.TryParse(sourcePort,out int localPort) || localPort is <1 or >65535 ||
           !int.TryParse(destinationPort,out int remotePort) || remotePort is <1 or >65535)
            return false;
        // Treat an unusual/malformed local endpoint as unverified evidence, never an auto-ban.
        if(local.IsIPv4MappedToIPv6)local=local.MapToIPv4();
        if(local.Equals(IPAddress.Any)||local.Equals(IPAddress.IPv6Any)||
           local.IsIPv6Multicast||local.AddressFamily!=remote.AddressFamily)
            return false;
        connection=new(local.ToString(),localPort,remote.ToString(),remotePort);
        return true;
    }
}
