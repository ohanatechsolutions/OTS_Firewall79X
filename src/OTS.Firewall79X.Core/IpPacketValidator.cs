using System.Buffers.Binary;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Pure, bounded IP header inspection. It receives packet bytes from a caller;
/// it does NOT capture packets or install WFP filters. "Unsupported" must never
/// be treated as a deny decision: ESP, IPv6 jumbograms, unknown protocols and
/// truncated CAPTURE buffers require an explicitly supported capture context.
/// </summary>
public static class IpPacketValidator
{
    public enum Verdict { Valid, Malformed, Unsupported }
    public sealed record Result(Verdict Status,int IpVersion,bool Fragmented,string Reason);
    private static Result Ok(int family,bool fragments,string reason) => new(Verdict.Valid,family,fragments,reason);
    private static Result Bad(int family,string reason) => new(Verdict.Malformed,family,false,reason);
    private static Result Unknown(int family,string reason) => new(Verdict.Unsupported,family,false,reason);

    public static Result Inspect(ReadOnlySpan<byte> packet)
    {
        if(packet.IsEmpty)return Unknown(0,"No captured packet data");
        int version=packet[0]>>4;
        return version switch
        {
            4=>Ipv4(packet),
            6=>Ipv6(packet),
            _=>Bad(version,"Invalid IP version")
        };
    }

    private static Result Ipv4(ReadOnlySpan<byte> b)
    {
        if(b.Length<20)return Unknown(4,"Truncated IPv4 capture");
        int length=(b[0]&15)*4;
        if(length<20 || length>60)return Bad(4,"Invalid IPv4 header length");
        if(length>b.Length)return Unknown(4,"Truncated IPv4 options/header capture");
        int total=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(2,2));
        if(total<length)return Bad(4,"IPv4 total length smaller than header");
        if(total>b.Length)return Unknown(4,"IPv4 capture shorter than declared packet");
        // Verify the one's-complement IPv4 header checksum, including options.
        uint sum=0;
        for(int i=0;i<length;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(i,2));
        while((sum>>16)!=0)sum=(sum&0xFFFF)+(sum>>16);
        if(sum!=0xFFFF)return Bad(4,"IPv4 header checksum mismatch");
        int fragments=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(6,2));
        bool reserved=(fragments&0x8000)!=0,df=(fragments&0x4000)!=0;
        bool mf=(fragments&0x2000)!=0,nonFirst=(fragments&0x1FFF)!=0;
        if(reserved || df&&(mf||nonFirst))return Bad(4,"Invalid IPv4 fragmentation flags");
        if(mf && (total-length)%8!=0)return Bad(4,"Non-final IPv4 fragment not eight-byte aligned");
        bool fragmented=mf||nonFirst;
        int protocol=b[9];
        if(fragmented)return Ok(4,true,"Fragment header structurally valid; reassembly and evasion checks require a stateful packet engine");
        if(protocol is 6 or 17)
        {
            int minimum=protocol==6?20:8;
            if(total-length<minimum)return Bad(4,"Truncated unfragmented transport header");
            if(protocol==17)
            {
                int udpLength=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(length+4,2));
                if(udpLength<8 || udpLength>total-length)return Bad(4,"Invalid IPv4 UDP length");
            }
            else
            {
                int tcpHeaderBytes=(b[length+12]>>4)*4;
                if(tcpHeaderBytes<20 || tcpHeaderBytes>total-length)
                    return Bad(4,"Invalid IPv4 TCP header data offset");
            }
        }
        return Ok(4,false,"IPv4 packet header and declared length inspected");
    }

    private static Result Ipv6(ReadOnlySpan<byte> b)
    {
        if(b.Length<40)return Unknown(6,"Truncated IPv6 capture");
        int payload=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(4,2));
        if(payload==0)return Unknown(6,"IPv6 zero-payload or jumbo option requires specialized validation");
        int end=40+payload;
        if(end>b.Length)return Unknown(6,"IPv6 capture shorter than declared payload");
        int next=b[6],offset=40,extensions=0;
        bool fragmented=false,nonFirst=false;
        while(next is 0 or 43 or 44 or 51 or 60 or 135 or 139 or 140)
        {
            if(++extensions>8||offset-40>2048)return Unknown(6,"IPv6 extension-chain inspection budget exceeded");
            if(next==0 && offset!=40)
                return Bad(6,"IPv6 Hop-by-Hop header must appear first");
            if(next==44)
            {
                if(offset+8>end)return Bad(6,"Truncated IPv6 fragmentation header");
                if(fragmented)return Bad(6,"Repeated IPv6 fragmentation header");
                if(b[offset+1]!=0)return Bad(6,"Nonzero IPv6 fragmentation reserved byte");
                int flags=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(offset+2,2));
                if((flags&6)!=0)return Bad(6,"IPv6 fragmentation reserved flag bits set");
                nonFirst=(flags&0xFFF8)!=0;
                fragmented=true;
                next=b[offset];
                offset+=8;
                continue;
            }
            if(offset+2>end)return Bad(6,"Truncated IPv6 extension header");
            int bytes=next==51?(b[offset+1]+2)*4:(b[offset+1]+1)*8;
            if(bytes<8 || offset+bytes>end)return Bad(6,"Invalid IPv6 extension header length");
            next=b[offset];
            offset+=bytes;
        }
        if(next==50)return Unknown(6,"Encrypted ESP payload requires a supporting security association");
        if(next==59)return Ok(6,fragmented,"IPv6 no-next-header packet structurally valid");
        if(next is not (6 or 17 or 58 or 1))return Unknown(6,"Unrecognized IPv6 next-header protocol");
        if(nonFirst)return Ok(6,true,"IPv6 noninitial fragment inspected without assuming upper-layer header");
        // RFC 7112: the first IPv6 fragment must contain the upper-layer
        // header. Later fragments are never parsed as transport headers.
        int minimum=next switch{6=>20,17=>8,_=>4};
        if(end-offset<minimum)return Bad(6,"Truncated IPv6 first/unfragmented transport header");
        if(next==17)
        {
            int udpLength=BinaryPrimitives.ReadUInt16BigEndian(b.Slice(offset+4,2));
            if(udpLength<8 || (fragmented ? udpLength<end-offset : udpLength!=end-offset))
                return Bad(6,"IPv6 UDP length mismatch");
        }
        if(next==6)
        {
            int tcpHeaderBytes=(b[offset+12]>>4)*4;
            if(tcpHeaderBytes<20 || tcpHeaderBytes>end-offset)
                return Bad(6,"Invalid IPv6 TCP header data offset");
        }
        return Ok(6,fragmented,fragmented
            ?"IPv6 fragment header inspected; overlap/reassembly requires a stateful WFP packet source"
            :"IPv6 extension chain and transport length inspected");
    }
}
