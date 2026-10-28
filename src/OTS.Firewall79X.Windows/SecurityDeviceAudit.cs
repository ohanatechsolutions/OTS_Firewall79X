using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using OTS.Firewall79X.Core;
namespace OTS.Firewall79X.Windows;

/// <summary>Observes Windows system encryption and TPM security without accessing
/// recovery material, modifying protectors, or altering firmware security settings.</summary>
public static class SecurityDeviceAudit
{
    public sealed record Result(bool? TpmEnabled,bool? OsVolumeProtected,string Evidence);
    private static bool SupportedFailure(Exception ex)=>ex is ManagementException or COMException or UnauthorizedAccessException or SecurityException or TimeoutException or InvalidOperationException;

    public static Result Read()
    {
        bool? tpm=null,volume=null;
        string tpmEvidence="not measured",volumeEvidence="not measured";
        try
        {
            var records=SystemQueries.Wmi(@"root\CIMV2\Security\MicrosoftTpm",
                "SELECT IsEnabled_InitialValue,IsActivated_InitialValue,SpecVersion FROM Win32_Tpm",
                "IsEnabled_InitialValue","IsActivated_InitialValue","SpecVersion");
            if(records.Count==0)tpmEvidence="not enumerated (unknown)";
            else
            {
                var data=records[0];
                tpm=SecurityDeviceStates.TpmEnabled(data["IsEnabled_InitialValue"],data["IsActivated_InitialValue"]);
                tpmEvidence=(tpm==true?"enabled/activated":tpm==false?"inactive/disabled":"state unknown")+
                    "; version="+Wire.Clean(data["SpecVersion"],50);
            }
        }
        catch(Exception ex)when(SupportedFailure(ex)){tpmEvidence="provider unavailable: "+Wire.Clean(ex.Message,100);}
        try
        {
            var records=SystemQueries.Wmi(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume",
                "DriveLetter","ProtectionStatus");
            var drive=Environment.GetEnvironmentVariable("SystemDrive")??Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\')??"C:";
            var found=records.FirstOrDefault(row=>row["DriveLetter"].Equals(drive,StringComparison.OrdinalIgnoreCase));
            if(found==null)volumeEvidence="system drive not enumerated (unknown)";
            else
            {
                volume=SecurityDeviceStates.VolumeProtected(found["ProtectionStatus"]);
                volumeEvidence=volume==true?"ON":volume==false?"OFF":"unknown";
            }
        }
        catch(Exception ex)when(SupportedFailure(ex)){volumeEvidence="provider unavailable: "+Wire.Clean(ex.Message,100);}
        return new(tpm,volume,"TPM: "+tpmEvidence+"; OS drive protection: "+volumeEvidence);
    }
}
