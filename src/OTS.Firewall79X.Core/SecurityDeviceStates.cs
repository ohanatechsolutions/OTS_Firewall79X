namespace OTS.Firewall79X.Core;
public static class SecurityDeviceStates
{
    public static bool? TpmEnabled(string? enabled,string? activated)
    {
        if (enabled?.Equals("False",StringComparison.OrdinalIgnoreCase)==true ||
            activated?.Equals("False",StringComparison.OrdinalIgnoreCase)==true)return false;
        if (enabled?.Equals("True",StringComparison.OrdinalIgnoreCase)==true &&
            activated?.Equals("True",StringComparison.OrdinalIgnoreCase)==true)return true;
        return null;
    }
    public static bool? VolumeProtected(string? status)=>status switch {"1"=>true,"0"=>false,_=>null};
}
