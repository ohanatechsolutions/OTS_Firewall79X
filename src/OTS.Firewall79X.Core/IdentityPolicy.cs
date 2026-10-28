namespace OTS.Firewall79X.Core;

/// <summary>Read-only review of the local SAM password/lockout policy. These
/// values are warning indicators, not proof of an account compromise.</summary>
public static class IdentityPasswordPolicy
{
    public sealed record Assessment(IReadOnlyList<string> Risks);
    public static Assessment Assess(uint minLength,uint history,uint maxAgeSeconds,uint lockoutThreshold)
    {
        List<string> risks=[];
        if(minLength<12)risks.Add("minimum length below 12");
        if(history<5)risks.Add("password history below 5");
        if(maxAgeSeconds==uint.MaxValue)risks.Add("passwords do not expire");
        if(lockoutThreshold==0)risks.Add("local account lockout disabled");
        return new(risks);
    }
}
