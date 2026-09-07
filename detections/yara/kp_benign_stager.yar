rule KP_Benign_Stager_v1
{
    meta:
        author      = "Project KESTREL"
        description = "Detects the self-authored BENIGN lab stager (malware-analysis practice artifact). Not real malware."
        reference   = "dfir/malware-analysis/analysis.md"
        sample_sha256 = "e75fb7f032522ce21dbf97aa5569896b4e25d30d599b0fdbee98c3cbeb572f09"
    strings:
        $tag    = "KESTREL-LAB-BENIGN-STAGER-v1" ascii
        $beacon = "cdn.sable-c2.example" ascii
        $mark   = "benign-stager" ascii
    condition:
        $tag or ($beacon and $mark)
}
