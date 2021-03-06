rule Emotet_Payload
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"

    strings:
        $snippet1 = {FF 15 ?? ?? ?? ?? 83 C4 0C 68 40 00 00 F0 6A 18}
        $snippet2 = {6A 13 68 01 00 01 00 FF 15 ?? ?? ?? ?? 85 C0}
        $snippet3 = {83 3D ?? ?? ?? ?? 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 74 0A 51 E8 ?? ?? ?? ?? 83 C4 04 C3 33 C0 C3}
        $snippet4 = {33 C0 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 83 C4 04 C3}
        $snippet5 = {8B E5 5D C3 B8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 21 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 18 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 59 C3}
        $snippet6 = {33 C0 21 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 18 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 59 C3}
        $snippet7 = {8B 48 ?? C7 [5-6] C7 40 ?? ?? ?? ?? ?? C7 ?? ?? 00 00 00 [0-1] 83 3C CD ?? ?? ?? ?? 00 74 0E 41 89 48 ?? 83 3C CD ?? ?? ?? ?? 00 75 F2}

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and (($snippet1) and ($snippet2)) or ($snippet3) or ($snippet4) or ($snippet5) or ($snippet6) or ($snippet7)
}

rule Emotet_Loader
{
    meta:
        author = "kevoreilly"
        description = "Emotet Loader"
        cape_type = "Emotet Loader"

    strings:
        $antihook = {8B 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 95 28 FF FF FF A1 ?? ?? ?? ?? 2D 4D 01 00 00 A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 3B 0D ?? ?? ?? ?? 76 26 8B 95 18 FF FF FF 8B 42 38}

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and any of them
}
