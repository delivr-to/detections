rule SUSP_ZIP_Smuggling_Jun01
{
    meta:
        description = "ZIP archives with data smuggled between last file record and the central directory."
        author = "delivr.to"
        date = "2025-06-01"
        score = 60
        reference = "https://github.com/Octoberfest7/zip_smuggling/"
    strings:
        $lfh  = { 50 4B 03 04 }            // Local File Header
        $eocd = { 50 4B 05 06 }            // End of Central Directory

    condition:
        // Zip File Header
        uint32(0) == 0x04034b50 and

        // Require at least one LFH, no more than 10 and exactly one EOCD
        #lfh > 0 and
        #lfh <= 10 and
        #eocd == 1 and

        // Extract reasonable name and extra field lengths from last LFH
        uint16(@lfh[#lfh] + 26) <= 256 and
        uint16(@lfh[#lfh] + 28) <= 256 and

        // Compressed size from LFH must be present and sane
        uint32(@lfh[#lfh] + 18) > 0 and
        uint32(@lfh[#lfh] + 18) < 100000000 and

        // CD offset must lie after the LFH (avoid malformed back-jumps)
        uint32(@eocd[1] + 16) > @lfh[#lfh] and 

        // Compute estimated end of file content:
        // offset_of_LFH + lfh_size (fixed) + name_len + extra_len + compressed_size
        // Compare with central directory offset from EOCD
        // Gap must be 64b+, accounts for nonstandard but benign padding (data descriptors etc.)
        // but sacrificing detection of small file smuggling
        (
            uint32(@eocd[1] + 16) - (
                @lfh[#lfh] +
                30 +
                uint16(@lfh[#lfh] + 26) +
                uint16(@lfh[#lfh] + 28) +
                uint32(@lfh[#lfh] + 18)
            )
        ) > 64
}

rule SUSP_ZIP_Smuggling_Egg_Jun01
{
    meta:
        description = "ZIP archives with known egghunter byte sequence from Octoberfest7 zip_smuggling tool between end of file content and central directory."
        author = "delivr.to"
        date = "2025-06-01"
        score = 75
        reference = "https://github.com/Octoberfest7/zip_smuggling/"
    strings:
        $lfh  = { 50 4B 03 04 }            // Local File Header
        $eocd = { 50 4B 05 06 }            // End of Central Directory
        $egg  = { 55 55 55 55 }            // Egghunter Byte Sequence

    condition:
        // Zip File Header
        uint32(0) == 0x04034b50 and

        // Require at least one LFH, no more than 10 and exactly one EOCD
        #lfh > 0 and
        #lfh <= 10 and
        #eocd == 1 and
        
        // Egghunter byte sequence is present
        #egg > 0 and

        // Compute end of file content:
        // lfh_offset + lfh_size + name + extra + compressed_size
        // Check byte sequence is after last file content and before central directory
        $egg in (
            @lfh[#lfh] + 30 + uint16(@lfh[#lfh] + 26) + uint16(@lfh[#lfh] + 28) + uint32(@lfh[#lfh] + 18)
            ..
            uint32(@eocd[1] + 16)
        )
}
