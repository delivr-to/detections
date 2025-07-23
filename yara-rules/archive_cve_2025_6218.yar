rule SUSP_archive_CVE_2025_6218_Jul25 {
    meta:
        description = "ZIP or RAR archive with directory traversal exploit"
        author = "delivr.to"
        date = "2025-07-23"
        score = 60
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6218"
    strings:
        $t1 = "\\.. ."
        $t2 = "/.. /"
    condition:
        (uint32be(0) == 0x52617221 or   // RAR File Magic Header
        uint32(0) == 0x04034b50)        // Zip File Header
        and filesize < 1024KB 
        and any of ($t*) in (8..504)
        and (#t1 > 1 or #t2 > 1)
}