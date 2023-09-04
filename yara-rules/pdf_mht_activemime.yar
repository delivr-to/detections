rule SUSP_PDF_MHT_ActiveMime_Sept23 {
    meta:
      description = "Presence of MHT ActiveMime within PDF for polyglot file"
      author = "delivr.to"
      date = "2023-09-04"
      score = 70
      reference = "https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html"

    strings:
        $mht0 = "mime" ascii nocase
        $mht1 = "content-location:" ascii nocase
        $mht2 = "content-type:" ascii nocase
        $act  = "edit-time-data" ascii nocase
     
    condition:
        uint32(0) == 0x46445025 and
        all of ($mht*) and
        $act
}