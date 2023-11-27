rule SUSP_ZPAQ_Archive_Nov23 {
   meta:
      description = "ZPAQ file archive with expected file and block headers"
      author = "delivr.to"
      date = "2023-11-26"
      score = 40
      reference = "https://www.gdatasoftware.com/blog/2023/11/37822-agent-tesla-zpaq"
   strings:
      $fh = { 37 6B 53 74 A0 31 83 D3 8C B2 28 B0 D3 }
      $block_header = /jDC\d{14}[cdhi]\d{10}/
   condition:
      $fh at 0 and 
      $block_header
}