rule SUSP_CONCAT_ZIP_Nov24 {
   meta:
      description = "Zip archives concatenated together, based on the presence of more than one End of Central Directory record signature"
      author = "delivr.to"
      date = "2024-11-13"
      score = 40
      reference = "https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/"
   strings:
      $fh = { 50 4B 03 04 }
      $eocd = { 50 4B 05 06 }
   condition:
      $fh at 0 and 
      #fh > 1 and 
      #eocd == #fh
}