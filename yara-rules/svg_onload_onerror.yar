rule SUSP_SVG_Onload_Onerror_Jul23 {
   meta:
      description = "Presence of onload or onerror attribute in SVG file"
      author = "delivr.to"
      date = "2023-07-22"
      score = 40
   strings:
      $svg = "svg" ascii wide nocase

      $onload = "onload" ascii wide nocase
      
      $onerror = "onerror" ascii wide nocase

   condition:
      ($svg) and 
      ($onload or $onerror)
}