rule SUSP_SVG_ForeignObject_Nov24 {
   meta:
      description = "Presence of foreignObject in SVG file"
      author = "delivr.to"
      date = "2024-11-28"
      score = 40
   strings:
      $svg = "svg" ascii wide nocase
      $fo = "</foreignObject" ascii wide nocase
   condition:
      all of them
}