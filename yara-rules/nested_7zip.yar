rule SUSP_NESTED_7ZIP_Feb25 {
    meta:
       description = "Detects a 7-Zip archive containing a 7-Zip archive"
       author = "delivr.to"
       date = "2025-02-06"
       score = 40
       reference = "https://www.trendmicro.com/en_ae/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html"
    strings:
       $magic = { 37 7A BC AF 27 1C }
    condition:
       $magic at 0 and   // Ensure it's a 7z archive
       #magic == 2       // At least two occurrences of the 7z signature
}