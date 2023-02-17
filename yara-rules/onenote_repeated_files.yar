rule SUSP_OneNote_Repeated_FileDataReference_Feb23 {
   meta:
      description = "Repeated references to files embedded in OneNote file. May indicate multiple copies of file hidden under image, as leveraged by Qakbot et al."
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* FileDataReference <ifndf>{GUID} */
      /* https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf */
      $fref = { 3C 00 69 00 66 00 6E 00 64 00 66 00 3E 00 7B 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      #fref > (#fdso * 4)
}