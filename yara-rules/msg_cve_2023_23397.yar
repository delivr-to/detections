rule SUSP_msg_CVE_2023_23397_Mar23 {
   meta:
      description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
      author = "delivr.to"
      date = "2023-03-15"
      score = 60
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
   condition:
      uint32be(0) == 0xD0CF11E0 and
      uint32be(4) == 0xA1B11AE1 and
      $app and 
      $rfp
}