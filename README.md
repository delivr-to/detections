# Detections

This repo serves as a home for detection content developed by the [delivr.to](https://delivr.to) team.

All rules present in this repo have corresponding payloads (linked in references and shown below) that can be used to test detection content.

The repo currently holds the following types of detections:

- [Sublime Rules](#sublime-rules)
- [Yara Rules](#yara-rules)
- [Sigma Rules](#sigma-rules)

## Sublime Rules

Below is the list of rules for Sublime Security, organised into [General](sublime-rules/general/) and [Threat Intel](sublime-rules/threatintel/) specific folders.

You can also integrate delivr.to directly with Sublime as mentioned [here](https://blog.delivr.to/introducing-delivrto-7a8840ff5ed5) and documented [here](https://docs.delivr.to/docs/integrations/sublime_integration.html).

![](assets/delivrto-sublime-integration-results.png)

| Rule Name                                            | Type       | Payload 	| 
|------------------------------------------------------|------------|----------	| 
| [Body: Img Element Exploiting CVE-2024-38021 (Unsolicited)](sublime-rules/threatintel/body_cve_2024_38021.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=a0c7d2a6-4fb0-4120-b658-17a408c2d68e)        | 
| [Link: PIF File from Suspicious Source (AgentTesla)](sublime-rules/threatintel/link_agenttesla_pif.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=756f48df-4e6b-4855-bbb6-e673dfd4c705)        | 
| [Attachment: HTML with search-ms URI protocol handler (DarkGate)](sublime-rules/threatintel/attachment_html_search_ms.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=e3d89f22-df99-4693-b788-03022288ec43)        | 
| [Attachment: HTML with Meta Tag Refresh and File Protocol Handler (Pikabot)](sublime-rules/threatintel/attachment_html_meta_refresh.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=86dc74b5-ed67-41c9-8dc9-889ef11304d2)        | 
| [Attachment: PDF Link with Microsoft OneDrive Branding (Pikabot)](sublime-rules/threatintel/attachment_pdf_with_onedrive_pikabot_lure.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=a27587a6-ac97-4174-8f9e-c388ae54b0b4)        | 
| [Attachment: ZIP Containing LNK Minimized One-Liner (Unsolicited)](sublime-rules/threatintel/attachment_lnk_oneliner.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=2c258e20-9400-4c5d-9954-91eb2fa21050)        | 
| [Attachment: HTML Smuggling of Zip File with Evasion Indicators (Unsolicited)](sublime-rules/threatintel/attachment_html_smuggling_zip_with_evasion.yml ) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=37541776-bc8e-4af7-a54e-de97052ec092)        | 
| [Attachment: PDF with embedded MHT using ActiveMime objects (Unsolicited)](sublime-rules/threatintel/attachment_pdf_activemime_polyglot.yml) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=d93ea8ea-d421-4a1e-955b-a346a9eefa23)        | 
| [Attachment: Zip Exploiting CVE-2023-38831 (Unsolicited)](sublime-rules/threatintel/attachment_cve_2023_38831.yml) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=ab969e8a-bf5c-45a6-acd0-0dd2b2a34750)        | 
| [Attachment: PDF with Auto-Open Embedded Smuggling File](sublime-rules/threatintel/attachment_pdf_with_embedded_smuggling_file.yml) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=8d9b646c-cbf9-434e-8e1e-a014bd6248a7)        | 
| [Attachment: OneNote file with Suspicious Strings](sublime-rules/threatintel/attachment_onenote_suspicious_strings.yml) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=56188625-d386-489e-bf50-604d89675c2a)        | 
| [Link: Zipped OneNote file with Document Download Lure (QakBot)](sublime-rules/threatintel/link_qakbot_zipped_onenote_doc_download_lure.yml) 	               | Threat Intel    |  [![](assets/delivrto.png)](https://delivr.to/payloads?id=cee09f6e-9cac-4fc9-a033-c69254e6396c)         | 
| [Attachment: OneNote containing HTA with VBScript and JavaScript content (QakBot)](sublime-rules/threatintel/attachment_qakbot_onenote_with_hta_containing_javascript_vbscript.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=56188625-d386-489e-bf50-604d89675c2a)      |
| [Attachment: WSF File With Certificate Content (QakBot)](sublime-rules/threatintel/attachment_wsf_cert_file.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=6f7644eb-f31c-4240-8009-48a8db6fb417)      |
| [Attachment: PDF with Document Download Lure](sublime-rules/threatintel/attachment_pdf_with_document_download_lure.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=5d45687f-b2e3-4add-9b2c-71b68eecb169)      |
| [Attachment: PDF with Embedded Google Firebase Storage Link (Bumblebee)](sublime-rules/threatintel/attachment_pdf_with_firebase_link.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=61b6892e-51d9-4840-8446-4a78c80af5cb)      |
| [Attachment: Office Document with Embedded RTF Referencing Remote Resources CVE-2023-36884 (Unsolicited)](sublime-rules/threatintel/attachment_cve_2023_36884.yml) 	               | Threat Intel    |        | 
| [Attachment: HTML smuggling with Google Web Toolkit (GWT)](sublime-rules/general/attachment_html_file_with_gwt.yml ) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=a9d13662-2cbf-4c96-9f2e-f303afed8c6e)        | 
| [Attachment: HTML smuggling with WebAssembly (Wasm)](sublime-rules/general/attachment_html_file_with_wasm.yml ) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=126f0f5f-f2da-488e-9c82-af0aea90f154)        | 
| [Attachment: ZPAQ Archive (Unsolicited)](sublime-rules/general/attachment_zpaq_archive_unsolicited.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=33ac88a5-56fd-4c64-b01d-9489ea1fe00e)        | 
| [Attachment: Microsoft-branded HTML File (Unsolicited)](sublime-rules/general/attachment_microsoft_branded_html.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=37541776-bc8e-4af7-a54e-de97052ec092)        | 
| [Attachment: HTML file without HTML element (Unsolicited)](sublime-rules/general/attachment_html_file_without_html_elements.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=db56849c-7ae3-43b4-b07a-527b86217f43)        | 
| [Attachment: SVG file with Onerror or Onload (Unsolicited)](sublime-rules/general/attachment_svg_with_onload_onerror.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=01b3a3e8-dec1-4106-b782-d82c1fe658a9)        | 
| [Attachment: SVG file with Script Tags (Unsolicited)](sublime-rules/general/attachment_svg_with_script_element.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=3dce858d-7be3-412e-85d9-84f3b9845275)        | 
| [Attachment: HTML file with eval function and long byte string (Unsolicited)](sublime-rules/general/attachment_html_eval_byte_string.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=2e5e3a7b-457d-4bd9-8cbe-77d3f403b74c)        | 
| [Attachment: HTML File Containing Recipient Email Address (Unsolicited)](sublime-rules/general/attachment_html_file_with_recipient_email.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=648f544d-a2b0-4968-884e-a5d1a72f51fb)        | 
| [Attachment: Extended HTML File Format (Unsolicited)](sublime-rules/general/attachment_xhtml.yml ) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=44381a80-9269-4974-9d16-a62318ec39f3)        | 
| [Attachment: Microsoft Script Encoding Content](sublime-rules/general/attachment_microsoft_script_encoding_content.yml ) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=e8dce489-d33e-46b5-9e9f-cf2713abd213)        | 
| [Link: Zipped OneNote file](sublime-rules/general/link_zipped_onenote.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=cee09f6e-9cac-4fc9-a033-c69254e6396c)        | 
| [Link: OneNote file](sublime-rules/general/link_onenote.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=ea1b0f0e-fe2b-4ec9-8ba6-56cedf98066e)        | 
| [Link: Brand Impersonation Phishing Site](sublime-rules/general/link_brand_impersonation_phishing_site.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=14bacd0a-a160-4343-80ef-fa7998a32d2d)        | 
| [Link: Zipped Script File (Unsolicited)](sublime-rules/general/attachment_autoit.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=a8e3b1ee-6454-4b45-9b0f-31bf195f059b)        | 
| [Attachment: Remote Template Injection](sublime-rules/general/attachment_remote_template_injection.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=ef187d5d-3188-483e-b3b5-9ab5e0e032f7)        | 
| [Attachment: HTML Smuggling with msSaveOrOpenBlob](sublime-rules/general/attachment_mssaveoropenblob.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=be91a311-a023-4221-96da-6f5b717fdc54)        | 
| [Attachment: AutoIt Script File (Unsolicited)](sublime-rules/general/link_zipped_script.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=84e421f8-ffc6-425b-b64d-df0a32e8c679)        | 
| [Attachment: Microsoft Word SMB-hosted Remote Template Injection](sublime-rules/general/attachment_smb_remote_template_injection.yml) | General | [![](assets/delivrto.png)](https://delivr.to/payloads?id=73895e1a-4c15-4d1e-8e17-60f05baafdd2) |

## Yara Rules

Below is the list of Yara rules in the repo. 

| Rule Name                                            | Type       | Payload 	| 
|------------------------------------------------------|------------|----------	| 
| [SUSP_HTML_WASM_Smuggling](yara-rules/html_wasm.yar)	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=126f0f5f-f2da-488e-9c82-af0aea90f154)        | 
| [SUSP_HTML_B64_WASM_Blob](yara-rules/html_wasm.yar)	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=126f0f5f-f2da-488e-9c82-af0aea90f154)        | 
| [SUSP_ZPAQ_Archive_Nov23](yara-rules/zpaq_archives.yar)	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=33ac88a5-56fd-4c64-b01d-9489ea1fe00e)        | 
| [SUSP_PDF_MHT_ActiveMime_Sept23](yara-rules/pdf_mht_activemime.yar)	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=d93ea8ea-d421-4a1e-955b-a346a9eefa23)        | 
| [SUSP_SVG_Onload_Onerror_Jul23](yara-rules/svg_onload_onerror.yar)	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=01b3a3e8-dec1-4106-b782-d82c1fe658a9)        | 
| [SUSP_OneNote_Repeated_FileDataReference_Feb23](yara-rules/onenote_repeated_files.yar)	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=2722d95f-f51d-4ad7-aeb1-60a38e52ae5e)        | 
| [SUSP_OneNote_RTLO_Character_Feb23](yara-rules/onenote_rtlo_filename.yar)	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=44bab49e-21f0-40ef-8851-f9ea70d6b001)        | 
| [SUSP_OneNote_Win_Script_Encoding_Feb23](yara-rules/onenote_windows_script_encoding_file.yar )	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=e8dce489-d33e-46b5-9e9f-cf2713abd213)        | 
| [SUSP_msg_CVE_2023_23397_Mar23](yara-rules/msg_cve_2023_23397.yar )	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=494a2718-a012-45d5-9fe8-27465b0c1809)        | 
| [SUSP_CONCAT_ZIP_Nov24](yara-rules/concatenated_zip.yar )	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=a8ebf059-b4e6-4d83-9953-6a97cdd5b5b0)        | 

## Sigma Rules

Below is the list of Sigma rules in the repo.

| Rule Name                                            | Type       | Payload 	| 
|------------------------------------------------------|------------|----------	| 
| [PDF HTML Smuggling](sigma-rules/file_event_win_pdf_html_smuggle.yml)	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=10fea5c5-9a05-423d-82cb-ea21e28ddc27)        | 
