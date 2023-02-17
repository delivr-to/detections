# Detections

This repo serves as a home for detection content developed by the [delivr.to](https://delivr.to) team.

All rules present in this repo have corresponding payloads (linked in references and shown below) that can be used to test detection content.

The repo currently holds the following types of detections:

- [Sublime Rules](#sublime-rules)
- [Yara Rules](#yara-rules)


## Sublime Rules

Below is the list of rules for Sublime Security, organised into [General](sublime-rules/general/) and [Threat Intel](sublime-rules/threatintel/) specific folders.

You can also integrate delivr.to directly with Sublime as mentioned [here](https://blog.delivr.to/introducing-delivrto-7a8840ff5ed5) and documented [here](https://docs.delivr.to/docs/integrations/sublime_integration.html).

![](assets/delivrto-sublime-integration-results.png)

| Rule Name                                            | Type       | Payload 	| 
|------------------------------------------------------|------------|----------	| 
| [Link: Zipped OneNote file](sublime-rules/general/link_zipped_onenote.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=cee09f6e-9cac-4fc9-a033-c69254e6396c)        | 
| [Link: OneNote file](sublime-rules/general/link_onenote.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=ea1b0f0e-fe2b-4ec9-8ba6-56cedf98066e)        | 
| [Link: Brand Impersonation Phishing Site](sublime-rules/general/link_brand_impersonation_phishing_site.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=14bacd0a-a160-4343-80ef-fa7998a32d2d)        | 
| [Attachment: Remote Template Injection](sublime-rules/general/attachment_remote_template_injection.yml) 	               | General    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=ef187d5d-3188-483e-b3b5-9ab5e0e032f7)        | 
| [Attachment: OneNote file with Suspicious Strings](sublime-rules/threatintel/attachment_onenote_suspicious_strings.yml) 	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=56188625-d386-489e-bf50-604d89675c2a)        | 
| [Link: Zipped OneNote file with Document Download Lure (QakBot)](sublime-rules/threatintel/link_qakbot_zipped_onenote_doc_download_lure.yml) 	               | Threat Intel    |  [![](assets/delivrto.png)](https://delivr.to/payloads?id=cee09f6e-9cac-4fc9-a033-c69254e6396c)         | 
| [Attachment: OneNote containing HTA with VBScript and JavaScript content (QakBot)](sublime-rules/threatintel/attachment_qakbot_onenote_with_hta_containing_javascript_vbscript.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=56188625-d386-489e-bf50-604d89675c2a)      |
| [Attachment: Attachment: WSF File With Certificate Content (QakBot)](sublime-rules/threatintel/attachment_wsf_cert_file.yml) 	               | Threat Intel    |     [![](assets/delivrto.png)](https://delivr.to/payloads?id=6f7644eb-f31c-4240-8009-48a8db6fb417)      |


## Yara Rules

Below is the list of Yara rules in the repo. 

| Rule Name                                            | Type       | Payload 	| 
|------------------------------------------------------|------------|----------	| 
| [SUSP_OneNote_Repeated_FileDataReference_Feb23](yara-rules/onenote_repeated_files.yar)	               | Threat Intel    |   [![](assets/delivrto.png)](https://delivr.to/payloads?id=https://delivr.to/payloads?id=2722d95f-f51d-4ad7-aeb1-60a38e52ae5e)        | 
