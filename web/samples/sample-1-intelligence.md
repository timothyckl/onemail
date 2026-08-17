# Intelligence Report: dataset/phishing\_pot/email/sample-1.eml

## Summary

No additional grounded observations were selected for the report.

## Detection Context

- link on a high-abuse TLD combined with action/urgency language

## Artifacts

- <code>message.eml</code> (<code>35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0</code>): message/rfc822

## Claims


## Indicators


## Diamond Model

### Adversary

- Unknown from available evidence.

### Infrastructure

- Unknown from available evidence.

### Capability

- Unknown from available evidence.

### Victim

- Unknown from available evidence.

## MITRE ATT&CK

- No supported mappings.

## Cyber Kill Chain

- No supported mappings.

## Gaps

- antivirus:email: ClamAV database unavailable
- agent: Email content not yet inspected for embedded URLs or attachments
- agent: No analysis of email headers for spoofing or routing anomalies
- agent: No extraction of embedded objects from the email body
- script:email: task does not apply to the detected format

## Evidence

- <code>0a0f3af8994df994</code> [detection/high\_abuse\_tld]: {"clause": "link on a high-abuse TLD combined with action/urgency language", "evidence": {"hosts": \["blog1seguimentmydomaine2bra.me"\], "matched\_language": \["expire", "expira", "expirando", "expiram", "resgate"\], "tlds": \["me"\]}, "heuristic": true, "severity": "medium"}
- <code>63a3476a884f176f</code> [analysis/extract]: {"artifacts": 1, "failures": 0}
- <code>2176bb8423c49674</code> [analysis/profile]: {"declared": "message/rfc822", "detected": "message/rfc822", "entropy": 6.070433, "extension": "eml", "mismatch": false, "printable\_ratio": 0.999875, "sha256": "35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0", "size": 15967}
- <code>6399e0b3dd875db5</code> [analysis/strings]: {"count": 228, "preview": \["Received: from SA3PR19MB7370.namprd19.prod.outlook.com \(::1\) by", " MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Tue, 19 Sep 2023 18:36:46", " +0000", "Received: from BN0PR03CA0023.namprd03.prod.outlook.com \(2603:10b6:408:e6::28\)", " by SA3PR19MB7370.namprd19.prod.outlook.com \(2603:10b6:806:317::17\) with", " Microsoft SMTP Server \(version=TLS1\_2,", " cipher=TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384\) id 15.20.6792.27; Tue, 19 Sep", " 2023 18:36:45 +0000", "Received: from BN8NAM11FT066.eop-nam11.prod.protection.outlook.com", " \(2603:10b6:408:e6:cafe::23\) by BN0PR03CA0023.outlook.office365.com", " \(2603:10b6:408:e6::28\) with Microsoft SMTP Server \(version=TLS1\_2,", " cipher=TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384\) id 15.20.6792.28 via Frontend", " Transport; Tue, 19 Sep 2023 18:36:45 +0000", "Authentication-Results: spf=temperror \(sender IP is 137.184.34.4\)", " smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06; dkim=none \(message not", " signed\) header.d=none;dmarc=temperror action=none", " header.from=atendimento.com.br;compauth=fail reason=001", "Received-SPF: TempError \(protection.outlook.com: error in processing during", " lookup of ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06: DNS Timeout\)", "Received: from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 \(137.184.34.4\) by"\]}
- <code>fed0bfee2ca179bb</code> [analysis/yara]: {"matches": \[\], "rules\_sha256": "26dba42a74ae5badb1b779a72bed3983168eced6fd0f9bcfd7a4fefe9c32b585"}
- <code>c81943183b633f78</code> [analysis/embedded]: \[{"offset": 4654, "type": "pe"}\]
- <code>3616561ac607bbdc</code> [analysis/metadata]: \[{   "SourceFile": "/work/artifacts/email",   "ExifToolVersion": 12.76,   "FileName": "email",   "Directory": "/work/artifacts",   "FileSize": "16 kB",   "FileModifyDate": "2026:08:17 02:02:46+00:00",   "FileAccessDate": "2026:08:17 02:02:46+00:00",   "FileInodeChangeDate": "2026:08:17 02:02:46+00:00",   "FilePermissions": "-rw-r--r--",   "FileType": "TXT",   "FileTypeExtension": "txt",   "MIMEType": "text/plain",   "MIMEEncoding": "utf-8",   "ByteOrderMark": "No",   "Newlines": "Windows CRLF",   "LineCount": 228,   "WordCount": 395 }\]
