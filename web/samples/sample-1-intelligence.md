# OneMail Investigation Report

> **Scope:** Evidence-grounded isolated investigation. This report does not assign a malicious/benign verdict or prescribe an action.

| Report detail | Value |
| --- | --- |
| Email | <code>dataset/phishing_pot/email/sample-1.eml</code> |
| Model | <code>qwen/qwen3.6-35b-a3b</code> |
| Analysis | Deterministic detection + sandboxed inspection, rendering, and emulation |

## Investigation Overview

Grounded observations: link on a high-abuse TLD combined with action/urgency language

### At a glance

| Category | Count |
| --- | ---: |
| Detection signals | 1 |
| Analysed files | 2 |
| Grounded observations | 1 |
| Indicators | 0 |
| Evidence records | 15 |
| Gaps and limitations | 0 |

## Key Findings

### Detection signals

| Severity | Detector | Basis | Finding |
| --- | --- | --- | --- |
| MEDIUM | <code>high_abuse_tld</code> | Heuristic | link on a high-abuse TLD combined with action/urgency language |

### Grounded analysis observations

| # | Confidence | Observation | Evidence |
| --- | --- | --- | --- |
| 1 | Medium | link on a high-abuse TLD combined with action/urgency language | <code>0a0f3af8994df994</code> |

## Analysed Files

| ID | File | Parent | Detected type | Similarity | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| <code>email</code> | <code>message.eml</code> | — | message/rfc822 | <code>5cf1fa8d836a5e82</code> | <code>35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0</code> |
| <code>a001</code> | <code>body-1.html</code> | — | text/html | <code>eb82e6279b451fdf</code> | <code>772ad9cb4dc9077a882a9be8b185c47f51ff0dd29ea50397a82fa309b471ce24</code> |

## Indicators

No independently grounded indicators were retained.

## Technical Assessment

### Diamond Model

| Facet | Assessment | Confidence | Evidence |
| --- | --- | --- | --- |
| Adversary | Unknown from available evidence | — | — |
| Infrastructure | blog1seguimentmydomaine2bra.me | Medium | <code>0a0f3af8994df994</code> |
| Infrastructure | 137.184.34.4 | Low | <code>359fe577d36c4d51</code> |
| Capability | Unknown from available evidence | — | — |
| Victim | Unknown from available evidence | — | — |

### MITRE ATT&CK

| Technique | Confidence | Evidence-based rationale | Evidence |
| --- | --- | --- | --- |
| <code>T1566.002</code> Spearphishing Link | Medium | link on a high-abuse TLD combined with action/urgency language | <code>0a0f3af8994df994</code> |

### Cyber Kill Chain

No Cyber Kill Chain mappings were supported by the available evidence.

## Limitations and Gaps

- No additional gaps were recorded.

## Technical Evidence Appendix

<details>
<summary>Show 15 evidence records</summary>

<h4><code>0a0f3af8994df994</code> — high_abuse_tld</h4>
<p><strong>Source:</strong> detection</p>
<pre><code>{
  "clause": "link on a high-abuse TLD combined with action/urgency language",
  "evidence": {
    "hosts": [
      "blog1seguimentmydomaine2bra.me"
    ],
    "matched_language": [
      "expire",
      "expira",
      "expirando",
      "expiram",
      "resgate"
    ],
    "tlds": [
      "me"
    ]
  },
  "heuristic": true,
  "severity": "medium"
}</code></pre>
<h4><code>c7afd0ff07ed4feb</code> — extract</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "artifacts": 2,
  "failures": 0
}</code></pre>
<h4><code>5558a5c39baad550</code> — profile</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "declared": "message/rfc822",
  "detected": "message/rfc822",
  "entropy": 6.070433,
  "extension": "eml",
  "mismatch": false,
  "printable_ratio": 0.999875,
  "sha256": "35ef116a75e5e46e6859b49b60a23b4ddfe5f91d1368e0fc67a16df698cb96e0",
  "similarity_hash": "5cf1fa8d836a5e82",
  "size": 15967
}</code></pre>
<h4><code>6399e0b3dd875db5</code> — strings</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "count": 228,
  "preview": [
    "Received: from SA3PR19MB7370.namprd19.prod.outlook.com (::1) by",
    " MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Tue, 19 Sep 2023 18:36:46",
    " +0000",
    "Received: from BN0PR03CA0023.namprd03.prod.outlook.com (2603:10b6:408:e6::28)",
    " by SA3PR19MB7370.namprd19.prod.outlook.com (2603:10b6:806:317::17) with",
    " Microsoft SMTP Server (version=TLS1_2,",
    " cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6792.27; Tue, 19 Sep",
    " 2023 18:36:45 +0000",
    "Received: from BN8NAM11FT066.eop-nam11.prod.protection.outlook.com",
    " (2603:10b6:408:e6:cafe::23) by BN0PR03CA0023.outlook.office365.com",
    " (2603:10b6:408:e6::28) with Microsoft SMTP Server (version=TLS1_2,",
    " cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6792.28 via Frontend",
    " Transport; Tue, 19 Sep 2023 18:36:45 +0000",
    "Authentication-Results: spf=temperror (sender IP is 137.184.34.4)",
    " smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06; dkim=none (message not",
    " signed) header.d=none;dmarc=temperror action=none",
    " header.from=atendimento.com.br;compauth=fail reason=001",
    "Received-SPF: TempError (protection.outlook.com: error in processing during",
    " lookup of ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06: DNS Timeout)",
    "Received: from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4) by"
  ]
}</code></pre>
<h4><code>fed0bfee2ca179bb</code> — yara</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "matches": [],
  "rules_sha256": "26dba42a74ae5badb1b779a72bed3983168eced6fd0f9bcfd7a4fefe9c32b585"
}</code></pre>
<h4><code>3415cbb22955d06f</code> — profile</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "declared": "text/html",
  "detected": "text/html",
  "entropy": 4.993934,
  "extension": "html",
  "mismatch": false,
  "printable_ratio": 0.992699,
  "sha256": "772ad9cb4dc9077a882a9be8b185c47f51ff0dd29ea50397a82fa309b471ce24",
  "similarity_hash": "eb82e6279b451fdf",
  "size": 4931
}</code></pre>
<h4><code>6227e894947e0512</code> — strings</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "count": 69,
  "preview": [
    "&lt;!DOCTYPE html&gt;&lt;html lang=\"en\"&gt;&lt;head&gt;",
    "&lt;meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"&gt;&lt;body style=\"background-color:rgb(241, 241, 241);\"&gt;",
    "\t&lt;p style=\"text-align:center;\"&gt;",
    "\t\t&lt;font face=\"Arial\" size=\"2\"&gt;Para visualizar as imagens deste email. &lt;a href=\"https://blog1seguimentmydomaine2bra.me/\"&gt;Clique aqui&lt;/a&gt;&lt;/font&gt;",
    "    &lt;meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"&gt;",
    "    &lt;meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"&gt;",
    "    &lt;link rel=\"preconnect\" href=\"https://fonts.gstatic.com\"&gt;",
    "    &lt;link href=\"https://fonts.googleapis.com/css2?family=Signika:wght@300;500;700&amp;amp;display=swap\" rel=\"stylesheet\"&gt;",
    "    &lt;title&gt;Pontos Livelo&lt;/title&gt;",
    "&lt;/head&gt;",
    "&lt;body style=\"background-color:#eeeeee;\"&gt;",
    "    &lt;div id=\"bg\" style=\"width: 602px; margin: 0 auto; padding: 15px;background-color: #fff;\"&gt;",
    "        &lt;div id=\"bg\" style=\"width: 100%; margin: 0 auto; padding: 0px 15px 15px 15px; border: 2px solid #e50091;box-sizing: border-box;\"&gt;",
    "            &lt;div style=\"text-align: center; margin-bottom: 30px;\"&gt;",
    "                &lt;img src=\"header.png\" alt=\"\"&gt;",
    "            &lt;/div&gt;",
    "            &lt;div style=\"text-align: center;\"&gt;",
    "                &lt;img src=\"icone-superior.png\" alt=\"\"&gt;",
    "            &lt;/div&gt;",
    "            &lt;div style=\"text-align: center;\"&gt;"
  ]
}</code></pre>
<h4><code>4c53a8ae94433435</code> — yara</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "matches": [],
  "rules_sha256": "26dba42a74ae5badb1b779a72bed3983168eced6fd0f9bcfd7a4fefe9c32b585"
}</code></pre>
<h4><code>b2ccf65ff105ee87</code> — render</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "external_resources_fetched": false,
  "ocr_preview": "Para visualizar as imagens deste email. Clique aqui\n\nBanco do Bradesco (Livelo).\n\nVocé possui Pontos Livelo com seu cartao Banco do Bradesco\ndisponiveis para resgate que expiram HOJE, evite a perda destes\n\npontos realizando agora mesmo o resgate da sua Pontuacao Visa\nInfinite.\n\nVocé Clientes Banco do Bradesco acumulam pontos livelo todas as\nvezes que utilizam seus cartdes na funco débito ou crédito, é rapido\ne facil de acumular.\n\n‘Troque seus pontos por milhas aéreas\nDescontos de até 35% na fatura do\n\ncarta\n\nResgatar Agora\n\nResgate agora mesmo antes que eles expirem! Aproveite, Toque seus pontos por milhas\naereas, Descontos de ate 35% no cartéo ou milhares de premios em nosso Catalogo.\n\n",
  "pages_requested": 3,
  "screenshot_bytes": 82643,
  "screenshot_sha256": "76aaf3243838a1fd14e4e8bdebe4a714890aa7163ef229c21579500922ec42ab",
  "text_preview": "Para visualizar as imagens deste email. Clique aqui\n\nBanco do Bradesco (Livelo).\nVocê possui Pontos Livelo com seu cartão Banco do Bradesco\ndisponíveis para resgate que expiram HOJE, evite a perda destes\npontos realizando agora mesmo o resgate da sua Pontuação Visa\nInfinite.\nVocê Clientes Banco do Bradesco acumulam pontos livelo todas as\nvezes que utilizam seus cartões na função débito ou crédito, é rápido\ne fácil de acumular.\n\nTroque seus pontos por milhas aéreas\nDescontos de até 35% na fatura do\ncartão\n\n92.990\nMIL PONTOS ACUMULADOS EXPIRAM\nHOJE\n\nResgatar Agora\n\nResgate agora mesmo antes que eles expirem! Aproveite, Troque seus pontos por milhas\naereas, Descontos de ate 35% no cartão ou milhares de premios em nosso Catalogo.\n\n\f"
}</code></pre>
<h4><code>359fe577d36c4d51</code> — ioc</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "domains": [
    "ATENDIMENTO.COM.BR",
    "BANCO.BRADESCO",
    "BN0PR03CA0023.namprd03.prod.outlook.com",
    "BN0PR03CA0023.outlook.office365.com",
    "BN8NAM11FT066.eop-nam11.prod.protection.outlook.com",
    "BN8NAM11FT066.mail.protection.outlook.com",
    "MN0PR19MB6312.namprd19.prod.outlook.com",
    "SA3PR19MB7370.namprd19.prod.outlook.com",
    "atendimento.com.br",
    "banco.bradesco",
    "header.from",
    "protection.outlook.com",
    "smtp.mailfrom"
  ],
  "email_addresses": [
    "BANCO.BRADESCO@ATENDIMENTO.COM.BR",
    "banco.bradesco@atendimento.com.br"
  ],
  "ip_addresses": [
    "10.13.177.138",
    "137.184.34.4"
  ],
  "urls": []
}</code></pre>
<h4><code>0d06f86b296a1c3e</code> — ioc</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "domains": [
    "blog1seguimentmydomaine2bra.me",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "header.png",
    "icone-rodape.png",
    "icone-superior.png"
  ],
  "email_addresses": [],
  "ip_addresses": [],
  "urls": [
    "https://blog1seguimentmydomaine2bra.me/",
    "https://fonts.googleapis.com/css2?family=Signika:wght@300;500;700&amp;amp;display=swap",
    "https://fonts.gstatic.com"
  ]
}</code></pre>
<h4><code>9b242f3b55a4fb4e</code> — decode</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "decoded": []
}</code></pre>
<h4><code>1cd74752fb38b93e</code> — script</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "base64_candidates": 0,
  "encoding": "utf-8",
  "lines": 120,
  "longest_line": 371,
  "suspicious_tokens": []
}</code></pre>
<h4><code>ed8bf20b875cadec</code> — embedded</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "carved": [],
  "signatures": []
}</code></pre>
<h4><code>990cd0153a635551</code> — correlation</h4>
<p><strong>Source:</strong> analysis</p>
<pre><code>{
  "database": "local-normalised-intelligence",
  "exact_artifact_matches": [],
  "indicator_matches": [],
  "raw_message_stored": false,
  "similar_artifact_matches": []
}</code></pre>

</details>
