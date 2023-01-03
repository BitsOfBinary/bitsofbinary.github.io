---
layout: post
title: "100 Days of YARA - Day 3"
date: 2023-01-03 00:00:00 -0000
categories: yara
---

# YARA Module Example 1 - Imphash and Rich Header Hash
A simple, yet effective way of using the PE module to cluster samples is via hash values of specific components of the PE: namely, the [import hash](https://www.mandiant.com/resources/blog/tracking-malware-import-hashing) (or imphash) and the [rich header hash](https://www.giac.org/paper/grem/6321/leveraging-pe-rich-header-static-alware-etection-linking/169729).

Both of these hash values can prove to be quite unique, and make it possible write YARA based off them. For example, if I take the SHA-256 hash `a37a290863fe29b9812e819e4c5b047c44e7a7d7c40e33da6f5662e1957862ab` from a [report by Mandiant on APT42](https://mandiant.com/resources/blog/apt42-charms-cons-compromises), we can write the following the rule which can be used to cluster further samples:
```
import "pe"
import "hash"

rule APT42_CHAIRSMACK_PE_Metadata {
    meta:
        description = "Detects samples of CHAIRSMACK based on unique PE metadata (i.e. imphash and rich PE header hash)"
        reference = "https://mandiant.com/resources/blog/apt42-charms-cons-compromises"
        hash = "a37a290863fe29b9812e819e4c5b047c44e7a7d7c40e33da6f5662e1957862ab"

    condition:
        pe.imphash() == "72f60d7f4ce22db4506547ad555ea0b1" or 
        hash.md5(pe.rich_signature.clear_data) == "c0de41e45352714500771d43f0d8c4c3"
}
```

[I've written a script](https://github.com/BitsOfBinary/yarabuilder-examples/blob/main/pe/yarabuilder_pe.py) that can generate rules from these values (making use of [pefile](https://github.com/erocarrera/pefile) which makes this parsing very straightforward!), and you can also get these values from other platforms that parse files, such as VirusTotal, AlienVault, MalwareBazaar, and so on!

So next time you are about to write some rules for a PE binary, use the imphash and rich header hash for some quick and easy rules! These shouldn't be intended to replace more rigorous rules (i.e. based on strings, code segments, anomalies, etc.), but can build in some redundancy into your detection capabilities. 

## Disclaimer
As always with YARA rules, test to make sure your rules behave as expected! Blindly using an imphash or rich header hash might get you lots of false positives. E.g., the [imphash for a .NET PE binary](https://twitter.com/cyb3rops/status/1511725863414419459) (`f34d5f2d4577ed6d9ceec516c1f5a744`) will be the same across many different files, due to them all importing the same library (`mscoree.dll`) and the same function from that library (`_CorExeMain`).