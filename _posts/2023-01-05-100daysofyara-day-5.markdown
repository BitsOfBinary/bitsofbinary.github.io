---
layout: post
title: "100 Days of YARA - Day 5"
date: 2023-01-05 00:00:00 -0000
categories: yara
---

# Introducing the YARA LNK module
The [Windows Shell Link file format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) (or LNK) has been used by threat actors for years for malicious purposes (reference: [https://attack.mitre.org/techniques/T1204/001/](https://attack.mitre.org/techniques/T1204/001/))! Whether to download a next-stage payload, or set persistence on an infected system, the LNK file format can be quite versatile. It has also seen an uptick in use as part of initial infection chains due to Microsoft [disabling macros by default from documents downloaded from the internet](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked).

With all this combined, I wanted to [put together a YARA module for LNK files](https://github.com/VirusTotal/yara/pull/1732) to aid defenders in being able to triage, parse, and detect them.

The next few weeks of posts will go into detail of how to use the module, and some rules that are possible to write using it. Along the way, we'll hopefully learn some cool features of the LNK file format that will be useful to consider in general (check out [Greg Lesnewich's](https://twitter.com/greglesnewich) **#100DaysofYARA** contributions so far [to see some cool LNK rules](https://github.com/g-les/100DaysofYARA/blob/main/100DaysofYARA_2023_Week1_LNKPark.ipynb)).

## Shoutouts
I wouldn't have been able to write this module without being able to see the source code of other YARA modules, and through the variety of currently available LNK parsers to help validate my output (such as [exiftool](https://exiftool.org/TagNames/LNK.html) or [Silas Cutler's](https://twitter.com/silascutler) [LnkParse](https://github.com/silascutler/LnkParse) Python module).

Also shoutouts to [Ollie Whitehouse](https://twitter.com/ollieatnowhere) who gave me some great tips [to avoid bugs in my C code](https://twitter.com/ollieatnowhere/status/1556554996866596865) (which was very much needed!), and [Wesley Shields](https://twitter.com/wxs) for an early tip to make sure [I didn't do silly things dereferencing pointers in C](https://twitter.com/wxs/status/1483544341272576009).

And of course, shoutout to [Victor Alvarez](https://twitter.com/plusvic) and all the YARA maintainers for creating and developing this awesome tool!

## Acknowledgments
While I think the LNK module will give a great deal of flexibility to writing YARA rules for LNK files, a great deal of work has already done by others to write rules for LNKs! Please go check out rules from the following authors:
- Bart (@bartblaze): [https://github.com/bartblaze/Yara-rules/blob/master/rules/generic/LNK_Ruleset.yar](https://github.com/bartblaze/Yara-rules/blob/master/rules/generic/LNK_Ruleset.yar)
- Florian Roth (@cyb3rops): [https://github.com/Neo23x0/signature-base/blob/05ef26965be930fade49e5dcba73b9fefc04757e/yara/gen_susp_lnk_files.yar](https://github.com/Neo23x0/signature-base/blob/05ef26965be930fade49e5dcba73b9fefc04757e/yara/gen_susp_lnk_files.yar)

If you know of any other open source LNK YARA rulesets, please give me a shout and I can update this page with them! Check out the repo set up for **#100DaysofYARA** to see some further LNK rules available as well: [https://github.com/100DaysofYARA/2023](https://github.com/100DaysofYARA/2023)