---
layout: post
title: "100 Days of YARA - Day 9"
date: 2023-01-09 00:00:00 -0000
categories: yara
---

# Checking LNK Timestamps
LNKs have three timestamps in their headers: creation time, access time, and write time. All of these are timestamps are in the [FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime) structure format, but for ease of use the LNK module converts them to Unix timestamps (e.g. to make them compatible with the [time module](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)).

![LNK timestamps](/assets/2023-01-09_lnk_timestamps.png)

As such, you can write rules based on these timestamps for a variety of purposes, such as:
- Clustering LNK files with the same timestamps
- Looking for anomalies in LNK timestamps

For example, the following rule will look for an LNK file that has supposedly been created after it has been accessed/last been written to:
```
import "lnk"

rule Heuristic_LNK_Created_After_Access_or_Write {
    meta:
        description = "Detects an LNK file with a creation timestamp later than that of its access/write timestamp"
        
    condition:
        lnk.creation_time > lnk.access_time or
        lnk.creation_time > lnk.write_time
}
```

And here's another one that finds LNK files that have been created in the future:
```
import "lnk"
import "time"

rule Heuristic_LNK_Created_in_Future {
    meta:
        description = "Detects LNK files with a creation timestamp in the future"
        
    condition:
        lnk.creation_time > time.now()
}
```

Or maybe, you want to look for LNKs where the timestamp has been removed:
```
import "lnk"

rule Heuristic_LNK_Empty_Timestamp {
    meta:
        description = "Detects an LNK file with a creation/write/access timestamp that has been zero'ed out"
        
    condition:
        lnk.creation_time == 0 or
        lnk.write_time == 0 or
        lnk.access_time == 0
}
```

This last rule can be written in pure YARA as follows:
```
rule Heuristic_LNK_Zeroed_Header_Timestamp {
    meta:
        description = "Detects an LNK file with a creation/write/access timestamp that has been zeroed out"
        
    condition:
        uint32(0) == 0x0000004C and
        uint32(4) == 0x00021401 and
        uint32(8) == 0x00000000 and
        uint32(12) == 0x000000C0 and
        uint32(16) == 0x46000000 and
        (
            // Creation timestamp
            (
                uint32(28) == 0 and uint32(32) == 0
            ) or
            // Access timestamp
            (
                uint32(36) == 0 and uint32(40) == 0
            ) or
            // Write timestamp
            (
                uint32(44) == 0 and uint32(48) == 0
            )
        )
}
```
This is possible to do due to the fixed offsets in the LNK header, but makes for a more verbose rule!

(EDIT: it actually looks fairly common that LNKs will have no timestamps; go figure!)

## Think about timestamps in different ways
Timestamp anomalies can lead to some really interesting rules! For example, check out [Costin Raiu's](https://twitter.com/craiu) slides from a [presentation on writing good YARA rules](https://www.slideshare.net/KasperskyLabGlobal/upping-the-apt-hunting-game-learn-the-best-yara-practices-from-kaspersky), where slides 48-50 describe how it is possible to track TripleFantasy based on an impossible timestamp in a PE.

Maybe there are more possibilities to create YARA rules for LNKs based on strange timestamp features? Have a go if you've got an idea!