---
layout: post
title: "100 Days of YARA - Day 8"
date: 2023-01-08 00:00:00 -0000
categories: yara
---

# Testing if a file is an LNK
Let's start with a straightforward rule: determining whether a file is an LNK in the first place. This is possible due to the LNK file header size and CLSID being fixed values:
![From the LNK docs](/assets/2023-01-08_shell_lnk_header_and_clsid.png)

If you are doing this with "pure" YARA, the rule would look like this:
```
rule is_lnk {
    condition:
        uint32(0) == 0x0000004C and
        uint32(4) == 0x00021401 and
        uint32(8) == 0x00000000 and
        uint32(12) == 0x000000C0 and
        uint32(16) == 0x46000000
}
```

If you're unfamiliar with the syntax used, YARA has a variety of operators to compare byte values at specific offsets in a file. These come in the form of the `int` and `uint` operators (which are both signed and unsigned respectively), and are available for 8-bit, 16-bit and 32-bit values. Later versions of YARA have also added big endian versions of these operators, so the first line of the condition of this rule could also be written as `uint32be(0) == 0x4C000000`.

As such, it is possible to determine whether a file is an LNK using this method, but requires you to go and read the LNK docs/keep a copy of this condition somewhere for use each time (plus it's a little verbose if you're replicating it across many rules).

With the LNK module, this same rule reduces to:
```
import "lnk"

rule is_lnk {
    condition:
        lnk.is_lnk
}
```

The `lnk.is_lnk` variable is a boolean value, set to `1` if the file being scanned is an LNK, and `0` if it isn't. As such, just validating that this value is true is enough to determine whether you're scanning an LNK or not!

(**Note**: you don't need to do `lnk.is_lnk == true`, as it is implicitly checking if it is true)

## Aside - Thoughts on file header validation
If you've been following #100DaysofYARA so far and seen [@greglesnewich's](https://twitter.com/greglesnewich) LNK rules, you'll notice that he does the check `uint32be(0x0) == 0x4C000000` to see if a file is an LNK.

I can't think of any cases where this won't be sufficient! Files starting with those 4 bytes are almost certainly going to be LNKs. It's similar to how a lot of us will write `uint16(0) == 0x5A4D` to check that a file is a PE; we're not actually checking the PE header or even validating the rest of the header itself, but just seeing the `MZ` string at the start is enough for us.

Checking both the header size and CLSID is a bit overkill for a rule's condition I will admit. However, if you want the assurance of the full header being present, then I think `lnk.is_lnk` is a lot more concise than the five `uint32` checks required.