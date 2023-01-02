---
layout: post
title: "100 Days of YARA - Day 2"
date: 2023-01-02 00:00:00 -0000
categories: yara
---

# YARA Modules
YARA is primarily designed to be used for efficient string matching (which it does very well). But one of its most powerful features (in my opinion) is the ability to create and use [modules](https://yara.readthedocs.io/en/stable/modules.html). These can be used for file parsing (such as [PE](https://yara.readthedocs.io/en/stable/modules/pe.html), [ELF](https://yara.readthedocs.io/en/stable/modules/elf.html) or [.NET](https://yara.readthedocs.io/en/stable/modules/dotnet.html) binaries), utility functions to aid in writing rules (such as [hashing algorithms](https://yara.readthedocs.io/en/stable/modules/hash.html), or [maths functions](https://yara.readthedocs.io/en/stable/modules/math.html)), to help debug your rules (e.g. via the [console module](https://yara.readthedocs.io/en/stable/modules/console.html)), or anything you can think of that can be written in C using YARA's API!

![Available YARA modules](/assets/2023-01-02_default_yara_modules.png "Available YARA modules")

Personally, I find myself using the PE module the most, which also happens to be the most built out default YARA module. I highly recommend reading through its documentation to see what it can do, and if there's something missing then raise an issue on GitHub! There are many active contributors to YARA who will be willing to try and implement it.

I'll give some example rules using the PE module over the next couple of days to give some inspiration for how they can be used!