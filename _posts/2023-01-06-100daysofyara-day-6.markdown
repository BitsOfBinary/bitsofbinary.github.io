---
layout: post
title: "100 Days of YARA - Day 6"
date: 2023-01-06 00:00:00 -0000
categories: yara
---

# Installing YARA with the LNK module
The LNK is currently not included by default with YARA; at the time of writing, it is still awaiting approval to be merged in via a pull request on GitHub.

As such, if you want to test out the LNK module, you'll need to:
- Clone the LNK module branch from here: [https://github.com/BitsOfBinary/yara/tree/lnk-module](https://github.com/BitsOfBinary/yara/tree/lnk-module)
- Follow the instructions in the docs to install YARA: [https://yara.readthedocs.io/en/stable/gettingstarted.html](https://yara.readthedocs.io/en/stable/gettingstarted.html)

The rough set of commands you'll need to run if installing on Linux are as follows:
```
sudo apt-get install automake libtool make gcc pkg-config flex bison
./bootstrap.sh
./configure
make
sudo make install
```

You can optionally run `make check` to see if all the tests pass for YARA as well, although if you're able to run `yara --help` at this stage as see output then you'll know it has compiled and installed correctly!

The LNK module is available for any operating system, so you can compile it as normal for Linux/macOS, or use the Visual Studio projects to build it for Windows. [@r0ny_123](https://twitter.com/r0ny_123) also pointed out to me that you can grab Windows binaries from the AppVeyor builds (i.e. part of the regular CI/CD applied to YARA), e.g.: [https://ci.appveyor.com/project/plusvic/yara/build/job/wthlb30bklmlns0a/artifacts](https://ci.appveyor.com/project/plusvic/yara/build/job/wthlb30bklmlns0a/artifacts)

You can test if it the LNK module itself is working properly by trying to run the following rule and making sure there are no errors:
```
import "lnk"

rule test {
    condition:
        filesize > 0
}
```

The branch that the LNK module is on will install it by default, so you don't need to add any flags to `configure` when compiling YARA.

I'm aiming to keep the LNK module branch up to date with the [main branch of YARA](https://github.com/VirusTotal/yara), so all other features of YARA will be available if you compile the LNK module branch!

## Troubleshooting
Let me know if you have any issues installing the module. Personally I've found that when compiling via WSL on Windows that the `./bootstrap.sh` command doesn't work as expected, but if I manually run the command inside the script file, that is `autoreconf --force --install`, then it works as expected!

## Any feedback on the module?
If you have any feedback on the module (whether suggestions for how it could be used, support for it being merged in, etc.) please feel free to drop a comment on the open pull request on GitHub!

I hope that the module will be merged in by default into YARA one day (or at least, optionally available when compiling YARA from source).