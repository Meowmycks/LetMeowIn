# LetMeowIn
A sophisticated, covert LSASS dumper using C++ and MASM x64.

As seen on [Binary Defense](https://www.binarydefense.com/resources/blog/letmeowin-analysis-of-a-credential-dumper/) and [Cyber Security News](https://cybersecuritynews.com/researchers-detailed-letmeowin-credentials/)

## Disclaimer
Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

----------------------------------------------------------------------------------------------------------

Historically was able to (and may presently still) bypass
  - Windows Defender
  - Malwarebytes Anti-Malware
  - CrowdStrike Falcon EDR (Falcon Complete + OverWatch)
  - Palo Alto Cortex xDR*
    *(When combined with strong initial access methods)

![image](https://github.com/Meowmycks/LetMeowIn/assets/45502375/fb99f6e3-abb4-4beb-9130-dfbc550e1abe)

## Features
Avoids detection by using various means, such as:
  - Manually implementing NTAPI operations through indirect system calls
  - ~~Disabling~~ Breaking telemetry features (i.e ETW)
  - Polymorphism through compile-time hash generation
  - Obfuscating API function names and pointers
  - Duplicating existing LSASS handles instead of opening new ones
  - Creating offline copies of the LSASS process to perform memory dumps on
  - Corrupting the `MDMP` signature of dropped files
  - Probably other stuff I forgot to mention here

## Negatives
  - Only works on x64 architecture
  - Relies on there being [existing opened LSASS handles](https://itm4n.github.io/lsass-runasppl/#technique-3--python--katz) on target systems 
  - Don't expect this to be undetectable forever 🙂
