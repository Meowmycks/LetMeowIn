# LetMeowIn
A sophisticated, covert LSASS dumper using C++ and MASM x64.

## Disclaimer
Don't be evil with this. I created this tool to learn. I'm not responsible if the Feds knock on your door.

Historically was able to (and may presently still) bypass
  - Windows Defender
  - Malwarebytes Anti-Malware
  - CrowdStrike Falcon EDR

![image](https://github.com/Meowmycks/LetMeowIn/assets/45502375/fb99f6e3-abb4-4beb-9130-dfbc550e1abe)

## Features
Avoids detection by using various means, such as:
  - Manually implementing NTAPI operations through indirect system calls
  - Disabling telemetry features (e.g. ETW and other EDR hooks)
  - Polymorphism through compile-time hash generation
  - Obfuscating API function names and pointers
  - Duplicating existing LSASS handles instead of opening new ones
  - Creating offline copies of the LSASS process to perform memory dumps on
  - Corrupting the `MDMP` signature of dropped files
  - Probably other stuff I forgot to mention here

## Negatives
  - Tools like Moneta and pe-sieve64 will detect changes made to NTDLL.dll from unhooking
  - Only works on x64 architecture
  - Don't expect this to be undetectable forever 🙂
