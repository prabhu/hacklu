# Introduction

This document discusses the steps involved in computing and analysing the slices for ffmpeg using atom, blint, and dosai.

## Pre-requisites

- Java >= 21
- Python >= 3.10
- Install [atom >= 2.4.2](https://github.com/AppThreat/atom/releases/tag/v2.4.2)
- Install [blint >= 3.0.2](https://github.com/owasp-dep-scan/blint?tab=readme-ov-file#installation)
- Install [dosai >= 2.0.3](https://github.com/owasp-dep-scan/dosai/releases/tag/v2.0.3) - optional for dotnet analysis
- LLVM@18

## Slices creation

### Download ffmpeg source

```
git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg --depth=1
```

### Generate or download atom

To generate atom for ffmpeg from scratch:

```shell
atom.sh reachables -l c -o c-app.atom -s reachables.slices.json <ffmpeg directory>
```

This step would take a while and needs > 40GB memory!

Alternatively, download from [HuggingFace](https://huggingface.co/datasets/AppThreat/ukaina/tree/main/c/ffmpeg).

### Generate blint metadata

Compile ffmpeg.

```
cd ffmpeg
./configure
make
```

```
pip install blint[extended]
blint -i <ffmpeg directory> -o <reports directory> --disassemble .
```

Use the container image when faced with llvm or nyxstone related issues.

```
nerdctl pull ghcr.io/owasp-dep-scan/blint:latest
# docker pull ghcr.io/owasp-dep-scan/blint:latest
```

## blint metadata analysis

Let's focus on a method: `av_bprint_append_data`

### assembly logic

Prepare for copy operation

load base address to x9

```
ldr x9, [x19]
```

Add value in register x9 to the value in w8.

```
add x0, x9, w8, uxtw
```

Compare and branch if zero

```
cbz w9, #24
```

Calls function to append data into the buffer at the calculated address:

```
bl #977392
```

NOTE: Help improve [blint](https://github.com/owasp-dep-scan/blint/pulls) to resolve and track this call under [direct_calls](https://github.com/owasp-dep-scan/blint/blob/main/docs/DISASSEMBLE.md)!

From ffmpeg-metadata.json (aarch64-apple)

```
"0x100e5b9a4::_av_bprint_append_data": {
    "name": "_av_bprint_append_data",
    "address": "0x100e5b9a4",
    "assembly": "stp x28, x27, [sp, #-96]!\nstp x26, x25, [sp, #16]\nstp x24, x23, [sp, #32]\nstp x22, x21, [sp, #48]\nstp x20, x19, [sp, #64]\nstp x29, x30, [sp, #80]\nmov x20, x2\nmov x21, x1\nmov x19, x0\nldp w24, w28, [x0, #8]\nsubs w8, w28, w24\ncsel w25, wzr, w8, lo\ncmp w25, w2\nb.ls #132\nmov x8, x24\nmov x22, x28\ncmp w22, w24\nb.ls #36\nsub w9, w25, #1\ncmp w9, w20\ncsel w2, w9, w20, lo\nldr x9, [x19]\nadd x0, x9, w8, uxtw\nmov x1, x21\nbl #977392\nldr w8, [x19, #8]\nmov w9, #-6\nsub w9, w9, w8\ncmp w9, w20\ncsel w9, w9, w20, lo\nadd w8, w9, w8\nstr w8, [x19, #8]\nldr w9, [x19, #12]\ncbz w9, #24\nldr x10, [x19]\nsub w9, w9, #1\ncmp w8, w9\ncsel w8, w8, w9, lo\nstrb wzr, [x10, w8, uxtw]\nldp x29, x30, [sp, #80]\nldp x20, x19, [sp, #64]\nldp x22, x21, [sp, #48]\nldp x24, x23, [sp, #32]\nldp x26, x25, [sp, #16]\nldp x28, x27, [sp], #96\nret\nadd x26, x19, #20\nmov w27, #-2\nb #40\nstr x0, [x19]\nstr w22, [x19, #12]\nldr w24, [x19, #8]\nsubs w8, w22, w24\ncsel w25, wzr, w8, lo\nmov x28, x22\nmov x8, x24\ncmp w25, w20\nb.hi #-164\ncmp w24, w28\nb.hs #-180\nldr w8, [x19, #16]\ncmp w28, w8\nb.eq #-192\nsub w9, w27, w24\ncmp w9, w20\ncsel w9, w9, w20, lo\nadd w9, w24, w9\nadd w10, w9, #1\nlsl w11, w28, #1\ncmp w28, w8, lsr #1\ncsel w11, w8, w11, hi\ncmp w8, w10\ncsinc w8, w8, w9, lo\ncmp w11, w10\ncsel w22, w8, w11, lo\nldr x8, [x19]\ncmp x8, x26\ncsel x23, xzr, x8, eq\nmov x0, x23\nmov x1, x22\nbl #114316\ncbz x0, #36\ncbnz x23, #-132\nldr x1, [x19]\nldr w8, [x19, #8]\nadd w2, w8, #1\nmov x23, x0\nbl #977140\nmov x0, x23\nb #-160\nldr w8, [x19, #8]\nb #-304",
    "assembly_hash": "29d168d58cf1ee77e82ec1a5e6c86dc745e928a252a2582babd34bb9fb700cef",
    "instruction_hash": "3490d4389f6c982ef20e762c4b757ef4395ef2658add903b610d2c8a9b84ba7f",
    "instruction_count": 46,
    "instruction_metrics": {
        "call_count": 1,
        "conditional_jump_count": 1, // <----
        "xor_count": 0,
        "shift_count": 0,
        "arith_count": 5,
        "ret_count": 1,
        "jump_count": 0,
        "simd_fpu_count": 0,
        "unique_regs_read_count": 20,
        "unique_regs_written_count": 23
    },
    "direct_calls": [],
    "has_indirect_call": false,
    "has_system_call": false,
    "has_security_feature": false,
    "has_crypto_call": false,
    "has_gpu_call": false,
    "has_loop": false,
    "regs_read": [
      "sp",
      "w2",
      "w20",
      "w22",
      "w24",
      "w25",
      "w28",
      "w8",
      "w9",
      "wzr",
      "x0",
      "x1",
      "x10",
      "x19",
      "x2",
      "x21",
      "x24",
      "x28",
      "x30",
      "x9"
  ],
  "regs_written": [
      "w2",
      "w24",
      "w25",
      "w28",
      "w8",
      "w9",
      "x0",
      "x1",
      "x10",
      "x19",
      "x20",
      "x21",
      "x22",
      "x23",
      "x24",
      "x25",
      "x26",
      "x27",
      "x28",
      "x29",
      "x30",
      "x8",
      "x9"
  ],
  "used_simd_reg_types": [],
  "instructions_with_registers": [
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x27",
              "x28"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x25",
              "x26"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x23",
              "x24"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x21",
              "x22"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x19",
              "x20"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x29",
              "x30"
          ]
      },
      {
          "regs_read": [
              "x2"
          ],
          "regs_written": [
              "x20"
          ]
      },
      {
          "regs_read": [
              "x1"
          ],
          "regs_written": [
              "x21"
          ]
      },
      {
          "regs_read": [
              "x0"
          ],
          "regs_written": [
              "x19"
          ]
      },
      {
          "regs_read": [
              "x0"
          ],
          "regs_written": [
              "w24",
              "w28"
          ]
      },
      {
          "regs_read": [
              "w24",
              "w28"
          ],
          "regs_written": [
              "w8"
          ]
      },
      {
          "regs_read": [
              "w8",
              "wzr"
          ],
          "regs_written": [
              "w25"
          ]
      },
      {
          "regs_read": [
              "w2",
              "w25"
          ],
          "regs_written": []
      },
      {
          "regs_read": [],
          "regs_written": []
      },
      {
          "regs_read": [
              "x24"
          ],
          "regs_written": [
              "x8"
          ]
      },
      {
          "regs_read": [
              "x28"
          ],
          "regs_written": [
              "x22"
          ]
      },
      {
          "regs_read": [
              "w22",
              "w24"
          ],
          "regs_written": []
      },
      {
          "regs_read": [],
          "regs_written": []
      },
      {
          "regs_read": [
              "w25"
          ],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w20",
              "w9"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "w20",
              "w9"
          ],
          "regs_written": [
              "w2"
          ]
      },
      {
          "regs_read": [
              "x19"
          ],
          "regs_written": [
              "x9"
          ]
      },
      {
          "regs_read": [
              "w8",
              "x9"
          ],
          "regs_written": [
              "x0"
          ]
      },
      {
          "regs_read": [
              "x21"
          ],
          "regs_written": [
              "x1"
          ]
      },
      {
          "regs_read": [],
          "regs_written": [
              "x30"
          ]
      },
      {
          "regs_read": [
              "x19"
          ],
          "regs_written": [
              "w8"
          ]
      },
      {
          "regs_read": [],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w8",
              "w9"
          ],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w20",
              "w9"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "w20",
              "w9"
          ],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w8",
              "w9"
          ],
          "regs_written": [
              "w8"
          ]
      },
      {
          "regs_read": [
              "w8",
              "x19"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "x19"
          ],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w9"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "x19"
          ],
          "regs_written": [
              "x10"
          ]
      },
      {
          "regs_read": [
              "w9"
          ],
          "regs_written": [
              "w9"
          ]
      },
      {
          "regs_read": [
              "w8",
              "w9"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "w8",
              "w9"
          ],
          "regs_written": [
              "w8"
          ]
      },
      {
          "regs_read": [
              "wzr",
              "x10"
          ],
          "regs_written": []
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x29",
              "x30"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x19",
              "x20"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x21",
              "x22"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x23",
              "x24"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x25",
              "x26"
          ]
      },
      {
          "regs_read": [
              "sp"
          ],
          "regs_written": [
              "x27",
              "x28"
          ]
      },
      {
          "regs_read": [
              "x30"
          ],
          "regs_written": []
      }
    ],
    "function_type": "Has_Conditional_Jumps", // <----
    "proprietary_instructions": [],
    "sreg_interactions": []
}
```

## YARA rules

### Rule: Detect obfuscation using xor count

```yara
rule Blint_Potential_Obfuscation_HighXor
{
    meta:
        description = "Detects functions that may be using obfuscation techniques by having an unusually high number of XOR instructions."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            func.instruction_metrics.xor_count > 5 and func.instruction_count > 10
}
```

### Rule: Malware evasion with indirect and syscall

```yara
rule Blint_Malware_Evasion_IndirectAndSyscalls
{
    meta:
        description = "Identifies functions that use both indirect calls and system calls, a common pattern in malware for evasion and stealth."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            func.has_indirect_call and func.has_system_call
}
```

### Rule: Windows suspicious calls

```yara
rule Blint_Windows_API_SuspiciousCalls
{
    meta:
        description = "Finds functions that directly call a list of suspicious or high-risk Windows APIs, often used for process injection, memory allocation, and file manipulation."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            any of ("VirtualAlloc*", "CreateProcess*", "WriteFile", "SetWindowsHookEx", "CreateRemoteThread") in func.direct_calls
}
```

### Rule: Potential buffer overflow

```yara
rule Blint_Potential_BufferOverflow_Strcpy
{
    meta:
        description = "Detects potential buffer overflow vulnerabilities by finding functions that call known unsafe string functions like 'strcpy'. This rule combines symbol table data with disassembly."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        any sym in (blint.symtab_symbols) where (
            sym.name contains "strcpy" or
            sym.name contains "strcat" or
            sym.name contains "gets"
        ) and (
            any func in (blint.disassembled_functions) where (
                func.address == sym.address and
                func.function_type != "PLT_Thunk"
            )
        )
}
```

### Rule: Potential crypto mining

```yara
rule Blint_Crypto_Operation_Monitoring
{
    meta:
        description = "Flags functions that contain cryptographic instruction patterns, which could indicate ransomware, packers, or legitimate crypto libraries."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            func.has_crypto_call
}
```

### Rule: Apple silicon security feature usage

```yara
rule Blint_AppleSilicon_HighSecurityFeatures
{
    meta:
        description = "Identifies functions on Apple Silicon that interact with proprietary high-security hardware features like SPRR, PAC, or GXF. Useful for security research on macOS/iOS."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            any of ("SPRR_CONTROL", "PAC_KEYS", "GXF_CONTROL") in func.sreg_interactions
}
```

### Rule: Leaf functions to triage based on register usage

```
rule Blint_RegisterUsage_AnomalousPattern
{
    meta:
        description = "Detects functions with an unusual register usage pattern, such as reading from a register used for arguments (rdi) without writing to it."
        author = "Team AppThreat"
        date = "2025-10-18"
    condition:
        for any func in (blint.disassembled_functions):
            "rdi" in func.regs_read and
            "rdi" not in func.regs_written and
            func.instruction_metrics.call_count == 0
}
```

### Rule: Detect suspicious dotnet API

```
rule DotNet_Suspicious_API_Usage
{
    meta:
        description = "Detects usage of suspicious APIs in .NET assemblies"
        author = "Team AppThreat"
        reference = "Dosai JSON Analysis"
        date = "2025-10-18"

    strings:
        $process_start = /"CalledMethod":\s*"System\.Diagnostics\.Process\.Start"/
        $process_create = /"CalledMethod":\s*"System\.Diagnostics\.Process\.Create"/
        $file_write = /"CalledMethod":\s*"System\.IO\.File\.WriteAllText"/
        $file_read = /"CalledMethod":\s*"System\.IO\.File\.ReadAllText"/
        $file_delete = /"CalledMethod":\s*"System\.IO\.File\.Delete"/
        $registry_key = /"CalledMethod":\s*"Microsoft\.Win32\.Registry\.Key"/
        $web_request = /"CalledMethod":\s*"System\.Net\.WebRequest\.Create"/
        $socket_connect = /"CalledMethod":\s*"System\.Net\.Sockets\.Socket\.Connect"/
        $crypto_encrypt = /"CalledMethod":\s*"System\.Security\.Cryptography\.SymmetricAlgorithm\.CreateEncryptor"/
        $crypto_decrypt = /"CalledMethod":\s*"System\.Security\.Cryptography\.SymmetricAlgorithm\.CreateDecryptor"/
        $reflection_load = /"CalledMethod":\s*"System\.Reflection\.Assembly\.LoadFrom"/
        $reflection_create = /"CalledMethod":\s*"System\.Activator\.CreateInstance"/

    condition:
        any of them
}
```

### Rule: Detect dotnet anti-analysis techniques

```
rule DotNet_Anti_Analysis_Techniques
{
    meta:
        description = "Detects anti-analysis techniques in .NET assemblies"
        author = "Team AppThreat"
        reference = "Dosai JSON Analysis"
        date = "2025-10-18"

    strings:
        $debugger_check = /"CalledMethod":\s*"System\.Diagnostics\.Debugger\.IsAttached"/
        $debugger_break = /"CalledMethod":\s*"System\.Diagnostics\.Debugger\.Break"/
        $vm_check = /"CalledMethod":\s*"System\.Management\.ManagementObjectSearcher"/
        $timing_check = /"CalledMethod":\s*"System\.Diagnostics\.Stopwatch\.GetTimestamp"/
        $sandbox_check = /"CalledMethod":\s*"System\.Windows\.Forms\.Screen\.AllScreens"/

    condition:
        any of them
}
```

## Interactive source analysis with chennai

Download chennai [distribution](https://github.com/AppThreat/chen/releases/tag/v2.5.5) or container [image](https://github.com/AppThreat/chen?tab=readme-ov-file#interactive-console).

Set the environment variable `SCALAPY_PYTHON_LIBRARY` for local installations as per [README](https://github.com/AppThreat/chen?tab=readme-ov-file#commands-throw-errors-in-chennai-console).

```
❯ ./chennai -J-Xms16g -J-Xmx40g
 _                          _   _   _   _  __
/  |_   _  ._  ._   _. o   |_  / \ / \ / \  / |_|_
\_ | | (/_ | | | | (_| |   |_) \_/ \_/ \_/ /    |

Version: 2.5.1


chennai> importAtom("/Users/prabhu/sandbox/ffmpeg/c-app.atom")
         Atom Summary
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Node Type        ┃ Count   ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Files            │ 4271    │
│ Methods          │ 65085   │
│ Annotations      │ 0       │
│ Imports          │ 25918   │
│ Literals         │ 1884737 │
│ Config Files     │ 1       │
│ Validation tags  │ 6262    │
│ Unique packages  │ 0       │
│ Framework tags   │ 54      │
│ Framework input  │ 54      │
│ Framework output │ 0       │
│ Crypto tags      │ 0       │
│ Overlays         │ 5       │
└──────────────────┴─────────┘
```

```
chennai> atom.method("av_bprint_append_data").call.methodFullName.toSet
val res0: Set[String] = HashSet(
  "<operator>.indirectFieldAccess",
  "av_bprint_grow",
  "libavutil/bprint.c:33:33:av_bprint_room:0",
  "<operator>.lessThan",
  "<operator>.greaterThan",
  "<operator>.assignment",
  "<operator>.subtraction",
  "<operator>.addition",
  "av_bprint_alloc",
  "memcpy",
  "libavutil/macros.h:49:49:FFMIN:0",
  "<operator>.conditional"
)
```

```
chennai> atom.method("av_bprint_append_data").call.filterNot(_.methodFullName.startsWith("<operator>")).methodFullName.toSet
val res1: Set[String] = HashSet(
  "av_bprint_grow",
  "libavutil/bprint.c:33:33:av_bprint_room:0",
  "libavutil/macros.h:49:49:FFMIN:0",
  "av_bprint_alloc",
  "memcpy"
)
```

```
chennai> callTree("av_bprint_append_data")
val res2: scala.collection.mutable.ListBuffer[String] = ListBuffer(
  "av_bprint_append_data",
  "|    +--- av_bprint_grow~~libavutil/bprint.c#60",
  "+--- libavutil/macros.h:49:49:FFMIN:0~~libavutil/macros.h#49",
  "+--- libavutil/macros.h:49:49:FFMIN:0~~libavutil/macros.h#49",
  "+--- memcpy~~/usr/include/string.h#43",
  "+--- memcpy~~/usr/include/string.h#43",
  "+--- memcpy~~/usr/include/string.h#43",
  "+--- memcpy~~/usr/include/string.h#43",
  "+--- memcpy~~/usr/include/string.h#43",
  "+--- libavutil/bprint.c:33:33:av_bprint_room:0~~libavutil/bprint.c#33",
  "+--- av_bprint_alloc~~libavutil/bprint.c#36",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.c#155",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~tools/coverity.c#72",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_realloc~~libavutil/mem.h#180",
  "|    +--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- realloc~~/usr/include/stdlib.h#683",
  "+--- /usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h:141:148:atomic_load_explicit:0~~/usr/lib/gcc/x86_64-linux-gnu/13/include/stdatomic.h#141",
  "+--- NULL~~<empty>#0",
  "+--- __atomic_load~~<empty>#0",
  "+--- __coverity_negative_sink__~~<empty>#0",
  "+--- __coverity_escape__~~<empty>#0",
  "+--- __coverity_writeall__~~<empty>#0",
  "+--- __coverity_mark_as_afm_allocated__~~<empty>#0",
  "+--- __coverity_alloc__~~<empty>#0",
  "+--- av_bprint_is_complete~~libavutil/bprint.h#218",
  "|    +--- libavutil/macros.h:49:49:FFMIN:0~~libavutil/macros.h#49",
  "|    |    +--- NULL~~<empty>#0",
  "|    |    |    +--- memcpy~~/usr/include/string.h#43",
  "|    |    |    |    +--- memcpy~~/usr/include/string.h#43",
  "|    |    |    |    |    +--- memcpy~~/usr/include/string.h#43",
  "|    |    |    |    |    |    +--- memcpy~~/usr/include/string.h#43",
  "|    |    |    |    |    |    |    +--- memcpy~~/usr/include/string.h#43",
  "|    |    |    |    |    |    |    |    +--- libavutil/error.h:41:41:AVERROR:0~~libavutil/error.h#41",
  "|    |    |    |    |    |    |    |    |    +--- libavutil/error.h:61:61:AVERROR_INVALIDDATA:0~~libavutil/error.h#61",
  "|    |    |    |    |    |    |    |    |    |    +--- libavutil/macros.h:49:49:FFMIN:0~~libavutil/macros.h#49",
  "|    |    |    |    |    |    |    |    |    |    |    +--- libavutil/error.h:41:41:AVERROR:0~~libavutil/error.h#41",
  "|    |    |    |    |    |    |    |    |    |    |    |    +--- libavutil/macros.h:49:49:FFMIN:0~~libavutil/macros.h#49"
)
```

```
chennai> atom.method("realloc").callIn.argument.df(atom.method("av_bprint_append_data").parameter).t
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                   ┃ Method                                            ┃ Parameter              ┃ Tracked                                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavutil/bprint.c#148                                     │ av_bprint_append_data                             │ buf                    │ av_bprint_append_data                            │
│                                                            │                                                   │                        │                                                  │
│ libavutil/bprint.c#36                                      │ av_bprint_alloc                                   │ buf                    │ av_bprint_alloc                                  │
│                                                            │                                                   │                        │                                                  │
│ libavutil/bprint.h#218                                     │ av_bprint_is_complete                             │ buf                    │ av_bprint_is_complete                            │
│                                                            │                                                   │                        │                                                  │
│ libavutil/mem.c#155                                        │ av_realloc                                        │ size                   │ av_realloc                                       │
│                                                            │                                                   │                        │                                                  │
│ /usr/include/stdlib.h#683                                  │ realloc                                           │ __size                 │ realloc                                          │
│                                                            │                                                   │                        │                                                  │
└────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────┴────────────────────────┴──────────────────────────────────────────────────┘
                                                                                    Source: AVBPrint *buf
                                                                                       Sink: av_realloc
```

```
chennai> atom.tag("event").identifier.df(atom.tag("parse").parameter).t
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                ┃ Method                                           ┃ Parameter               ┃ Tracked                                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/whip.c#513                                  │ parse_codec                                      │ s                       │ parse_codec                                     │
│                                                         │ Tags: parse                                      │                         │                                                 │
│ libavformat/whip.c#596                                  │ generate_sdp_offer                               │ s                       │ generate_sdp_offer                              │
│                                                         │                                                  │                         │                                                 │
│ libavformat/whip.c#744                                  │ exchange_sdp                                     │ s                       │ exchange_sdp                                    │
│                                                         │                                                  │                         │                                                 │
│ libavformat/whip.c#863                                  │ parse_answer                                     │ s                       │ parse_answer                                    │
│                                                         │ Tags: parse                                      │                         │                                                 │
│ libavformat/whip.c#1210                                 │ udp_connect                                      │ s                       │ udp_connect                                     │
│                                                         │                                                  │                         │                                                 │
│ libavformat/whip.c#1248                                 │ ice_dtls_handshake                               │ s                       │ ice_dtls_handshake                              │
│                                                         │                                                  │                         │                                                 │
│ libavformat/whip.c#972                                  │ ice_create_request                               │ s                       │ ice_create_request                              │
│                                                         │                                                  │                         │                                                 │
│ libavformat/avio.c#365                                  │ ffurl_open_whitelist                             │ whitelist               │ ffurl_open_whitelist                            │
│                                                         │                                                  │                         │                                                 │
│ libavformat/whip.c#377                                  │ dtls_initialize                                  │ s                       │ dtls_initialize                                 │
│                                                         │                                                  │                         │                                                 │
│ libavformat/url.h#145                                   │ ffurl_open_whitelist                             │ blacklist               │ ffurl_open_whitelist                            │
│                                                         │                                                  │                         │                                                 │
└─────────────────────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┴─────────────────────────────────────────────────┘
                                                                                Source: AVFormatContext *s
                                                                                    Source Tags: parse
                                                                                 Sink: ice_dtls_handshake
                                                                                     Sink Tags: event

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                     ┃ Method                                        ┃ Parameter                ┃ Tracked                                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/wavdec.c#186                                     │ wav_parse_fmt_tag                             │ st                       │ wav_parse_fmt_tag                            │
│                                                              │ Tags: parse                                   │                          │                                              │
│ libavformat/wavdec.c#205                                     │ wav_parse_xma2_tag                            │ st                       │ wav_parse_xma2_tag                           │
│                                                              │ Tags: parse                                   │                          │                                              │
└──────────────────────────────────────────────────────────────┴───────────────────────────────────────────────┴──────────────────────────┴──────────────────────────────────────────────┘
                                                                                   Source: AVStream *st
                                                                                    Source Tags: parse
                                                                                 Sink: wav_parse_fmt_tag
                                                                                     Sink Tags: event
```

```
chennai> atom.method("cleanup.*").callIn.argument.isIdentifier.df(atom.method(".*decode.*").parameter).t
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                    ┃ Method                                            ┃ Parameter          ┃ Tracked                                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ fftools/ffplay.c#578                                        │ decoder_decode_frame                              │ frame              │ decoder_decode_frame                            │
│                                                             │                                                   │                    │                                                 │
│ libavutil/samplefmt.c#51                                    │ av_get_sample_fmt_name                            │ sample_fmt         │ av_get_sample_fmt_name                          │
│                                                             │                                                   │                    │                                                 │
│ fftools/ffplay.c#408                                        │ cmp_audio_fmts                                    │ fmt2               │ cmp_audio_fmts                                  │
│                                                             │                                                   │                    │                                                 │
│ libavutil/frame.c#523                                       │ av_frame_move_ref                                 │ src                │ av_frame_move_ref                               │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/buffersink.h#78                                 │ av_buffersink_get_frame_flags                     │ frame              │ av_buffersink_get_frame_flags                   │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/buffersrc.h#189                                 │ av_buffersrc_add_frame                            │ frame              │ av_buffersrc_add_frame                          │
│                                                             │                                                   │                    │                                                 │
│ fftools/ffplay.c#2015                                       │ configure_audio_filters                           │ is                 │ configure_audio_filters                         │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/avfilter.h#735                                  │ avfilter_graph_free                               │ graph              │ avfilter_graph_free                             │
│                                                             │                                                   │                    │                                                 │
│ libavutil/opt.h#869                                         │ av_opt_set                                        │ obj                │ av_opt_set                                      │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/avfilter.h#705                                  │ avfilter_graph_create_filter                      │ graph_ctx          │ avfilter_graph_create_filter                    │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/avfiltergraph.c#167                             │ avfilter_graph_alloc_filter                       │ graph              │ avfilter_graph_alloc_filter                     │
│                                                             │                                                   │                    │                                                 │
│ libavfilter/avfilter_internal.h#150                         │ fffiltergraph                                     │ graph              │ fffiltergraph                                   │
│                                                             │                                                   │                    │                                                 │
│ fftools/ffmpeg_filter.c#1921                                │ configure_filtergraph                             │ fg                 │ configure_filtergraph                           │
│                                                             │                                                   │                    │                                                 │
│ fftools/ffmpeg_filter.c#73                                  │ fgp_from_fg                                       │ fg                 │ fgp_from_fg                                     │
│                                                             │                                                   │                    │                                                 │
│ fftools/ffmpeg_filter.c#2158                                │ filtergraph_is_simple                             │ fg                 │ filtergraph_is_simple                           │
│                                                             │                                                   │                    │                                                 │
└─────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────┴────────────────────┴─────────────────────────────────────────────────┘
                                                                                  Source: AVFrame *frame
                                                                               Sink: configure_filtergraph

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                     ┃ Method                                          ┃ Parameter            ┃ Tracked                                        ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ fftools/ffplay.c#578                                         │ decoder_decode_frame                            │ d                    │ decoder_decode_frame                           │
│                                                              │                                                 │                      │                                                │
│ fftools/ffmpeg_filter.c#1886                                 │ cleanup_filtergraph                             │ fg                   │ cleanup_filtergraph                            │
│                                                              │                                                 │                      │                                                │
│ fftools/ffmpeg_filter.c#560                                  │ graph_parse                                     │ logctx               │ graph_parse                                    │
│                                                              │                                                 │                      │                                                │
│ fftools/ffmpeg_filter.c#1876                                 │ configure_input_filter                          │ fg                   │ configure_input_filter                         │
│                                                              │                                                 │                      │                                                │
└──────────────────────────────────────────────────────────────┴─────────────────────────────────────────────────┴──────────────────────┴────────────────────────────────────────────────┘
                                                                                    Source: Decoder *d
                                                                               Sink: configure_filtergraph
```

```
chennai> atom.method(".*whisper.*").callIn.argument.df(atom.tag("parse").parameter).t
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                                          ┃ Method                             ┃ Parameter                  ┃ Tracked                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavcodec/dolby_e.c#955                                                          │ parse_audio                        │ s1                         │ parse_audio                      │
│                                                                                   │ Tags: parse                        │                            │                                  │
│ libavfilter/vf_colorspace.c#727                                                   │ filter_frame                       │ link                       │ filter_frame                     │
│                                                                                   │                                    │                            │                                  │
│ libavfilter/af_whisper.c#159                                                      │ uninit                             │ ctx                        │ uninit                           │
│                                                                                   │                                    │                            │                                  │
└───────────────────────────────────────────────────────────────────────────────────┴────────────────────────────────────┴────────────────────────────┴──────────────────────────────────┘
                                                                               Source: DBEDecodeContext *s1
                                                                                    Source Tags: parse
                                                                                       Sink: uninit

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                            ┃ Method                                     ┃ Parameter               ┃ Tracked                                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavcodec/dolby_e.c#955                                            │ parse_audio                                │ s1                      │ parse_audio                               │
│                                                                     │ Tags: parse                                │                         │                                           │
│ libavfilter/af_whisper.c#287                                        │ filter_frame                               │ inlink                  │ filter_frame                              │
│                                                                     │                                            │                         │                                           │
│ libavfilter/af_whisper.c#185                                        │ run_transcription                          │ ctx                     │ run_transcription                         │
│                                                                     │                                            │                         │                                           │
└─────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────┴─────────────────────────┴───────────────────────────────────────────┘
                                                                               Source: DBEDecodeContext *s1
                                                                                    Source Tags: parse
                                                                                 Sink: run_transcription
```

```
chennai> atom.method(".*decode.*").callIn.argument.df(atom.method(".*parse.*").parameter).t
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                      ┃ Method                                                   ┃ Parameter         ┃ Tracked                                                 ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/utils.c#636                       │ ff_parse_opts_from_query_string                          │ str               │ ff_parse_opts_from_query_string                         │
│                                               │ Tags: parse                                              │                   │                                                         │
│ /usr/include/string.h#293                     │ strcspn                                                  │ __s               │ strcspn                                                 │
│                                               │                                                          │                   │                                                         │
│ libavformat/utils.c#626                       │ find_opt                                                 │ name              │ find_opt                                                │
│                                               │                                                          │                   │                                                         │
└───────────────────────────────────────────────┴──────────────────────────────────────────────────────────┴───────────────────┴─────────────────────────────────────────────────────────┘
                                                                                 Source: const char *str
                                                                                    Source Tags: parse
                                                                                      Sink: find_opt

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                        ┃ Method                                                  ┃ Parameter         ┃ Tracked                                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/utils.c#636                         │ ff_parse_opts_from_query_string                         │ str               │ ff_parse_opts_from_query_string                        │
│                                                 │ Tags: parse                                             │                   │                                                        │
│ libavformat/urldecode.c#99                      │ ff_urldecode_len                                        │ url               │ ff_urldecode_len                                       │
│                                                 │                                                         │                   │                                                        │
└─────────────────────────────────────────────────┴─────────────────────────────────────────────────────────┴───────────────────┴────────────────────────────────────────────────────────┘
                                                                                 Source: const char *str
                                                                                    Source Tags: parse
                                                                          Sink: ff_parse_opts_from_query_string

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                              ┃ Method                                             ┃ Parameter             ┃ Tracked                                           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/rtpdec.c#589                              │ ff_rtp_parse_set_crypto                            │ params                │ ff_rtp_parse_set_crypto                           │
│                                                       │ Tags: parse                                        │                       │                                                   │
│ libavformat/srtp.c#67                                 │ ff_srtp_set_crypto                                 │ params                │ ff_srtp_set_crypto                                │
│                                                       │                                                    │                       │                                                   │
└───────────────────────────────────────────────────────┴────────────────────────────────────────────────────┴───────────────────────┴───────────────────────────────────────────────────┘
                                                                                Source: const char *params
                                                                                    Source Tags: parse
                                                                                 Sink: ff_srtp_set_crypto

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                ┃ Method                                          ┃ Parameter                 ┃ Tracked                                        ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/rdt.c#414                                   │ rdt_parse_sdp_line                              │ line                      │ rdt_parse_sdp_line                             │
│                                                         │ Tags: parse                                     │                           │                                                │
│ libavformat/rdt.c#396                                   │ rdt_parse_b64buf                                │ p                         │ rdt_parse_b64buf                               │
│                                                         │ Tags: parse                                     │                           │                                                │
└─────────────────────────────────────────────────────────┴─────────────────────────────────────────────────┴───────────────────────────┴────────────────────────────────────────────────┘
                                                                                 Source: const char *line
                                                                                    Source Tags: parse
                                                                                  Sink: rdt_parse_b64buf

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                  ┃ Method                                             ┃ Parameter          ┃ Tracked                                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/oggparsevorbis.c#92                           │ vorbis_parse_single_comment                        │ size               │ vorbis_parse_single_comment                      │
│                                                           │ Tags: parse                                        │                    │                                                  │
│ /usr/include/string.h#107                                 │ memchr                                             │ __n                │ memchr                                           │
│                                                           │                                                    │                    │                                                  │
└───────────────────────────────────────────────────────────┴────────────────────────────────────────────────────┴────────────────────┴──────────────────────────────────────────────────┘
                                                                                  Source: uint32_t size
                                                                                    Source Tags: parse
                                                                            Sink: vorbis_parse_single_comment

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                           ┃ Method                                                ┃ Parameter          ┃ Tracked                                              ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/mccdec.c#211                           │ mcc_parse_time_code                                   │ tc                 │ mcc_parse_time_code                                  │
│                                                    │ Tags: parse                                           │                    │                                                      │
│ libavcodec/smpte_436m.h#199                        │ av_smpte_291m_anc_8bit_decode                         │ payload            │ av_smpte_291m_anc_8bit_decode                        │
│                                                    │                                                       │                    │                                                      │
│ libavcodec/bytestream.h#148                        │ bytestream2_init_writer                               │ buf                │ bytestream2_init_writer                              │
│                                                    │                                                       │                    │                                                      │
│ libavcodec/bytestream.h#147                        │ bytestream2_init_writer                               │                    │ RET                                                  │
│                                                    │                                                       │                    │                                                      │
│ libavcodec/bytestream.h#197                        │ bytestream2_tell_p                                    │ p                  │ bytestream2_tell_p                                   │
│                                                    │                                                       │                    │                                                      │
└────────────────────────────────────────────────────┴───────────────────────────────────────────────────────┴────────────────────┴──────────────────────────────────────────────────────┘
                                                                                 Source: MCCTimecode *tc
                                                                                    Source Tags: parse
                                                                                  Sink: mcc_read_header

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                ┃ Method                                            ┃ Parameter              ┃ Tracked                                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/mccdec.c#171                                │ parse_time_code_rate                              │ s                      │ parse_time_code_rate                            │
│                                                         │ Tags: parse                                       │                        │                                                 │
│ libavformat/mccdec.c#141                                │ time_tracker_set_time                             │ log_ctx                │ time_tracker_set_time                           │
│                                                         │                                                   │                        │                                                 │
└─────────────────────────────────────────────────────────┴───────────────────────────────────────────────────┴────────────────────────┴─────────────────────────────────────────────────┘
                                                                                Source: AVFormatContext *s
                                                                                    Source Tags: parse
                                                                                  Sink: mcc_read_header

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                           ┃ Method                                                 ┃ Parameter        ┃ Tracked                                               ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#2504                     │ mkv_parse_block_addition_mappings                      │ s                │ mkv_parse_block_addition_mappings                     │
│                                                    │ Tags: parse                                            │                  │                                                       │
│ libavformat/matroskadec.c#2043                     │ matroska_parse_content_encodings                       │ track            │ matroska_parse_content_encodings                      │
│                                                    │ Tags: parse                                            │                  │                                                       │
└────────────────────────────────────────────────────┴────────────────────────────────────────────────────────┴──────────────────┴───────────────────────────────────────────────────────┘
                                                                                Source: AVFormatContext *s
                                                                                    Source Tags: parse
                                                                          Sink: matroska_parse_content_encodings

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                            ┃ Method                                                 ┃ Parameter        ┃ Tracked                                              ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#2044                      │ matroska_parse_content_encodings                       │ logctx           │ matroska_parse_content_encodings                     │
│                                                     │ Tags: parse                                            │                  │                                                      │
│ libavformat/matroskadec.c#2830                      │ mka_parse_audio                                        │ matroska         │ mka_parse_audio                                      │
│                                                     │ Tags: parse                                            │                  │                                                      │
└─────────────────────────────────────────────────────┴────────────────────────────────────────────────────────┴──────────────────┴──────────────────────────────────────────────────────┘
                                                                                   Source: void *logctx
                                                                                    Source Tags: parse
                                                                          Sink: matroska_parse_content_encodings

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                      ┃ Method                                          ┃ Parameter            ┃ Tracked                                       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#3588                                │ matroska_parse_rm_audio                         │ track                │ matroska_parse_rm_audio                       │
│                                                               │ Tags: parse                                     │                      │                                               │
│ libavformat/matroskadec.c#3771                                │ matroska_parse_webvtt                           │ track                │ matroska_parse_webvtt                         │
│                                                               │ Tags: parse                                     │                      │                                               │
│ libavformat/matroskadec.c#3973                                │ matroska_parse_frame                            │ track                │ matroska_parse_frame                          │
│                                                               │ Tags: parse                                     │                      │                                               │
└───────────────────────────────────────────────────────────────┴─────────────────────────────────────────────────┴──────────────────────┴───────────────────────────────────────────────┘
                                                                               Source: MatroskaTrack *track
                                                                                    Source Tags: parse
                                                                                Sink: matroska_parse_block

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                     ┃ Method                                        ┃ Parameter                 ┃ Tracked                                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#2022                               │ matroska_parse_cues                           │ matroska                  │ matroska_parse_cues                         │
│                                                              │ Tags: parse                                   │                           │                                             │
│ libavformat/matroskadec.c#845                                │ matroska_reset_status                         │ matroska                  │ matroska_reset_status                       │
│                                                              │                                               │                           │                                             │
│ libavformat/matroskadec.c#3486                               │ matroska_clear_queue                          │ matroska                  │ matroska_clear_queue                        │
│                                                              │                                               │                           │                                             │
│ libavformat/matroskadec.c#4245                               │ matroska_parse_cluster                        │ matroska                  │ matroska_parse_cluster                      │
│                                                              │ Tags: parse                                   │                           │                                             │
│ libavformat/matroskadec.c#1153                               │ ebml_parse                                    │ data                      │ ebml_parse                                  │
│                                                              │                                               │                           │                                             │
│ libavformat/matroskadec.c#1259                               │ ebml_parse                                    │ data                      │ ebml_parse                                  │
│                                                              │                                               │                           │                                             │
│ libavformat/matroskadec.c#4094                               │ matroska_parse_block                          │ cluster_time              │ matroska_parse_block                        │
│                                                              │ Tags: parse                                   │                           │                                             │
└──────────────────────────────────────────────────────────────┴───────────────────────────────────────────────┴───────────────────────────┴─────────────────────────────────────────────┘
                                                                          Source: MatroskaDemuxContext *matroska
                                                                                    Source Tags: parse
                                                                                Sink: matroska_parse_block

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                      ┃ Method                                          ┃ Parameter            ┃ Tracked                                       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#4245                                │ matroska_parse_cluster                          │ matroska             │ matroska_parse_cluster                        │
│                                                               │ Tags: parse                                     │                      │                                               │
│ libavformat/matroskadec.c#866                                 │ matroska_resync                                 │ last_pos             │ matroska_resync                               │
│                                                               │                                                 │                      │                                               │
│ libavformat/matroskadec.c#3459                                │ matroska_deliver_packet                         │ matroska             │ matroska_deliver_packet                       │
│                                                               │                                                 │                      │                                               │
└───────────────────────────────────────────────────────────────┴─────────────────────────────────────────────────┴──────────────────────┴───────────────────────────────────────────────┘
                                                                          Source: MatroskaDemuxContext *matroska
                                                                                    Source Tags: parse
                                                                                Sink: matroska_parse_block

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location                                                       ┃ Method                                         ┃ Parameter            ┃ Tracked                                       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ libavformat/matroskadec.c#4245                                 │ matroska_parse_cluster                         │ matroska             │ matroska_parse_cluster                        │
│                                                                │ Tags: parse                                    │                      │                                               │
│ libavformat/matroskadec.c#913                                  │ ebml_read_num                                  │ matroska             │ ebml_read_num                                 │
│                                                                │                                                │                      │                                               │
│ libavformat/matroskadec.c#978                                  │ ebml_read_length                               │ matroska             │ ebml_read_length                              │
│                                                                │                                                │                      │                                               │
└────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────┴──────────────────────┴───────────────────────────────────────────────┘
                                                                          Source: MatroskaDemuxContext *matroska
                                                                                    Source Tags: parse
                                                                                Sink: matroska_parse_block
```

### More queries to try

```
atom.method(".*Thread.*").callIn.argument.isIdentifier.df(atom.method(".*init.*").parameter).t
```

```
atom.method(".*gpu.*").callIn.argument.df(atom.method(".*init.*").parameter).t
```

```
atom.method(".*gpu.*").callIn.argument.df(atom.method(".*init.*").parameter).passesNot(_.collectAll[Expression].inCall.name("d3d12va_encode_set_profile")).t
```
