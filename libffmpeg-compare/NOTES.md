# Introduction

This document discusses the steps involved in computing and analysing the slices for ffmpeg using atom, blint, and dosai.

## Pre-requisites

- Java >= 21
- Python >= 3.10
- Install [atom >= 2.4.2](https://github.com/AppThreat/atom/releases/tag/v2.4.2)
- Install [blint >= 3.0.1](https://github.com/owasp-dep-scan/blint?tab=readme-ov-file#installation)
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
        "jump_count": 1, // <----
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
        "x10",
        "x28",
        "x19",
        "w2",
        "x30",
        "w8",
        "w25",
        "x0",
        "w28",
        "x1",
        "w22",
        "x21",
        "x9",
        "w9",
        "x24",
        "w24",
        "sp",
        "w20",
        "x2",
        "wzr"
    ],
    "regs_written": [
        "x8",
        "x10",
        "x25",
        "x27",
        "x29",
        "x28",
        "x19",
        "x30",
        "w2",
        "w8",
        "x20",
        "w25",
        "x0",
        "w28",
        "x1",
        "x23",
        "x21",
        "x22",
        "x9",
        "w9",
        "x24",
        "w24",
        "x26"
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
                "x24",
                "x23"
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
                "x30",
                "x29"
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
                "w28",
                "w24"
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
                "w9",
                "w20"
            ],
            "regs_written": []
        },
        {
            "regs_read": [
                "w9",
                "w20"
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
                "x9",
                "w8"
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
                "w9",
                "w20"
            ],
            "regs_written": []
        },
        {
            "regs_read": [
                "w9",
                "w20"
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
                "x10",
                "wzr"
            ],
            "regs_written": []
        },
        {
            "regs_read": [
                "sp"
            ],
            "regs_written": [
                "x30",
                "x29"
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
                "x24",
                "x23"
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

### Rule 1: Detect Potential C2 Indicators

```yara
rule Blint_C2_Syscall_Crypto {
    meta:
        description = "Detects binaries with functions containing both syscalls and crypto, potential C2"
        author = "Team AppThreat"
        date = "2025-10-19"
        reference = "Based on blint disassembled_functions metadata"

    condition:
        any function_metadata in blint_disassembled_functions : (
            function_metadata.has_system_call == true and
            function_metadata.has_crypto_call == true
        )
}
```

### Rule 2: Detect High Entropy Assembly Blocks

```yara
rule Blint_High_Entropy_Assembly {
    meta:
        description = "Detects functions with high conditional jumps and register usage, potential obfuscation/crypto"
        author = "Team AppThreat"
        date = "2025-10-19"
        reference = "Based on blint disassembled_functions instruction_metrics"
    condition:
        any function_metadata in blint_disassembled_functions : (
            function_metadata.instruction_metrics.conditional_jump_count > 50 and
            function_metadata.instruction_metrics.unique_regs_read_count > 20
        )
}
```

### Rule 3: Detect suspicious dotnet API

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

### Rule 4: Detect dotnet anti-analysis techniques

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

