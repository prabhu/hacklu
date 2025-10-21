`mov fs, word ptr [rcx + 437735814]` fs segment register is modified!
`jne -22`

```
╟─────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────────┼────────────────────────────────────────────────╢
║ ANTI_DISASSEMBLY_TRICKS │ /Users/prabhu/sandbox/ffmpeg-nuget-mal/ffmpeg1.dll │ Function has a very low instruction count but contains │ _av_bprint_append_data                            ║
║                         │                                                    │ jumps, potentially indicating an obfuscated thunk.     │                                                ║
╚═════════════════════════╧════════════════════════════════════════════════════╧════════════════════════════════════════════════════════╧════════════════════════════════════════════════╝
```

```
"0x1004c950::_av_bprint_append_data": {
  "name": "_av_bprint_append_data",
  "address": "0x1004c950",
  "assembly": "call 2260747\nmov fs, word ptr [rcx + 437735814]\nadc dh, cl\nmov edi, 2413881385\nand eax, dword ptr [rax]\njne -22\nxor al, -94\nsub rsi, qword ptr [r15 - 38]\nadc dword ptr [rbx + 119], 3897890086\nxor eax, 4127204615",
  "assembly_hash": "cf34b6668d4cb719605d842d0209a5b28e50f5d14c4db67fb5697c07bd4faaf0",
  "instruction_hash": "43d7b7334270d131f16463386b9350003ae189a284154d896d30a8290aab9779",
  "instruction_count": 10,
  "instruction_metrics": {
      "call_count": 1,
      "conditional_jump_count": 1,
      "xor_count": 2,
      "shift_count": 0,
      "arith_count": 4,
      "ret_count": 0,
      "jump_count": 0,
      "simd_fpu_count": 0,
      "unique_regs_read_count": 9,
      "unique_regs_written_count": 14
  },
  "direct_calls": [],
  "has_indirect_call": false,
  "has_system_call": false,
  "has_security_feature": false,
  "has_crypto_call": false,
  "has_gpu_call": false,
  "has_loop": false,
  "regs_read": [
      "al",
      "cl",
      "dh",
      "eax",
      "r15",
      "rax",
      "rbx",
      "rcx",
      "rsi"
  ],
  "regs_written": [
      "al",
      "dh",
      "eax",
      "edi",
      "fs", <----
      "r10",
      "r11",
      "r8",
      "r9",
      "rax",
      "rbx",
      "rcx",
      "rdx",
      "rsi"
  ],
  "used_simd_reg_types": [],
  "instructions_with_registers": [
      {
          "regs_read": [],
          "regs_written": [
              "r10",
              "r11",
              "r8",
              "r9",
              "rax",
              "rcx",
              "rdx"
          ]
      },
      {
          "regs_read": [
              "rcx"
          ],
          "regs_written": [
              "fs"  <----
          ]
      },
      {
          "regs_read": [
              "cl",
              "dh"
          ],
          "regs_written": [
              "dh"
          ]
      },
      {
          "regs_read": [],
          "regs_written": [
              "edi"
          ]
      },
      {
          "regs_read": [
              "eax",
              "rax"
          ],
          "regs_written": [
              "eax"
          ]
      },
      {
          "regs_read": [],
          "regs_written": []
      },
      {
          "regs_read": [
              "al"
          ],
          "regs_written": [
              "al"
          ]
      },
      {
          "regs_read": [
              "r15",
              "rsi"
          ],
          "regs_written": [
              "rsi"
          ]
      },
      {
          "regs_read": [
              "rbx"
          ],
          "regs_written": [
              "rbx"
          ]
      },
      {
          "regs_read": [
              "eax"
          ],
          "regs_written": [
              "eax"
          ]
      }
  ],
  "function_type": "Has_Conditional_Jumps",
  "proprietary_instructions": [],
  "sreg_interactions": []
}
```
