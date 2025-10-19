`av_bprint_append_data`

Prepare for copy operation

load base address to x9

ldr x9, [x19]

Add value in register x9 to the value in w8.

add x0, x9, w8, uxtw

Compare and branch if zero

cbz w9, #24

Calls function to append data into the buffer at the calculated address

bl #977392

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
        "conditional_jump_count": 0,
        "xor_count": 0,
        "shift_count": 0,
        "arith_count": 5,
        "ret_count": 1,
        "jump_count": 0,
        "simd_fpu_count": 0,
        "unique_regs_read_count": 19,
        "unique_regs_written_count": 12
    },
    "direct_calls": [],
    "has_indirect_call": false,
    "has_system_call": false,
    "has_security_feature": false,
    "has_crypto_call": false,
    "has_gpu_call": false,
    "has_loop": false,
    "regs_read": [
        "w2",
        "x30",
        "w25",
        "w8",
        "x28",
        "x1",
        "w9",
        "x2",
        "x0",
        "x10",
        "w22",
        "x21",
        "w28",
        "x9",
        "w20",
        "wzr",
        "x19",
        "w24",
        "x24"
    ],
    "regs_written": [
        "w8",
        "x1",
        "x22",
        "w9",
        "x8",
        "x10",
        "x19",
        "x20",
        "x30",
        "x0",
        "x21",
        "x9"
    ],
    "used_simd_reg_types": [],
    "instructions_with_registers": [
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
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
            "regs_read": [],
            "regs_written": []
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
            "regs_read": [],
            "regs_written": []
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
            "regs_read": [],
            "regs_written": []
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
                "w9",
                "w8"
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
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [
                "w9",
                "w8"
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
                "w9",
                "w8"
            ],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [
                "wzr",
                "w8",
                "x10"
            ],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [
                "x30"
            ],
            "regs_written": []
        }
    ],
    "function_type": ""
}
```
