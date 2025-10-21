`_av_bprint_append_data` function from libffmpeg for `x86_64`.

```
"0xad4f0::_av_bprint_append_data": {
    "name": "_av_bprint_append_data",
    "address": "0xad4f0",
    "assembly": "push rbp\npush r15\npush r14\npush r13\npush r12\npush rbx\npush rax\nmov ebp, edx\nmov qword ptr [rsp], rsi\nmov rbx, rdi\nxor r14d, r14d\nmov r12d, dword ptr [rbx + 8]\nmov r13d, dword ptr [rbx + 12]\nmov r15d, r13d\nsub r15d, r12d\ncmovb r15d, r14d\ncmp ebp, r15d\njb 19\nmov rdi, rbx\nmov esi, ebp\ncall -680\ntest eax, eax\nje -37\nmov eax, dword ptr [rbx + 8]\njmp 3\nmov eax, r12d\ncmp r13d, r12d\njbe 30\ndec r15d\ncmp ebp, r15d\ncmovb r15d, ebp\nmov edi, eax\nadd rdi, qword ptr [rbx]\nmov rsi, qword ptr [rsp]\nmov rdx, r15\ncall 1129896\nmov eax, dword ptr [rbx + 8]\nmov ecx, 4294967290\nsub ecx, eax\ncmp ebp, ecx\ncmovb ecx, ebp\nadd ecx, eax\nmov dword ptr [rbx + 8], ecx\nmov eax, dword ptr [rbx + 12]\ntest eax, eax\nje 14\nmov rdx, qword ptr [rbx]\ndec eax\ncmp ecx, eax\ncmovb eax, ecx\nmov byte ptr [rdx + rax], 0\nadd rsp, 8\npop rbx\npop r12\npop r13\npop r14\npop r15\npop rbp\nret\nnop dword ptr [rax]",
    "assembly_hash": "66e69404d28f4532c4e202dbfbcdd07b982ead3c01ebec82df362ff7ec9bbb8b",
    "instruction_hash": "fd7631659eecafaf86ce20f0832fb1b8d1b5c01ee774e441f48c5514076c9ec2",
    "instruction_count": 25,
    "instruction_metrics": {
        "call_count": 1,
        "conditional_jump_count": 2, // <----
        "xor_count": 1,
        "shift_count": 0,
        "arith_count": 1,
        "ret_count": 0,
        "jump_count": 1, // <----
        "simd_fpu_count": 0,
        "unique_regs_read_count": 17, // <----
        "unique_regs_written_count": 18 // <----
    },
    "direct_calls": [],
    "has_indirect_call": false,
    "has_system_call": false,
    "has_security_feature": false,
    "has_crypto_call": false,
    "has_gpu_call": false,
    "has_loop": false,
    "regs_read": [
        "r15",
        "r13d",
        "rsp",
        "r12d",
        "eax",
        "rax",
        "rdi",
        "edx",
        "rbx",
        "r12",
        "r14d",
        "ebp",
        "rsi",
        "rbp",
        "r15d",
        "r14",
        "r13"
    ],
    "regs_written": [
        "rcx",
        "r11",
        "r13d",
        "rsp",
        "r12d",
        "esi",
        "eax",
        "r10",
        "r8",
        "rax",
        "rdx",
        "rdi",
        "r9",
        "rbx",
        "r14d",
        "ebp",
        "rsi",
        "r15d"
    ],
    "used_simd_reg_types": [],
    "instructions_with_registers": [
        {
            "regs_read": [
                "rsp",
                "rbp"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "r15",
                "rsp"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "r14",
                "rsp"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "rsp",
                "r13"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "r12",
                "rsp"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "rsp",
                "rbx"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "rax",
                "rsp"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "edx"
            ],
            "regs_written": [
                "ebp"
            ]
        },
        {
            "regs_read": [
                "rsi"
            ],
            "regs_written": [
                "rsp"
            ]
        },
        {
            "regs_read": [
                "rdi"
            ],
            "regs_written": [
                "rbx"
            ]
        },
        {
            "regs_read": [
                "r14d"
            ],
            "regs_written": [
                "r14d"
            ]
        },
        {
            "regs_read": [
                "rbx"
            ],
            "regs_written": [
                "r12d"
            ]
        },
        {
            "regs_read": [
                "rbx"
            ],
            "regs_written": [
                "r13d"
            ]
        },
        {
            "regs_read": [
                "r13d"
            ],
            "regs_written": [
                "r15d"
            ]
        },
        {
            "regs_read": [
                "r12d",
                "r15d"
            ],
            "regs_written": [
                "r15d"
            ]
        },
        {
            "regs_read": [
                "r14d"
            ],
            "regs_written": [
                "r15d"
            ]
        },
        {
            "regs_read": [
                "ebp",
                "r15d"
            ],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [
                "rbx"
            ],
            "regs_written": [
                "rdi"
            ]
        },
        {
            "regs_read": [
                "ebp"
            ],
            "regs_written": [
                "esi"
            ]
        },
        {
            "regs_read": [],
            "regs_written": [
                "rcx",
                "r11",
                "r10",
                "r8",
                "rax",
                "rdx",
                "rdi",
                "r9",
                "rsi"
            ]
        },
        {
            "regs_read": [
                "eax"
            ],
            "regs_written": []
        },
        {
            "regs_read": [],
            "regs_written": []
        },
        {
            "regs_read": [
                "rbx"
            ],
            "regs_written": [
                "eax"
            ]
        },
        {
            "regs_read": [],
            "regs_written": []
        }
    ],
    "function_type": "Has_Conditional_Jumps",
    "proprietary_instructions": [],
    "sreg_interactions": []
}
```