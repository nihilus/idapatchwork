
undefine_offsets = [
    0x98c09,
    0x9aa0a,
    0x9e80b,
    0x9e012,
    0x91016,
    0x93a1a,
    0xa4845,
    0xab025,
    0x98e26,
    0x993b1,
    0xb183f,
    0xb182a,
    0xa8c2e,
    0x9685d,
    0x98030,
    0x9d032,
    0xa3a33,
    0xa4a34,
    0xb5e35,
    0xa7236,
    0x9d009,
    0xa9c39,
    0xa063a,
    0xb763b,
    0xa083f,
    0xa7645,
    0xb0849,
    0xaf450,
    0x96a52,
    0x9c855,
    0x9b65c,
    0x9725d,
    0xa5e5e,
    0xb4665,
    0x93c68,
    0xb55bc,
    0xb246a,
    0x9686c,
    0xa3168,
    0xb8e72,
    0xa5e77,
    0xad678,
    0xb2479,
    0xb34bf,
    0x9b67c,
    0xaa27d,
    0x97280,
    0xa8883,
    0xa6885,
    0x9ae87,
    0x9e889,
    0x9e917,
    0xac48d,
    0xa2490,
    0xafe91,
    0xa1892,
    0xb8e95,
    0x9ae97,
    0x92c98,
    0xb2a99,
    0xa429e,
    0xb50a1,
    0xb5aa3,
    0xb76a5,
    0x90aa7,
    0xa30a9,
    0xa64aa,
    0x92cad,
    0x9beb3,
    0xb48b6,
    0xaa6b9,
    0xa58ba,
    0xb86bb,
    0xb50bf,
    0x974c0,
    0x94ac1,
    0xa6acb,
    0xb86c5,
    0xa71c6,
    0xa20c9,
    0xba0ca,
    0xb0c77,
    0x93c78,
    0xb3c79,
    0xb8724,
    0x9f0dc,
    0x952dd,
    0xaeede,
    0xabee3,
    0x9a4e4,
    0xaa2e5,
    0xa56e6,
    0xb0ceb,
    0x9a9d3,
    0xb54fa,
    0x91eff,
    0x93f08,
    0x90f0a,
    0xae70e,
    0xa4f0f,
    0xb8b13,
    0x91e2e,
    0xa7517,
    0x96118,
    0xadb20,
    0x91a30,
    0xa1322,
    0xab123,
    0xaeb24,
    0xaf125,
    0xb86dc,
    0xa0f2d,
    0xae32f,
    0xafb30,
    0xb9934,
    0xabd35,
    0xadc89,
    0xb8734,
    0x98b3d,
    0x9b744,
    0xa4d45,
    0x98349,
    0x92b4e,
    0xa214f,
    0xad1c2,
    0x93be3,
    0xb3b54,
    0xaa745,
    0xac2e4,
    0xab75c,
    0xb415d,
    0x9d690,
    0x91b62,
    0xaf6e6,
    0xacf68,
    0x9bb6a,
    0x99571,
    0xb237a,
    0xa7b7b,
    0xb257d,
    0xa6f7e,
    0x91b7f,
    0x91789,
    0xa118a,
    0x91297,
    0x9d45d,
    0x9cfed,
    0xad190,
    0x90a98,
    0xa4d95,
    0xa4d9f,
    0x9efa0,
    0xa23a4,
    0xa2baa,
    0x941b1,
    0x951b7,
    0xb9fbc,
    0xac3be,
    0x983c0,
    0xa97c2,
    0x9a9c3,
    0x941c6,
    0x9a4a1,
    0x98dcd,
    0x99dd0,
    0xb9dd2,
    0xa71d3,
    0x9c7d9,
    0xaffdb,
    0x9efdc,
    0xa69e3,
    0xa0feb,
    0xa51ec,
    0xb5852,
    0xae9f0,
    0x9cbf4,
    0xb11f5,
    0x9c1f9,
    0xb7e81,
    0xb451a,
    0x9a4bf
]

import idc

for offset in undefine_offsets:
    idc.MakeUnkn(offset, idc.DOUNK_EXPAND)