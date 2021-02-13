# 11775.3 - 12387

# 00000000000015A8 -> patch #1
# 0000000000001154 -> patch #2
# 0000000000001E6C -> patch #3

.include "macros.S"

#============================================================================
#   Shadowboot signature patch
#============================================================================
    MAKEPATCH 0x0000D9B0
0:
    li      %r3, 1
9:

#============================================================================
#   Patch TLB RPN to Remove Protections
#
#     - allows code excution anywhere in 0x80000000->0x9FFFFFFF range
#     - allows system thread manipulation of code/read only data without
#       disabling encryption
#     - 0x0007 clears bits NoExec:DataPage:Readonly of RPN
#============================================================================
    MAKEPATCH 0x000015A8
    .set PatchTlbRpn, PatchAddr
0:
    li      %r4, 0x0007             # removes all page protection
    andc    %r1, %r1, %r4
    mtspr   TLB_RPN, %r1            # instruction replaced to get here
    ba      PatchTlbRpnDone
9:

#============================================================================
#   hv tlb_rpn set command location       mtspr   SPR_TLB_RPN, sp           
#============================================================================
    MAKEPATCH 0x00001154
    .set PatchTlbRpnDone, (PatchAddr + (9f - 0f))
0:
    ba      PatchTlbRpn
9:

#============================================================================
#   Patch TLB RPN to Remove Protections
# 30090                 ori       r4, r4, 0x1B3
# 3009C                 mtspr     SPR_TLB_RPN, r4
#============================================================================
    MAKEPATCH 0x00001E6C
0:
    ori        %r4, %r4, 0x1B0
9:

#============================================================================
#   End of patches
#============================================================================
.long 0xFFFFFFFF
