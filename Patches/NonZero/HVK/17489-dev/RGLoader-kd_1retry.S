
# ============================================================================
#	Set KdpRetryCount and KdNetRetryCount to 1
#      (faster boot speed due to smaller kd timeout)
# ============================================================================

.set  KdpRetryCount,    0x801DD80C   #default value is 5
.set  KdNetRetryCount,  0x801DD81C   #default value is 3


	KMAKEPATCH KdpRetryCount
0:
	.long 0x00000001  #patch to 1 retry
9:

	KMAKEPATCH KdNetRetryCount
0:
	.long 0x00000001  #patch to 1 retry
9:



