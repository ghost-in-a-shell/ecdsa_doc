# 目前已知可优化位置总结

1. 签名时额外的随机数t     t (e + rd) / (kt) mod n  [t (e + rd) / (kt) mod n](../sign/signrestartable/#_5)
2. 椭圆曲线乘法中mxz方法时初始点随机化  [ecp_mul_mxz](../tools/mbedtls_ecp_mul_restartable/#ecp_mul_mxzecpc-2263)
3. 椭圆曲线乘法中mxz方法montgomery ladder替换为普通实现  [ecp_mul_mxz](../tools/mbedtls_ecp_mul_restartable/#ecp_mul_mxzecpc-2263)
4. 椭圆曲线乘法中comb方法优化，例如去掉安全赋值     [mbedtls_mpi_safe_cond_assign](../tools/ecp_safe_invert_jac)