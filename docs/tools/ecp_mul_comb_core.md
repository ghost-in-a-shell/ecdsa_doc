# ecp_mul_comb_core（ecp.c 1781）

## 函数代码

```c
static int ecp_mul_comb_core( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                              const mbedtls_ecp_point T[], unsigned char T_size,
                              const unsigned char x[], size_t d,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng,
                              mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_ecp_point Txi;
    size_t i;

    mbedtls_ecp_point_init( &Txi );

#if !defined(MBEDTLS_ECP_RESTARTABLE)
    (void) rs_ctx;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->rsm != NULL &&
        rs_ctx->rsm->state != ecp_rsm_comb_core )
    {
        rs_ctx->rsm->i = 0;
        rs_ctx->rsm->state = ecp_rsm_comb_core;
    }

    /* new 'if' instead of nested for the sake of the 'else' branch */
    if( rs_ctx != NULL && rs_ctx->rsm != NULL && rs_ctx->rsm->i != 0 )
    {
        /* restore current index (R already pointing to rs_ctx->rsm->R) */
        i = rs_ctx->rsm->i;
    }
    else
#endif
    {
        /* Start with a non-zero point and randomize its coordinates */
        i = d;
        MBEDTLS_MPI_CHK( ecp_select_comb( grp, R, T, T_size, x[i] ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );
        if( f_rng != 0 )
            MBEDTLS_MPI_CHK( ecp_randomize_jac( grp, R, f_rng, p_rng ) );
    }

    while( i != 0 )
    {
        MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_DBL + MBEDTLS_ECP_OPS_ADD );
        --i;

        MBEDTLS_MPI_CHK( ecp_double_jac( grp, R, R ) );
        MBEDTLS_MPI_CHK( ecp_select_comb( grp, &Txi, T, T_size, x[i] ) );
        MBEDTLS_MPI_CHK( ecp_add_mixed( grp, R, R, &Txi ) );
    }

cleanup:

    mbedtls_ecp_point_free( &Txi );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && rs_ctx->rsm != NULL &&
        ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
    {
        rs_ctx->rsm->i = i;
        /* no need to save R, already pointing to rs_ctx->rsm->R */
    }
#endif

    return( ret );
}
```

## 函数说明

父函数ecp_mul_comb_after_precomp

使用组合方法计算椭圆曲线上的乘法运算

- 当计数器 `i` 不为 0 时，进入循环。
- 使用 `ecp_double_jac` 函数对点 `R` 进行倍点运算。
- 使用 `ecp_select_comb` 函数根据乘法因子 `x[i]` 选择对应的输入点 `T[i]`。
- 使用 `ecp_add_mixed` 函数将倍点结果 `R` 与选择的输入点 `Txi` 相加，得到新的倍点结果。
- 计数器 `i` 自减，进入下一次循环。