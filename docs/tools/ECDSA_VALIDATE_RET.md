# ECDSA_VALIDATE_RET

函数位置ecdsa.c

代码：

```
#define ECDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
```

其中 MBEDTLS_INTERNAL_VALIDATE_RET 的定义为

```
#define MBEDTLS_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
```

此处函数为空