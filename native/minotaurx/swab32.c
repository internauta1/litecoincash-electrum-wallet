#include <stdint.h>

/* 32-bit byte swap used by the original SHA2 implementation. */
uint32_t swab32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24)
         | ((value & 0x0000ff00U) << 8)
         | ((value & 0x00ff0000U) >> 8)
         | ((value & 0xff000000U) >> 24);
}
