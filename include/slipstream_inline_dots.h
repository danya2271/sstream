#ifndef SLIPSTREAM_INLINE_DOTS_H
#define SLIPSTREAM_INLINE_DOTS_H
#include <stddef.h>

#define SLIPSTREAM_DNS_ENCODED_LABEL_MAX 63

size_t slipstream_inline_dotify(char * __restrict__ buf, size_t buflen, size_t len);

size_t slipstream_inline_undotify(char * __restrict__ buf, size_t len);

#endif // SLIPSTREAM_INLINE_DOTS_H
