#ifndef FLUTTER_PLUGIN_UNIXSOCK_H_
#define FLUTTER_PLUGIN_UNIXSOCK_H_

#include <stdint.h>

#if _WIN32
#define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FFI_PLUGIN_EXPORT __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

FFI_PLUGIN_EXPORT int32_t unixsock_set_nonblocking(int32_t fd, int32_t enabled);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FLUTTER_PLUGIN_UNIXSOCK_H_
