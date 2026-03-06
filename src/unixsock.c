#include "unixsock.h"

#include <fcntl.h>

int32_t unixsock_set_nonblocking(int32_t fd, int32_t enabled) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  int next_flags = flags;
  if (enabled) {
    next_flags |= O_NONBLOCK;
  } else {
    next_flags &= ~O_NONBLOCK;
  }

  return fcntl(fd, F_SETFL, next_flags);
}
