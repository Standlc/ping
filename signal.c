#include "ft_ping.h"

int handle_signal(int signo, void (*func)(int)) {
    struct sigaction act;

    act.sa_flags = 0;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);

    if (sigaction(signo, &act, NULL) < 0) {
        return (-1);
    }

    return (0);
}
