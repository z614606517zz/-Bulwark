#include "design/Motion.h"

#include <QtGlobal> // Q_OS_WIN

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace motion {

bool enabled()
{
    static const bool on = [] {
#ifdef Q_OS_WIN
        BOOL v = TRUE;
        if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &v, 0))
            return v != FALSE;
#endif
        return true;
    }();
    return on;
}

int duration(int ms)
{
    return enabled() ? ms : 0;
}

} // namespace motion
