#pragma once

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

static Color __yellow( 255, 255, 0, 255 );

#define _DebugMsg( ... ) Msg( __VA_ARGS__ )
#define _DebugWarning( ... ) ConColorMsg( 1, __yellow, __VA_ARGS__ )

#else

#define _DebugMsg( ... )
#define _DebugWarning( ... )

#endif
