#include "sysgaze/buffer.h"
#include "sysgaze/cli.h"
#include "sysgaze/config.h"
#include "sysgaze/decoder.h"
#include "sysgaze/event.h"
#include "sysgaze/filter.h"
#include "sysgaze/output.h"
#include "sysgaze/syscall_catalog.h"
#include "sysgaze/tracee.h"
#include "sysgaze/trace.h"
#include "sysgaze/tracee_table.h"

/* This translation unit intentionally has no symbols. Compiling it under the
 * project's strict flags verifies that every public header is self-contained. */
