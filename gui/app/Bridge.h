// The engine's whole interface to the macOS app. The engine is the Rust
// static library built from gui/src; the app is the Swift code in this folder.
// All strings are UTF-8 and NUL-terminated.
#ifndef LOOSE_KEYS_BRIDGE_H
#define LOOSE_KEYS_BRIDGE_H

#include <stdbool.h>

// Start the app side of the engine: open the review store and set up
// notifications. Call once, on the main thread, before any ch_call. It does
// not read the store, so it does not wait for the background agent.
// `review_route` is true when the app was opened to show the review list.
void ch_app_start(bool review_route);

// Run one command. `args` is a JSON object, "{}" when the command takes none.
// Returns a JSON document the caller releases with ch_free:
//   {"ok": <value>}                  the command's result, null when it has none
//   {"error": "<text for the person>"}
// Safe to call from any thread. `start_scan` blocks until the scan ends. The
// first call reads the review store, and like any call that reads it waits
// while the background agent holds it. Only `prepare_quit` never waits.
char *ch_call(const char *command, const char *args);
void ch_free(char *text);

// Events from the engine: a name and a JSON payload, both valid only for the
// duration of the call. May arrive on any thread.
void ch_set_event_handler(void (*handler)(const char *name, const char *payload));

// Run as the background agent (the executable's --agent mode). Never returns.
void ch_agent_main(void);

#endif
