#include <windows.h>
#include "beacon.h"

// Extern Rust initialize fn
extern void initialize(
    void (*beacon_output)(int, const char *, int),
    void (*beacon_printf)(int, const char * fmt, ...),
    char (*data_extract)(datap * parser, int * size),
    void (*data_parse)(datap * parser, char * buffer, int size),
    int (*data_int)(datap * parser),
    char* args,
    int alen
);

void go(char* args, int alen) {
    // Pass the fn pointers to the rust wrapper
    initialize(
        BeaconOutput,
        BeaconPrintf,
        BeaconDataExtract,
        BeaconDataParse,
        BeaconDataInt,
        args,
        alen
    );
}
