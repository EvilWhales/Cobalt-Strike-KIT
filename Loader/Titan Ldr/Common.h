/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/* Include core defs */
#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <ntstatus.h>
#include "Native.h"
#include "Macros.h"

/* Include Library */
#include "Labels.h"
#include "Hash.h"
#include "Peb.h"
#include "Ldr.h"
#include "Pe.h"

/* Include Hooks! */
#include "hooks/DnsQuery_A.h"
