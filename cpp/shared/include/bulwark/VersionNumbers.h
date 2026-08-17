#pragma once
/*
 * Version numbers ONLY. ASCII-only, on purpose -- this header is included by the
 * .rc resource scripts, and rc.exe preprocesses it with the system ANSI codepage.
 *
 * That is not a theoretical concern. The first attempt put these macros in
 * Version.h, which carries CJK commentary. rc.exe mis-lexed the UTF-8 CJK bytes as
 * ANSI, decided a stray byte opened a character constant (warning RC4093), and from
 * that point silently dropped the remaining #defines -- so the build failed with
 * "error RC2104: undefined keyword or key name: BULWARK_VERSION_STRING", which points
 * nowhere near the real cause. Keeping the resource-visible header free of non-ASCII
 * bytes removes the whole class of problem instead of relying on rc.exe encoding flags.
 *
 * Version.h includes this file and adds the C++ helpers, so there is still exactly
 * one place to bump a version.
 *
 * BULWARK_VERSION_STRING is a literal rather than something built with the
 * stringizing operator: rc.exe's support for '#' is unreliable too. Version.h
 * static_asserts that the literal and the three numbers agree.
 */

#define BULWARK_VERSION_MAJOR 1
#define BULWARK_VERSION_MINOR 0
#define BULWARK_VERSION_PATCH 0
#define BULWARK_VERSION_STRING "1.0.0"

/* Display suffix only; never part of any comparison. */
#define BULWARK_VERSION_SUFFIX "Qt Edition"

#define BULWARK_PRODUCT_NAME_A "Bulwark HIPS"
#define BULWARK_COMPANY_NAME_A "Bulwark"
