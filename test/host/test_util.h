#pragma once

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond) do {                                                \
        g_checks++;                                                     \
        if (!(cond)) {                                                  \
            g_failures++;                                               \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                               \
    } while (0)

#define CHECK_STR(got, want) do {                                       \
        g_checks++;                                                     \
        if (strcmp((got), (want)) != 0) {                               \
            g_failures++;                                               \
            printf("FAIL %s:%d:\n  got:  %s\n  want: %s\n",             \
                   __FILE__, __LINE__, (got), (want));                  \
        }                                                               \
    } while (0)

#define TEST_SUMMARY(name) do {                                         \
        printf("%s: %d checks, %d failures\n", (name), g_checks, g_failures); \
        return g_failures ? 1 : 0;                                      \
    } while (0)
