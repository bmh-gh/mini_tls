//
// Created by bmh on 12.10.23.
//
#include "minitests.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#define RESET_COLOR "\x1b[0m"
#define RED_COLOR "\x1b[31m"
#define GREEN_COLOR "\x1b[32m"

static int total_tests = 0;
static int passed_tests = 0;
static char *group;

void start_tests(char *group_name) {
    group = group_name;
    total_tests = 0;
    passed_tests = 0;
    printf("Starting tests %s...\n", group);
}

void end_tests() {
    if (passed_tests == total_tests) {
        printf(GREEN_COLOR "[%d/%d]·Tests·passed" RESET_COLOR "\n", passed_tests, total_tests);
    } else {
        printf(RED_COLOR "[%d/%d]·Tests·passed" RESET_COLOR "\n", passed_tests, total_tests);
    }
}

void run_test(const char *test_name, bool (*test_fn)(void)) {
    total_tests++;
    printf("Testing %s... ", test_name);
    double start = clock();
    bool result = test_fn();
    double end = clock();
    double time_passed = (double)(end - start) / CLOCKS_PER_SEC;
    if (result) {
        printf(GREEN_COLOR "[✓] %f" RESET_COLOR "\n", time_passed);
        passed_tests++;
    } else {
        printf(RED_COLOR "[X] %f" RESET_COLOR "\n", time_passed);
    }
}

bool assert_true(bool condition, const char *message, ...) {
    if (!condition) {
        printf(RED_COLOR "[X] Assertion failed: " RESET_COLOR);
        va_list args;
        va_start(args, message);
        vprintf(message, args);
        va_end(args);
        printf("\n");
    }
    return condition;
}

bool assert_false(bool condition, const char *message, ...) {
    if (condition) {
        printf(RED_COLOR "[X] Assertion failed: " RESET_COLOR);
        va_list args;
        va_start(args, message);
        vprintf(message, args);
        va_end(args);
        printf("\n");
    }
    return !condition;
}