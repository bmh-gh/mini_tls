//
// Created by bmh on 12.10.23.
//

#ifndef MINI_TLS_MINITEST_H
#define MINI_TLS_MINITEST_H
#include <stdbool.h>

void start_tests(char *group_name);

void end_tests();

void run_test(const char *tests_name, bool (*test_fn)(void));

bool assert_true(bool condition, const char *message, ...);

bool assert_false(bool condition, const char *message, ...);
#endif //MINI_TLS_MINITEST_H
