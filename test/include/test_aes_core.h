//
// Created by bmh on 12.10.23.
//

#ifndef MINI_TLS_TEST_AES_CORE_H
#define MINI_TLS_TEST_AES_CORE_H

#include "minitest.h"

const char *group = "AES_CORE";

// TODO: Add test cases given by FIPS 197 (AES)
// TODO: Correct the Messages in the assert statements to show why the assert went wrong
bool aes_key_addition(void) {
    return assert_true(true, "Key Addition")
}

bool aes_shift_rows(void) {
    return assert_true(true, "Shift Rows");
}

bool aes_mix_columns(void) {
    return assert_true(true, "Mix Columns");
}

bool aes_sub_bytes(void) {
    return assert_true(true, "Substitute Bytes");
}

bool key_schedule(void) {
    return assert_true(true, "Key Schedule");
}

void test_aes_core() {
    start_tests(group);
    // TODO: Add test-runner here:
    run_test("Key Addition", aes_key_addition);
    run_test("Byte Substitution", aes_key_addition);
    run_test("Shift Rows", aes_key_addition);
    run_test("Mix Columns", aes_key_addition);
    run_test("Key Schedule", aes_key_addition);

    end_tests();
}

#endif //MINI_TLS_TEST_AES_CORE_H
