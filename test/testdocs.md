# Documentation on how to structure the testfiles
For every testfile you need to create a <testname>.c and a <testname>.h file. The <testname>.h file must be structured like this:
```

```

In the <testgroup>.c file you should implement in the pattern 
```
bool test_function_name() {
    //setup test here
    return assert_true(condition, message);
}


test_<testgroup>() {
    start_tests("<put the name of the group in here>");
    // here you add all your tests:
    run_test("<Testname>", test_function_name);
    end_tests();
}
``` 

Now include the <testgroup>.h file in main_test.c and run the `test_<testgroup>();` function in the main function.