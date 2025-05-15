# CMake generated Testfile for 
# Source directory: /home/hugo/Desktop/emp/emp-ot/test
# Build directory: /home/hugo/Desktop/emp/emp-ot/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(ot "./run" "/home/hugo/Desktop/emp/emp-ot/bin/test_ot")
set_tests_properties(ot PROPERTIES  WORKING_DIRECTORY "/home/hugo/Desktop/emp/emp-ot/" _BACKTRACE_TRIPLES "/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;14;add_test;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;19;add_test_case_with_run;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;0;")
add_test(ferret "./run" "/home/hugo/Desktop/emp/emp-ot/bin/test_ferret")
set_tests_properties(ferret PROPERTIES  WORKING_DIRECTORY "/home/hugo/Desktop/emp/emp-ot/" _BACKTRACE_TRIPLES "/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;14;add_test;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;20;add_test_case_with_run;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;0;")
add_test(bench_lpn "/home/hugo/Desktop/emp/emp-ot/bin/test_bench_lpn")
set_tests_properties(bench_lpn PROPERTIES  WORKING_DIRECTORY "/home/hugo/Desktop/emp/emp-ot/" _BACKTRACE_TRIPLES "/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;9;add_test;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;21;add_test_case;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;0;")
add_test(ectf "./run" "/home/hugo/Desktop/emp/emp-ot/bin/test_ectf")
set_tests_properties(ectf PROPERTIES  WORKING_DIRECTORY "/home/hugo/Desktop/emp/emp-ot/" _BACKTRACE_TRIPLES "/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;14;add_test;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;22;add_test_case_with_run;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;0;")
add_test(p256-ectf "./run" "/home/hugo/Desktop/emp/emp-ot/bin/test_p256-ectf")
set_tests_properties(p256-ectf PROPERTIES  WORKING_DIRECTORY "/home/hugo/Desktop/emp/emp-ot/" _BACKTRACE_TRIPLES "/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;14;add_test;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;23;add_test_case_with_run;/home/hugo/Desktop/emp/emp-ot/test/CMakeLists.txt;0;")
