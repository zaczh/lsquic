# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.14

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.14.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.14.3/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/zhang/lsquic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/zhang/lsquic/build_i386

# Include any dependencies generated for this target.
include CMakeFiles/echo_client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/echo_client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/echo_client.dir/flags.make

CMakeFiles/echo_client.dir/test/echo_client.c.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/test/echo_client.c.o: ../test/echo_client.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/echo_client.dir/test/echo_client.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/echo_client.dir/test/echo_client.c.o   -c /Users/zhang/lsquic/test/echo_client.c

CMakeFiles/echo_client.dir/test/echo_client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/test/echo_client.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/echo_client.c > CMakeFiles/echo_client.dir/test/echo_client.c.i

CMakeFiles/echo_client.dir/test/echo_client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/test/echo_client.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/echo_client.c -o CMakeFiles/echo_client.dir/test/echo_client.c.s

CMakeFiles/echo_client.dir/test/prog.c.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/test/prog.c.o: ../test/prog.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/echo_client.dir/test/prog.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/echo_client.dir/test/prog.c.o   -c /Users/zhang/lsquic/test/prog.c

CMakeFiles/echo_client.dir/test/prog.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/test/prog.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/prog.c > CMakeFiles/echo_client.dir/test/prog.c.i

CMakeFiles/echo_client.dir/test/prog.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/test/prog.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/prog.c -o CMakeFiles/echo_client.dir/test/prog.c.s

CMakeFiles/echo_client.dir/test/test_common.c.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/test/test_common.c.o: ../test/test_common.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/echo_client.dir/test/test_common.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/echo_client.dir/test/test_common.c.o   -c /Users/zhang/lsquic/test/test_common.c

CMakeFiles/echo_client.dir/test/test_common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/test/test_common.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/test_common.c > CMakeFiles/echo_client.dir/test/test_common.c.i

CMakeFiles/echo_client.dir/test/test_common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/test/test_common.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/test_common.c -o CMakeFiles/echo_client.dir/test/test_common.c.s

CMakeFiles/echo_client.dir/test/test_cert.c.o: CMakeFiles/echo_client.dir/flags.make
CMakeFiles/echo_client.dir/test/test_cert.c.o: ../test/test_cert.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/echo_client.dir/test/test_cert.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/echo_client.dir/test/test_cert.c.o   -c /Users/zhang/lsquic/test/test_cert.c

CMakeFiles/echo_client.dir/test/test_cert.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/echo_client.dir/test/test_cert.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/test_cert.c > CMakeFiles/echo_client.dir/test/test_cert.c.i

CMakeFiles/echo_client.dir/test/test_cert.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/echo_client.dir/test/test_cert.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/test_cert.c -o CMakeFiles/echo_client.dir/test/test_cert.c.s

# Object files for target echo_client
echo_client_OBJECTS = \
"CMakeFiles/echo_client.dir/test/echo_client.c.o" \
"CMakeFiles/echo_client.dir/test/prog.c.o" \
"CMakeFiles/echo_client.dir/test/test_common.c.o" \
"CMakeFiles/echo_client.dir/test/test_cert.c.o"

# External object files for target echo_client
echo_client_EXTERNAL_OBJECTS =

echo_client: CMakeFiles/echo_client.dir/test/echo_client.c.o
echo_client: CMakeFiles/echo_client.dir/test/prog.c.o
echo_client: CMakeFiles/echo_client.dir/test/test_common.c.o
echo_client: CMakeFiles/echo_client.dir/test/test_cert.c.o
echo_client: CMakeFiles/echo_client.dir/build.make
echo_client: src/liblsquic/liblsquic.a
echo_client: /usr/local/lib/libevent.a
echo_client: ../boringssl/libssl.a
echo_client: ../boringssl/libcrypto.a
echo_client: CMakeFiles/echo_client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable echo_client"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/echo_client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/echo_client.dir/build: echo_client

.PHONY : CMakeFiles/echo_client.dir/build

CMakeFiles/echo_client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/echo_client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/echo_client.dir/clean

CMakeFiles/echo_client.dir/depend:
	cd /Users/zhang/lsquic/build_i386 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zhang/lsquic /Users/zhang/lsquic /Users/zhang/lsquic/build_i386 /Users/zhang/lsquic/build_i386 /Users/zhang/lsquic/build_i386/CMakeFiles/echo_client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/echo_client.dir/depend

