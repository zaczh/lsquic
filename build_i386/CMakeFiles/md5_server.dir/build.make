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
include CMakeFiles/md5_server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/md5_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/md5_server.dir/flags.make

CMakeFiles/md5_server.dir/test/md5_server.c.o: CMakeFiles/md5_server.dir/flags.make
CMakeFiles/md5_server.dir/test/md5_server.c.o: ../test/md5_server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/md5_server.dir/test/md5_server.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/md5_server.dir/test/md5_server.c.o   -c /Users/zhang/lsquic/test/md5_server.c

CMakeFiles/md5_server.dir/test/md5_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/md5_server.dir/test/md5_server.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/md5_server.c > CMakeFiles/md5_server.dir/test/md5_server.c.i

CMakeFiles/md5_server.dir/test/md5_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/md5_server.dir/test/md5_server.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/md5_server.c -o CMakeFiles/md5_server.dir/test/md5_server.c.s

CMakeFiles/md5_server.dir/test/prog.c.o: CMakeFiles/md5_server.dir/flags.make
CMakeFiles/md5_server.dir/test/prog.c.o: ../test/prog.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/md5_server.dir/test/prog.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/md5_server.dir/test/prog.c.o   -c /Users/zhang/lsquic/test/prog.c

CMakeFiles/md5_server.dir/test/prog.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/md5_server.dir/test/prog.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/prog.c > CMakeFiles/md5_server.dir/test/prog.c.i

CMakeFiles/md5_server.dir/test/prog.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/md5_server.dir/test/prog.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/prog.c -o CMakeFiles/md5_server.dir/test/prog.c.s

CMakeFiles/md5_server.dir/test/test_common.c.o: CMakeFiles/md5_server.dir/flags.make
CMakeFiles/md5_server.dir/test/test_common.c.o: ../test/test_common.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/md5_server.dir/test/test_common.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/md5_server.dir/test/test_common.c.o   -c /Users/zhang/lsquic/test/test_common.c

CMakeFiles/md5_server.dir/test/test_common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/md5_server.dir/test/test_common.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/test_common.c > CMakeFiles/md5_server.dir/test/test_common.c.i

CMakeFiles/md5_server.dir/test/test_common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/md5_server.dir/test/test_common.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/test_common.c -o CMakeFiles/md5_server.dir/test/test_common.c.s

CMakeFiles/md5_server.dir/test/test_cert.c.o: CMakeFiles/md5_server.dir/flags.make
CMakeFiles/md5_server.dir/test/test_cert.c.o: ../test/test_cert.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/md5_server.dir/test/test_cert.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/md5_server.dir/test/test_cert.c.o   -c /Users/zhang/lsquic/test/test_cert.c

CMakeFiles/md5_server.dir/test/test_cert.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/md5_server.dir/test/test_cert.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhang/lsquic/test/test_cert.c > CMakeFiles/md5_server.dir/test/test_cert.c.i

CMakeFiles/md5_server.dir/test/test_cert.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/md5_server.dir/test/test_cert.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhang/lsquic/test/test_cert.c -o CMakeFiles/md5_server.dir/test/test_cert.c.s

# Object files for target md5_server
md5_server_OBJECTS = \
"CMakeFiles/md5_server.dir/test/md5_server.c.o" \
"CMakeFiles/md5_server.dir/test/prog.c.o" \
"CMakeFiles/md5_server.dir/test/test_common.c.o" \
"CMakeFiles/md5_server.dir/test/test_cert.c.o"

# External object files for target md5_server
md5_server_EXTERNAL_OBJECTS =

md5_server: CMakeFiles/md5_server.dir/test/md5_server.c.o
md5_server: CMakeFiles/md5_server.dir/test/prog.c.o
md5_server: CMakeFiles/md5_server.dir/test/test_common.c.o
md5_server: CMakeFiles/md5_server.dir/test/test_cert.c.o
md5_server: CMakeFiles/md5_server.dir/build.make
md5_server: src/liblsquic/liblsquic.a
md5_server: /usr/local/lib/libevent.a
md5_server: ../boringssl/libssl.a
md5_server: ../boringssl/libcrypto.a
md5_server: CMakeFiles/md5_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zhang/lsquic/build_i386/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable md5_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/md5_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/md5_server.dir/build: md5_server

.PHONY : CMakeFiles/md5_server.dir/build

CMakeFiles/md5_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/md5_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/md5_server.dir/clean

CMakeFiles/md5_server.dir/depend:
	cd /Users/zhang/lsquic/build_i386 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zhang/lsquic /Users/zhang/lsquic /Users/zhang/lsquic/build_i386 /Users/zhang/lsquic/build_i386 /Users/zhang/lsquic/build_i386/CMakeFiles/md5_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/md5_server.dir/depend

