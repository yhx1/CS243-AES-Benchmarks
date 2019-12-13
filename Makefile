# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/Desktop/AES

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/Desktop/AES

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /root/Desktop/AES/CMakeFiles /root/Desktop/AES/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /root/Desktop/AES/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named MP_omp

# Build rule for target.
MP_omp: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 MP_omp
.PHONY : MP_omp

# fast build rule for target.
MP_omp/fast:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/build
.PHONY : MP_omp/fast

#=============================================================================
# Target rules for targets named serial

# Build rule for target.
serial: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 serial
.PHONY : serial

# fast build rule for target.
serial/fast:
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/build
.PHONY : serial/fast

#=============================================================================
# Target rules for targets named MP_tbb

# Build rule for target.
MP_tbb: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 MP_tbb
.PHONY : MP_tbb

# fast build rule for target.
MP_tbb/fast:
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/build
.PHONY : MP_tbb/fast

#=============================================================================
# Target rules for targets named MP_pthread

# Build rule for target.
MP_pthread: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 MP_pthread
.PHONY : MP_pthread

# fast build rule for target.
MP_pthread/fast:
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/build
.PHONY : MP_pthread/fast

AES.o: AES.cpp.o

.PHONY : AES.o

# target to build an object file
AES.cpp.o:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/AES.cpp.o
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/AES.cpp.o
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/AES.cpp.o
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/AES.cpp.o
.PHONY : AES.cpp.o

AES.i: AES.cpp.i

.PHONY : AES.i

# target to preprocess a source file
AES.cpp.i:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/AES.cpp.i
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/AES.cpp.i
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/AES.cpp.i
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/AES.cpp.i
.PHONY : AES.cpp.i

AES.s: AES.cpp.s

.PHONY : AES.s

# target to generate assembly for a file
AES.cpp.s:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/AES.cpp.s
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/AES.cpp.s
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/AES.cpp.s
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/AES.cpp.s
.PHONY : AES.cpp.s

openmp.o: openmp.cpp.o

.PHONY : openmp.o

# target to build an object file
openmp.cpp.o:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/openmp.cpp.o
.PHONY : openmp.cpp.o

openmp.i: openmp.cpp.i

.PHONY : openmp.i

# target to preprocess a source file
openmp.cpp.i:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/openmp.cpp.i
.PHONY : openmp.cpp.i

openmp.s: openmp.cpp.s

.PHONY : openmp.s

# target to generate assembly for a file
openmp.cpp.s:
	$(MAKE) -f CMakeFiles/MP_omp.dir/build.make CMakeFiles/MP_omp.dir/openmp.cpp.s
.PHONY : openmp.cpp.s

pthread.o: pthread.cpp.o

.PHONY : pthread.o

# target to build an object file
pthread.cpp.o:
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/pthread.cpp.o
.PHONY : pthread.cpp.o

pthread.i: pthread.cpp.i

.PHONY : pthread.i

# target to preprocess a source file
pthread.cpp.i:
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/pthread.cpp.i
.PHONY : pthread.cpp.i

pthread.s: pthread.cpp.s

.PHONY : pthread.s

# target to generate assembly for a file
pthread.cpp.s:
	$(MAKE) -f CMakeFiles/MP_pthread.dir/build.make CMakeFiles/MP_pthread.dir/pthread.cpp.s
.PHONY : pthread.cpp.s

serial.o: serial.cpp.o

.PHONY : serial.o

# target to build an object file
serial.cpp.o:
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/serial.cpp.o
.PHONY : serial.cpp.o

serial.i: serial.cpp.i

.PHONY : serial.i

# target to preprocess a source file
serial.cpp.i:
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/serial.cpp.i
.PHONY : serial.cpp.i

serial.s: serial.cpp.s

.PHONY : serial.s

# target to generate assembly for a file
serial.cpp.s:
	$(MAKE) -f CMakeFiles/serial.dir/build.make CMakeFiles/serial.dir/serial.cpp.s
.PHONY : serial.cpp.s

tbb.o: tbb.cpp.o

.PHONY : tbb.o

# target to build an object file
tbb.cpp.o:
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/tbb.cpp.o
.PHONY : tbb.cpp.o

tbb.i: tbb.cpp.i

.PHONY : tbb.i

# target to preprocess a source file
tbb.cpp.i:
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/tbb.cpp.i
.PHONY : tbb.cpp.i

tbb.s: tbb.cpp.s

.PHONY : tbb.s

# target to generate assembly for a file
tbb.cpp.s:
	$(MAKE) -f CMakeFiles/MP_tbb.dir/build.make CMakeFiles/MP_tbb.dir/tbb.cpp.s
.PHONY : tbb.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... MP_omp"
	@echo "... serial"
	@echo "... MP_tbb"
	@echo "... MP_pthread"
	@echo "... AES.o"
	@echo "... AES.i"
	@echo "... AES.s"
	@echo "... openmp.o"
	@echo "... openmp.i"
	@echo "... openmp.s"
	@echo "... pthread.o"
	@echo "... pthread.i"
	@echo "... pthread.s"
	@echo "... serial.o"
	@echo "... serial.i"
	@echo "... serial.s"
	@echo "... tbb.o"
	@echo "... tbb.i"
	@echo "... tbb.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
