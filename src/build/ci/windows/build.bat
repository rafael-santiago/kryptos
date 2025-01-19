@SET COMPILER=gcc

@SET COMPILER_OPTS=-c -Ihere/src -DHVM_ASYNC_RQUEUE

@SET LINKER=gcc

@SET LIB=ar

@SET ADVAPI32LIB=-ladvapi32

@SET LINKER_OPTS=-o../bin/hefesto.exe dbg.o dep_chain.o expr_handler.o exprchk.o file_io.o hlsc_msg.o htask.o hvm.o hvm_alu.o hvm_func.o hvm_list.o hvm_rqueue.o hvm_str.o hvm_syscall.o hvm_thread.o hvm_toolset.o init.o lang_defs.o main.o mem.o os_detect.o parser.o src_chsum.o structs_io.o synchk.o types.o vfs.o hvm_project.o hvm_winreg.o ivk.o hvm_mod.o conv.o here/src/libhere.a %ADVAPI32LIB%

@SET UNIT_TEST=-omain.exe ../../dbg.o ../../dep_chain.o ../../expr_handler.o ../../exprchk.o ../../file_io.o ../../hlsc_msg.o ../../htask.o ../../hvm.o ../../hvm_alu.o ../../hvm_func.o ../../hvm_list.o ../../hvm_rqueue.o ../../hvm_str.o ../../hvm_syscall.o ../../hvm_thread.o ../../hvm_toolset.o ../../init.o ../../lang_defs.o ../../mem.o ../../os_detect.o ../../parser.o ../../src_chsum.o ../../structs_io.o ../../synchk.o ../../types.o ../../vfs.o main.o ../../hvm_project.o ../../hvm_winreg.o ../../ivk.o ../../hvm_mod.o ../../conv.o cutest.o cutest_memory.o cutest_mmap.o ../../here/src/libhere.a %ADVAPI32LIB%

@SET LIBHERE_OBJS=here.o here_ctx.o here_mmachine.o here_mem.o

@SET HERE_UNIT_TEST=-ohere_unittest main.o ../libhere.a cutest/src/cutest.o cutest/src/cutest_memory.o cutest/src/cutest_mmap.o

@echo ### Compiling

@%COMPILER% %COMPILER_OPTS% dbg.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% dep_chain.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% exprchk.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% expr_handler.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% file_io.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hlsc_msg.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% htask.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_alu.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_func.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_list.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_project.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_rqueue.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_str.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_syscall.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_thread.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_toolset.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% init.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% lang_defs.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% main.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% mem.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% os_detect.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% parser.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% src_chsum.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% structs_io.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% ivk.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% synchk.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% types.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% vfs.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_winreg.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% hvm_mod.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% -c conv.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@echo ### Compiled.

@cd here/src

@%COMPILER% %COMPILER_OPTS% here.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% here_ctx.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% here_mem.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%COMPILER% %COMPILER_OPTS% here_mmachine.c
@IF %ERRORLEVEL% NEQ 0 ( GOTO COMPILATION_FAIL )

@%LIB% -r "libhere.a" %LIBHERE_OBJS%

@cd ../..

@echo ### Linking...
@%LINKER% %LINKER_OPTS%

@IF %ERRORLEVEL% NEQ 0 ( GOTO HEFESTO_LINK_ERROR )

@echo ### Linked.

@..\bin\hefesto.exe --forgefiles=..\\setup\\hfst-inst.hsl --hfst-inst-projects=hefesto-install
@GOTO ALL_DONE

:COMPILATION_FAIL
@echo ### Compilation errors!!
@GOTO ALL_DONE

:UNIT_TEST_COMPILATION_FAIL
@echo ### Unit tests has errors!
@GOTO ALL_DONE

:HEFESTO_LINK_ERROR
@echo ### Hefesto linking error! 
@GOTO ALL_DONE

:ALL_DONE
