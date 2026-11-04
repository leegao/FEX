add_executable(FEXOfflineCompiler Main.cpp)

target_link_libraries(FEXOfflineCompiler PRIVATE
  Common
  CommonTools
  cpp-optparse
  FEXCore
  JemallocLibs
  fmt::fmt)

if (MINGW)
  if (ARCHITECTURE_arm64ec)
    set_target_properties(FEXOfflineCompiler PROPERTIES OUTPUT_NAME "FEXOfflineCompiler64")
  else()
    set_target_properties(FEXOfflineCompiler PROPERTIES OUTPUT_NAME "FEXOfflineCompiler32")
  endif()
  patch_library_wine(FEXOfflineCompiler)
  target_include_directories(FEXOfflineCompiler PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
    "${CMAKE_SOURCE_DIR}/Source/"
    "${CMAKE_SOURCE_DIR}/Source/Windows/"
  )
  target_link_libraries(FEXOfflineCompiler PRIVATE CommonWindows ntdll_ex)
else()
  target_link_libraries(FEXOfflineCompiler PRIVATE ${PTHREAD_LIB} LinuxEmulation)
endif()

LinkerGC(FEXOfflineCompiler)

install(TARGETS FEXOfflineCompiler RUNTIME
  DESTINATION bin
  COMPONENT Runtime)

if (NOT MINGW)
  add_executable(fex-aot-pe EXCLUDE_FROM_ALL
    FEXAOTPECompiler.cpp
    "${CMAKE_SOURCE_DIR}/FEXCore/Source/Interface/Core/AOT/LLVMArm64ECAOT.cpp"
    "${CMAKE_SOURCE_DIR}/FEXCore/Source/Interface/Core/AOT/PECOFFContainer.cpp")
  target_include_directories(fex-aot-pe PRIVATE
    "${CMAKE_SOURCE_DIR}/FEXCore/Source"
    "${CMAKE_SOURCE_DIR}/FEXCore/Source/IncludePrivate")
  target_link_libraries(fex-aot-pe PRIVATE FEXCore FEXCore_Base JemallocDummy fmt::fmt xxHash::xxhash cephes_128bit softfloat_3e LLVM ${PTHREAD_LIB} dl atomic)
endif()
