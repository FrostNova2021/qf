cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF -DLLVM_ENABLE_PROJECTS='clang'  ../../llvm-project-llvmorg-11.0.1/llvm
cmake -DCMAKE_C_COMPILER='clang' -DLLVM_ENABLE_PROJECTS='compiler-rt' ../llvm-project-llvmorg-11.0.1/llvm