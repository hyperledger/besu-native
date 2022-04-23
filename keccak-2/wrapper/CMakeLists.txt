# ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
# Copyright 2019 Pawel Bylica.
# SPDX-License-Identifier: Apache-2.0

include(GNUInstallDirs)
include_directories(../ethash/include/)

add_library(keccak)
add_library(ethash::keccak ALIAS keccak)
target_compile_features(keccak PUBLIC c_std_99)
set_target_properties(keccak PROPERTIES C_EXTENSIONS OFF)
target_include_directories(keccak PUBLIC $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:include>)
target_sources(keccak PRIVATE
    ../ethash/include/ethash/keccak.h
    ../ethash/include/ethash/keccak.hpp
    ./keccak256.h
    ./keccak256.c
    ../ethash/lib/keccak/keccak.c
)

install(
    TARGETS keccak
    EXPORT ethashTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
