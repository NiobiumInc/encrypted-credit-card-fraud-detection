# Encrypted credit card fraud detection (PyTorch -> HEIR -> OpenFHE).
#
# Build flavors:
#   NIOBIUM_SDK_BUILD=ON: self-contained transport build (scripts/build_task.sh) —
#     the niobium-client builds its own OpenFHE + libnbfhetch; replay ships over
#     the FHETCH transport. See docs/NIOBIUM_CLIENT_TRANSPORT.md. Handled first.

cmake_minimum_required(VERSION 3.16)
project(encrypted_fraud_detection CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Transport build mode (niobium-client SDK) ────────────────────────────────
# Self-contained: OpenFHE + libnbfhetch come from the niobium-client's OWN build
# (scripts/build_task.sh), not an external checkout. Builds ONLY the client stages + the SDK-linked transport server, then
# returns early (skipping the CPU targets below).
option(NIOBIUM_SDK_BUILD "Self-contained build against the niobium-client SDK (transport)" OFF)
if(NIOBIUM_SDK_BUILD)
  set(NB_CLIENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/niobium-client")
  set(NB_FHETCH_DIR "${NB_CLIENT_DIR}/vendor/niobium-fhetch")

  find_package(OpenFHE CONFIG REQUIRED)      # from CMAKE_PREFIX_PATH = client's vendor/lib/openfhe
  message(STATUS "SDK build: OpenFHE ${OpenFHE_INCLUDE}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS} -Wno-error")

  include_directories(
    ${OpenFHE_INCLUDE} ${OpenFHE_INCLUDE}/core ${OpenFHE_INCLUDE}/pke ${OpenFHE_INCLUDE}/binfhe
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include                 # vendored nb_telemetry/ + plaintext_macro.h
    ${NB_FHETCH_DIR}/include                            # niobium/compiler.h (SDK)
    ${NB_FHETCH_DIR}/vendor/json/single_include)        # nlohmann/json (if vendored there)
  link_directories(${OpenFHE_LIBDIR})

  find_library(NBFHETCH_LIB NAMES nbfhetch
    PATHS "${NB_CLIENT_DIR}/build/vendor/niobium-fhetch"
          "${NB_CLIENT_DIR}/build/_deps/niobium-fhetch-build" NO_DEFAULT_PATH)
  if(NOT NBFHETCH_LIB)
    message(FATAL_ERROR "libnbfhetch not found — run 'make -C niobium-client release' first")
  endif()
  message(STATUS "SDK build: nbfhetch ${NBFHETCH_LIB}")
  get_filename_component(NBFHETCH_DIR "${NBFHETCH_LIB}" DIRECTORY)
  set(CMAKE_BUILD_RPATH "${OpenFHE_LIBDIR};${NBFHETCH_DIR}")

  # Client stages: plain OpenFHE; link nbfhetch to resolve the instrumented-OpenFHE globals.
  foreach(stage fraud_client_keygen fraud_client_encrypt fraud_client_decrypt)
    add_executable(${stage} src/${stage}.cc src/fraud_model_lib.inc.cc)
    target_link_libraries(${stage} ${OpenFHE_SHARED_LIBRARIES} ${NBFHETCH_LIB})
  endforeach()

  # SDK-linked server: record/replay via libnbfhetch -> the FHETCH transport.
  add_executable(fraud_server_sdk src/fraud_server_compute_sdk.cc src/fraud_model_lib.inc.cc)
  target_compile_definitions(fraud_server_sdk PRIVATE NIOBIUM_COMPILER OPENFHE_CPROBES)
  target_link_libraries(fraud_server_sdk ${OpenFHE_SHARED_LIBRARIES} ${NBFHETCH_LIB})
  return()
endif()

# The niobium-client submodule is the only OpenFHE source; there is no other
# build flavor.
message(FATAL_ERROR
  "configure with -DNIOBIUM_SDK_BUILD=ON — use scripts/build_task.sh")
