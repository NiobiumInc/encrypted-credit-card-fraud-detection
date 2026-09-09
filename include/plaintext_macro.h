// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef _PLAINTEXT_MACRO_H_
#define _PLAINTEXT_MACRO_H_

#include <iostream>
// helper macros to pause plaintext creation during recording time
#define MAKE_PLAINTEXT_HELPER(type_info, var_name, context, values) type_info var_name = context->MakeCKKSPackedPlaintext(values)


#ifdef NIOBIUM_COMPILER
#include "niobium/compiler.h"
#define MAKE_PLAINTEXT(type_info, var_name, context, values)\
  bool var_name ## _flag = niobium::compiler().running_p();\
  if(var_name ## _flag){\
    niobium::compiler().pause();\
  }\
  MAKE_PLAINTEXT_HELPER(type_info, var_name, context, values);\
  if(var_name ## _flag){\
    niobium::compiler().tag_input(#var_name, var_name);\
    niobium::compiler().resume(); \
  }
#else
#define MAKE_PLAINTEXT(type_info, var_name, context, values) MAKE_PLAINTEXT_HELPER(type_info, var_name, context, values)
#endif

#endif // _PLAINTEXT_MACRO_H_