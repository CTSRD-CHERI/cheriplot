#-
# Copyright (c) 2016-2017 Yixing(Ethan) Zheng
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

from symbol_type import symbol_type

# symbol_info stores the expected size, type of a symbol whose information is read either from the .symtab or .cap-reloc section in ELF
class symbol_info:

    # a list of valid types for symbols, currently only OBJECT, FUNC, NOTYPE are extracted and checked
    valid_types = [t.name for t in symbol_type]

    def __init__(self, expected_size: int, expected_type: str, objfile_path: str):
        self.expected_size = expected_size
        self.objfile_path = objfile_path
        # Exception is raised when the symbol type is not supported
        if expected_type in symbol_info.valid_types:
            self.expected_type = symbol_type[expected_type]
        else:
            raise ValueError("Invalid type:{}".format(expected_type))

    def __repr__(self):
        return "TYPE: {}, Expected size: {}, Objfile path: {}".format(self.expected_type, str(self.expected_size), self.objfile_path)
    
    def __str__(self):
        return "TYPE: {}, Expected size: {}, Objfile path: {}".format(self.expected_type, str(self.expected_size), self.objfile_path)

