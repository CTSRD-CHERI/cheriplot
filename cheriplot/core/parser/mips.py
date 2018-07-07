#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
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

"""
CHERI-MIPS specific core parser components.
"""

import exrex

from itertools import chain
from .base import CallbacksManager, IClass

class CheriMipsCallbacksManager(CallbacksManager):
    """
    A concrete CallbacksManager that handles callbacks for
    CHERI-mips traces.
    """

    iclass_map = {
        IClass.I_CAP_LOAD: list(chain(
            exrex.generate("cl[dc][ri]?|cl[bhw][u]?[ri]?"),
            exrex.generate("cll[cd]|cll[bhw][u]?"),
            ["clcbi"])),
        IClass.I_CAP_STORE: list(chain(
            exrex.generate("cs[bhwdc][ri]?"),
            exrex.generate("csc[cbhwd]"),
            ["cscbi"])),
        IClass.I_CAP_CAST: [
            "ctoptr", "cfromptr", "cfromddc"],
        IClass.I_CAP_ARITH: [
            "cincoffset", "csetoffset", "csub", "cmove"],
        IClass.I_CAP_BOUND: [
            "csetbounds", "csetboundsexact", "candperm"],
        IClass.I_CAP_FLOW: [
            "cbtu", "cbts", "cjr", "cjalr",
            "ccall", "creturn", "cbez", "cbnz"],
        IClass.I_CAP_CPREG: [
            "csetdefault", "cgetdefault", "cgetepcc", "csetepcc",
            "cgetkcc", "csetkcc", "cgetkdc", "csetkdc", "cgetpcc",
            "cgetpccsetoffset"],
        IClass.I_CAP_CMP: [
            "ceq", "cne", "clt", "cle", "cltu", "cleu", "cexeq"],
        IClass.I_CAP_OTHER: [
            "cgetperm", "cgettype", "cgetbase", "cgetlen",
            "cgettag", "cgetsealed", "cgetoffset",
            "cseal", "cunseal",
            "ccleartag", "cclearregs",
            "cgetcause", "csetcause", "ccheckperm", "cchecktype",
            "clearlo", "clearhi", "cclearlo", "cclearhi",
            "fpclearlo", "fpclearhi", "creadhwr", "cwritehwr",
            "cgetnull"]
        }
    iclass_map[IClass.I_CAP] = list(chain(*iclass_map.values()))
