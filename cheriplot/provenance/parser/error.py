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
Common parser errors.
"""

class SubgraphMergeError(RuntimeError):
    """
    Exception raised when there is an error during the merge
    of partial results from multiprocessing workers.
    """
    pass


class MissingParentError(RuntimeError):
    """
    Exception raised when attempting to create a provenance node but a
    valid parent is not found.
    This is a fatal error condition.
    """
    pass


class DereferenceUnknownCapabilityError(RuntimeError):
    """
    Exception raised when a capability dereference is found
    but it is not possible to determine the corresponding
    vertex in the graph where the dereference should be registered.
    This happens when a previously unseen capability register is
    dereferenced or in case of bugs in the vertex propagation in
    the register set.
    This is a fatal error condition.
    """
    pass


class ReturnToUnexpectedAddress(RuntimeError):
    """
    Exception raised by the call-graph parser.
    When a return is found to land to an address
    different from the expected return address for a previous
    frame.
    """
    pass


class UnexpectedOperationError(RuntimeError):
    """
    Exception raised when a seemingly impossible operation
    occurred.
    This is a fatal error condition.
    """
    pass
