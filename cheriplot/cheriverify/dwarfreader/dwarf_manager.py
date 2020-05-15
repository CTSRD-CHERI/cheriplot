# read and manage the dwarf information read
import sys
sys.path.append(r"/root/cheri/cheriplot/cheriplot/cheriverify/")
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/coredump')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/dwarfreader')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/')
from coredump.colour_print import *
from coredump.capability import capability
from coredump.object_file_boundary import object_file_boundary
from coredump.capability import capability
from coredump.symbol_table_reader import symbol_table_reader
from coredump.symbol_info import symbol_info
from coredump.symbol_table_reader import symbol_table_reader
from dwarfreader.dwarf_globals import generate_global_lookup_table_json
from dwarf_variable_type import dwarf_variable_data_type
from annotator.annotator import annotator, annotation
import pickle
import re
from subprocess import Popen, PIPE, TimeoutExpired
import json
from enum import IntEnum



class dwarf_stack_variable_location_type(IntEnum):
    LOC_CAP_REGISTER = 1
    LOC_CAP_OFFSET = 2
    LOC_UNHANDLED = 3



class dwarf_aggregate_content:

    def __init__(self, json_obj):
        self.name = json_obj["name"]
        self.offset = int(json_obj["offset"])
        self.size = int(json_obj["size"])
    
class dwarf_stack_variable_location:

    def __init__(self, json_obj, objfile_base):
        self.type = dwarf_stack_variable_location_type(int(json_obj["type"]))
        self.offset = int(json_obj["offset"])
        self.lowpc = int(json_obj["lowpc"], 16) + objfile_base
        self.highpc = int(json_obj["highpc"], 16) + objfile_base
        self.cap_register = json_obj["cap_register"]

class dwarf_stack_variable:

    def __init__(self, json_obj, objfile_base):
        self.variable_name = json_obj["name"]
        self.size = int(json_obj["size"])
        self.locations = [dwarf_stack_variable_location(k, objfile_base) for k in json_obj["locations"]]
        if "members" in json_obj:
            self.members = [dwarf_aggregate_content(k) for k in json_obj["members"]]
        else:
            self.members = None
        self.type =dwarf_variable_data_type(int(json_obj["type"]))
        self.line_number = int(json_obj["line"])
        self.annotation = None

    def __repr__(self):
        return "{} [size: {}](type: {})".format(self.variable_name, str(self.size), self.type)
    
    def __str__(self):
        return "{} [size: {}](type: {})".format(self.variable_name, str(self.size), self.type)


class dwarf_stack_function:

    def __init__(self, json_obj, objfile_base):
        self.function_name = json_obj["name"]
        self.lowpc = int(json_obj["lowpc"], 16) + objfile_base
        self.highpc = int(json_obj["highpc"], 16) + objfile_base
        self.parameters = [dwarf_stack_variable(k, objfile_base) for k in json_obj["parameters"]]
        self.variables = [dwarf_stack_variable(k, objfile_base) for k in json_obj["variables"]]
        self.cap_table_register = dict()
        self.setbound_pending_capabilities = dict()
        self.aggregate_variable_capabilities = dict()
        self.setbound_pending_subobject_capabilities = dict()
        self.andperm_pending_capabilities = dict()
        self.variables += self._unpack_variables_in_subblocks(json_obj["blocks"], objfile_base)

    def _unpack_variables_in_subblocks(self, json_array, objfile_base):
        # recursively extract the variables in the subblocks and put all results in one list
        result = list()
        for sub_block in json_array:
            for p in sub_block["parameters"]:
                raise ValueError("Subblock should not have variables")
            for v in sub_block["variables"]:
                result.append(dwarf_stack_variable(v, objfile_base))
            r = self._unpack_variables_in_subblocks(sub_block["blocks"], objfile_base)
            for v in r:
                result.append(v)
        return result

    def annotate(self, annotator: annotator):
        if annotator.has_annotated_variables(self.function_name):
            for p in self.parameters:
                # input("{} {}".format(self.function_name, p.variable_name))
                annotation = annotator.find_annotation(self.function_name, p.variable_name)
                if annotation:
                    
                    if p.line_number == annotation.line_number:
                        input("{} on line {} has annotation: {}. Confirm? [Enter]".format(p.variable_name, p.line_number, annotation))
                        p.annotation = annotation
            for v in self.variables:
                # input("{} {}".format(self.function_name, v.variable_name))
                annotation = annotator.find_annotation(self.function_name, v.variable_name)
                print(annotation)
                print(v.line_number)
                if annotation:
                    if v.line_number == annotation.line_number:
                        # input("{} on line {} has annotation: {}. Confirm? [Enter]".format(v.variable_name, v.line_number, annotation))
                        # raise ValueError("E")
                        v.annotation = annotation
            

    def __repr__(self):
        return "{}({}) [{}-{}]".format(self.function_name, ", ".join([str(v) for v in self.parameters]), str(hex(self.lowpc)), str(hex(self.highpc)))

    def __str__(self):
        return "{}({}) [{}-{}]".format(self.function_name, ", ".join([str(v) for v in self.parameters]), str(hex(self.lowpc)), str(hex(self.highpc)))

    def __eq__(self, other):
        if isinstance(other, dwarf_stack_function):
            return self.lowpc == other.lowpc and self.highpc == other.highpc
        return NotImplemented

    def __ne__(self, other):
        r = self.__eq__(other)
        if r is NotImplemented:
            return result
        return not result
    
    def __lt__(self, other):
        if max(self.highpc, other.highpc) - min(self.lowpc, other.lowpc) < (self.highpc - self.lowpc) + (other.highpc - other.lowpc):
            raise ValueError("Overlapping functions{} {}".format(self, other))
        return self.highpc <= other.lowpc

    def __gt__(self, other):
        if max(self.highpc, other.highpc) - min(self.lowpc, other.lowpc) < (self.highpc - self.lowpc) + (other.highpc - other.lowpc):
            raise ValueError("Overlapping functions{} {}".format(self, other))
        return self.lowpc >= other.highpc

# Generic tree node class 
class TreeNode(object): 
    def __init__(self, val:dwarf_stack_function): 
        self.val = val 
        self.left = None
        self.right = None
        self.height = 1

    def __str__(self):
        return self.val.__str__()

    def __repr__(self):
        return self.val.__repr__()
  
# This code of AVL Tree implementation is adapted from https://www.geeksforgeeks.org/avl-tree-set-1-insertion/
# AVL tree class which supports the  
# Insert operation 
class AVL_Tree(object): 
  
    # Recursive function to insert key in  
    # subtree rooted with node and returns 
    # new root of subtree. 
    def insert(self, root, key): 
      
        # Step 1 - Perform normal BST 
        if not root: 
            return TreeNode(key) 
        elif key < root.val: 
            root.left = self.insert(root.left, key) 
        else: 
            root.right = self.insert(root.right, key) 
  
        # Step 2 - Update the height of the  
        # ancestor node 
        root.height = 1 + max(self.getHeight(root.left), 
                           self.getHeight(root.right)) 
  
        # Step 3 - Get the balance factor 
        balance = self.getBalance(root) 
  
        # Step 4 - If the node is unbalanced,  
        # then try out the 4 cases 
        # Case 1 - Left Left 
        if balance > 1 and key < root.left.val: 
            return self.rightRotate(root) 
  
        # Case 2 - Right Right 
        if balance < -1 and key > root.right.val: 
            return self.leftRotate(root) 
  
        # Case 3 - Left Right 
        if balance > 1 and key > root.left.val: 
            root.left = self.leftRotate(root.left) 
            return self.rightRotate(root) 
  
        # Case 4 - Right Left 
        if balance < -1 and key < root.right.val: 
            root.right = self.rightRotate(root.right) 
            return self.leftRotate(root) 
  
        return root 
  
    def leftRotate(self, z): 
  
        y = z.right 
        T2 = y.left 
  
        # Perform rotation 
        y.left = z 
        z.right = T2 
  
        # Update heights 
        z.height = 1 + max(self.getHeight(z.left), 
                         self.getHeight(z.right)) 
        y.height = 1 + max(self.getHeight(y.left), 
                         self.getHeight(y.right)) 
  
        # Return the new root 
        return y 
  
    def rightRotate(self, z): 
  
        y = z.left 
        T3 = y.right 
  
        # Perform rotation 
        y.right = z 
        z.left = T3 
  
        # Update heights 
        z.height = 1 + max(self.getHeight(z.left), 
                        self.getHeight(z.right)) 
        y.height = 1 + max(self.getHeight(y.left), 
                        self.getHeight(y.right)) 
  
        # Return the new root 
        return y 
  
    def getHeight(self, root): 
        if not root: 
            return 0
  
        return root.height 
  
    def getBalance(self, root): 
        if not root: 
            return 0
  
        return self.getHeight(root.left) - self.getHeight(root.right) 
  
    def preOrder(self, root): 
  
        if not root: 
            return
  
        print("{0} ".format(root.val), end="") 
        self.preOrder(root.left) 
        self.preOrder(root.right) 
    
    def findFunction(self, root, addr: int):
        if root.val.lowpc <= addr < root.val.highpc:
            return root
        if addr >= root.val.highpc:
            if root.right is None:
                return None
            else:
                return self.findFunction(root.right, addr)
        elif addr < root.val.lowpc:
            if root.left is None:
                return None
            else:
                return self.findFunction(root.left, addr)

class dwarf_manager:

    def __init__(self, object_file_boundaries_file: str, dwarf_stack_executable_path:str, symbol_table: symbol_table_reader):
        self.functions = dict() # a map which allows to lookup by the object_file then by address
        self.function_lookup_tree = dict()
        self.avl_tree = AVL_Tree()
        prGreen("Dwarf manager: object file info read from {}".format(object_file_boundaries_file))
        self.extracted_info = dict()
        self.extracted_info["object_file_boundaries"] = pickle.load(open(object_file_boundaries_file, "rb") )
        self.object_files = [k for k in self.extracted_info["object_file_boundaries"]]
        self.symbol_table = symbol_table
        self.dwarf_stack_executable_path = dwarf_stack_executable_path
        self.dwarf_address_lookup, self.dwarf_name_lookup = generate_global_lookup_table_json(self.extracted_info["object_file_boundaries"], self.symbol_table)
        self.annotator = annotator()
        self._generate_dwarf_info_for_functions()

    def _generate_dwarf_info_for_functions(self):
        for objfile_path in self.object_files:
            objfile_base = self.extracted_info["object_file_boundaries"][objfile_path].base
            d = {}
            root = None
            t = self.avl_tree
            with Popen([self.dwarf_stack_executable_path, objfile_path], stdout=PIPE, stderr=PIPE, text=True) as dwarf_stack_proc:
                prGreen("Dwarf manager: extract dwarf information from {}".format(objfile_path))
                line = dwarf_stack_proc.stdout.read()
                json_obj = json.loads(line)
                func_list = []
                for o in json_obj:
                    if int(o["highpc"], 16) == 0:
                        start_addr = int(o["lowpc"], 16) + objfile_base
                        sym_info = self.symbol_table.find_symbol_at_addr(address=start_addr)
                        if sym_info:
                            if isinstance(sym_info, dict):
                                first_k = next(iter(sym_info))
                                sym_info = sym_info[first_k]
                            # prGreen("{} found as a function of size: {}, starting from address: {}".format(
                            #     o["name"], 
                            #     sym_info.expected_size, 
                            #     str(hex(start_addr)))
                            # )
                        else:
                            # prYellow("{} not found at address: {}".format(o["name"], str(hex(start_addr))))
                            continue
                        if sym_info.expected_size == 0:
                            continue
                        else:
                            new_highpc = int(o["lowpc"], 16) + sym_info.expected_size
                            o["highpc"] = str(hex(new_highpc))
                    f = dwarf_stack_function(o, objfile_base)
                    f.annotate(self.annotator)
                    d[f.lowpc] = f
                    root = t.insert(root, f)
            self.functions[objfile_path] = d
            self.function_lookup_tree[objfile_path] = root

    # function to find the object file where a cursor is pointing to
    def find_object_file(self, address:int) -> str:
        cap = capability()
        cap.cursor = str(hex(address))
        for k, boundary in self.extracted_info["object_file_boundaries"].items():
            if boundary.check_cursor_pointing_to_objfile(cap):
                return k
        return None

    def find_function_by_entry_addr(self, addr: int):
        # find the object file pointed to by the address 
        objfile_name = self.find_object_file(addr)
        if not objfile_name:
            return None
        if addr not in self.functions[objfile_name]:
            return None
        else:
            return self.functions[objfile_name][addr]

    def find_function_by_addr(self, addr: int):
        objfile_name = self.find_object_file(addr)
        if not objfile_name:
            return None
        return self.avl_tree.findFunction(self.function_lookup_tree[objfile_name], addr)

if __name__ == "__main__":
    object_file_boundaries_file = "/root/cheri/object_file_boundaries.pickle"
    section_info_file = "/root/cheri/section_info.pickle"
    dwarf_stack_executable_path = "/root/cheri-verify/dwarf_reader/read_stack"
    symbol_table = symbol_table_reader(object_file_boundaries_file, section_info_file)
    manager = dwarf_manager(object_file_boundaries_file, dwarf_stack_executable_path, symbol_table)
    addr = int("0x131d78", 16)
    print(manager.extracted_info["object_file_boundaries"])
    print(manager.function_lookup_tree)
    print(manager.find_object_file(addr))
    print(manager.find_function_by_addr(addr).val.variables)