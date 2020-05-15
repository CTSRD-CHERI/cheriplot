# generate random C programs with combinations of different data types and calls
# type: 
from random import *
from enum import IntEnum
import sys
import string
import time

array_type = ("array")
pointer_type = ("*")
aggregate_type = ("union", "struct")
floating_point_type = ("float", "double")
integer_type = ("unsigned char", "char", "unsigned short", "short", "unsigned int", "int", "long", "unsigned long",
                "long long", "unsigned long long")
no_bits = [1, 1, 2, 2, 4, 4, 4, 4, 8, 8]
base_type = integer_type + floating_point_type
modifier = ["const", "volatile", "static"]
valid_symbol_characters = string.ascii_lowercase + "_"
used_names = {}


def get_random_name():
    name = None
    while not name:
        no_characters = randint(4, 10)
        name = ""
        for i in range(no_characters):
            name += choice(valid_symbol_characters)
        if name in used_names:
            name = None
    used_names[name] = True
    return name


class base_type_content:
    """
    generate a random value depending on the given type
    """

    def __init__(self, t="int"):
        self.value = None
        if t in floating_point_type:
            self.value = random()
        elif t in integer_type:
            if "unsigned" in t:
                min_value = 0
                max_value = 255
            else:
                min_value = -128
                max_value = 127
            self.value = randrange(min_value, max_value)
        else:
            sys.exit(1)

    def __repr__(self):
        return "{}".format(self.value)

    def __str__(self):
        return "{}".format(self.value)


class pointer_content:
    """
    generate a pointer pointing to some variable in scope
    """

    def __init__(self, var_list: list):
        if len(var_list) > 0:
            self.target = choice(var_list)
        else:
            self.target = None

class array_content:
    """
    generate the content for an array
    """
    def __init__(self):
        self.number_of_elements = randint(1, 100000)
        self.available_choices = list()
        for t in base_type:
            self.available_choices.append(t)
        self.type = choice(self.available_choices)

class aggregate_definition:
    """
    the definition of an aggregate type which specifies all members
    """

    def __init__(self, counter):
        self.type = choice(aggregate_type)
        self.name = "test_" + self.type + "_" + str(counter)
        self.size = None
        self.members = list()
        self.num_element = randint(0, 6)
        self.available_choices = []
        for t in base_type:
            self.available_choices.append(t)
        for t in pointer_type:
            self.available_choices.append(t)
        self.name_l = list()
        self.type_l = list()
        for i in range(self.num_element):
            name = get_random_name()
            t = choice(self.available_choices)
            self.members.append((t, name))
            self.name_l.append(name)
            self.type_l.append(t)

    def __repr__(self):
        result = "typedef " + self.type + " " + self.name + "{" + ";".join(
            [(t if t != "*" else "void" + t) + " " + name for t, name in
             zip(self.type_l, self.name_l)]) + ";}" + self.name
        return result

    def __str__(self):
        result = "typedef " + self.type + " " + self.name + "{" + ";".join(
            [(t if t != "*" else "void" + t) + " " + name for t, name in
             zip(self.type_l, self.name_l)]) + ";}" + self.name
        return result


class aggregate_content:
    """
    generate the content of an aggregate variable, for each member in the definition
    generate a random value
    """

    def __init__(self, declared_line: int, var_list: list, definition: aggregate_definition):
        self.definition = definition
        self.members = list()
        self.num_element = len(self.definition.members)
        for i in range(self.num_element):
            member_type, name = self.definition.members[i]
            self.members.append(variable(declared_line, var_list, [], member_type, name))


class variable:
    """
    generate a variable with random type and random value and random name
    """

    def __init__(self, declared_line: int, var_list: list, aggregate_definition_list: list = [], var_type: str = None,
                 name: str = None):
        # if name is not given, generate a new name
        if name:
            self.name = name
        else:
            self.name = get_random_name()  # for annotation
        self.declared_line = declared_line  # for annotation
        if var_type:
            self.type = var_type
        else:
            self.available_choices = []
            for t in array_type:
                self.available_choices.append(t)
            for t in base_type:
                self.available_choices.append(t)
            if len(var_list) > 0:
                for t in pointer_type:
                    self.available_choices.append(t)
            if len(aggregate_definition_list) > 0:
                for t in aggregate_type:
                    self.available_choices.append(t)
            self.type = choice(self.available_choices)
        self.content = None
        if self.type in aggregate_type:
            self.content = aggregate_content(declared_line, var_list, choice(aggregate_definition_list))
        elif self.type in pointer_type:
            self.content = pointer_content(var_list)
        elif self.type in base_type:
            self.content = base_type_content(self.type)
        elif self.type in array_type:
            self.content = array_content()
        else:
            raise ValueError("Invalid type: {}".format(self.type))

    def get_value_str(self):
        if self.type in base_type:
            return str(self.content)
        elif self.type in pointer_type:
            if self.content.target.name:
                return "&" + self.content.target.name
            else:
                return "NULL"
        elif self.type in aggregate_type:
            if self.content.definition.type == "union":
                if len(self.content.members) > 0:
                    return "{" + self.content.members[0].get_value_str() + "}"
                else:
                    return "{}"
            else:
                return "{" + ",".join([m.get_value_str() for m in self.content.members]) + "}"
        elif self.type in array_type:
            return "{}"
        else:
            raise ValueError("Invalid type")

    def get_type_str(self):
        if self.type in base_type:
            # type<space>name
            return self.type + " " + self.name
        elif self.type in pointer_type:
            # void*<space>name
            return "void " + self.type + " " + self.name
        elif self.type in aggregate_type:
            return self.content.definition.name + " " + self.name
        elif self.type in array_type:
            return self.content.type + " " + self.name + "[" + str(self.content.number_of_elements) + "]"
        else:
            raise ValueError("Invalid type")

class function:

    def __init__(self):
        self.parameters = list()
        self.variables = list()

class test_case:

    def __init__(self):
        self.line_counter = 1
        self.aggregate_definition_list = list()  # collection of aggregate definitions
        self.no_aggregate_definitions = 5
        for i in range(self.no_aggregate_definitions):
            self.aggregate_definition_list.append(aggregate_definition(i))
        self.globals = list()  # collection of global variables
        self.functions = list()  # collection of functions to include and call
        self.no_globals = 20
        for i in range(self.no_globals):
            self.globals.append(variable(self.line_counter, self.globals, self.aggregate_definition_list))
            self.line_counter += 1

    def __repr__(self):
        output = ""
        output += "/* Test Case generated on {}\n".format(time.strftime('%X %x %Z'))
        output += "* Author: Yixing Zheng */\n"
        for ad in self.aggregate_definition_list:
            output += str(ad) + ";\n"
        for g in self.globals:
            output += g.get_type_str() + " = " + g.get_value_str() + ";\n"
        for f in self.functions:
            output += str(f) + "\n"
        return output


class test_suite:

    def __init__(self):
        self.test_cases = list()

    def convert_to_files(self, directory="./"):
        count = 1
        import os
        complete_path = os.path.abspath(directory)
        for tc in self.test_cases:
            file_path = os.path.join(complete_path, "test_case_{}.c".format(str(count)))
            with open(file_path, "w") as f:
                f.write(str(tc))
            print(str(tc))
            count += 1

    def add_test(self):
        self.test_cases.append(test_case())


if __name__ == "__main__":
    ts = test_suite()
    ts.add_test()
    ts.convert_to_files(directory="/root/cheri/")


