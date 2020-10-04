header_files = ["inttypes.h", "stdio.h", "stdlib.h", "stdarg.h"]

function_template = """
extern void {}();
void __attribute__((noinline)){}() {{
{}
{}
}}
"""

main_template = """
/* struct declaration */
{} 
/* global variable declarations */
{} 
/* static variable declarations */
{}

extern void test_func(int count, ...);
void test_func(int count, ...) {{
    va_list ap;
    double sum = 0.0;
    /* Requires the last fixed parameter (to get the address) */
    va_start(ap, count); 
    /* Increments ap to the next argument. */
	sum += va_arg(ap, int);
	sum += va_arg(ap, int);
	sum += va_arg(ap, int); 
    va_end(ap);
    printf("Average is %lf\\n", sum / 3);
}}

int main(int argc, char** argv) {{
    test_func(argc, 4, 3, 4);
    /* struct variable declarations */
{}
    /* alloca calls */
{}
    /* heap calloc allocations */
{}
    /* heap malloc allocations */
{}
    /* stack variable declarations */
{}
    /* print statements */
{}
}}
"""
def generate_struct():
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    declaration_template = """
typedef struct test_struct{}{{
    {} a[{}];
    {} b;
    {} c[{}];
}}test_struct{};
    """
    variable_name_template = "test_struct_var{}"
    pointer_name_template = "test_struct{}_p"
    type_template = "test_struct{}"
    type_list = [type_template.format(str(sz)) for sz in array_sizes]
    variable_names = [variable_name_template.format(str(sz)) for sz in array_sizes]
    declarations = [declaration_template.format(str(sz), common_type, str(sz), common_type, common_type, str(sz), str(sz)) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]  
    variable_declarations = ["\t{} {};".format(type_list[i], variable_names[i], type_list[i], variable_names[i]) for i in size_range]
    print_statements = []
    for i in size_range:
        print_statements.append('\tprintf("Address to struct variable {} is: %p\\n", &{});'.format(variable_names[i], variable_names[i]))
        print_statements.append('\tprintf("Address to subobject a of {} is: %p\\n", &{}.a);'.format(variable_names[i], variable_names[i]))
        print_statements.append('\tprintf("Address to subobject b of {} is: %p\\n", &{}.b);'.format(variable_names[i], variable_names[i]))
        print_statements.append('\tprintf("Address to subobject c of {} is: %p\\n", &{}.c);'.format(variable_names[i], variable_names[i]))
    return declarations, variable_declarations, print_statements
      

def generate_stack():
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    variable_name_template = "stack_var{}"
    pointer_name_template = "stack_var{}_p"
    # test_function_name_template = "test_stack_variable{}"
    variable_names = [variable_name_template.format(str(sz)) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]    
    variable_declarations = ["\t{} {}[{}];".format(common_type, variable_names[i], array_sizes[i]) for i in size_range]
    pointer_assignments = ["\t{}* {} = &{}[0];".format(common_type, pointer_names[i], variable_names[i]) for i in size_range]
    print_statements = ['\tprintf("Address to stack variable {} is: %p\\n", &{}[0]);'.format(pointer_names[i], variable_names[i]) for i in size_range]
    return variable_declarations, print_statements

def generate_alloca():
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    alloca_template = "alloca({})"
    pointer_name_template = "stack_alloca{}_p"
    calloc_calls = [alloca_template.format(str(sz), common_type) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]
    alloca_variable_declarations = ["\t{}* {} = {};".format(common_type, pointer_names[i], calloc_calls[i]) for i in size_range]
    print_statements = ['\tprintf("Address to alloca allocation {} is: %p\\n", {});'.format(pointer_names[i], pointer_names[i]) for i in size_range]
    return alloca_variable_declarations, print_statements


def generate_global():
    # generate global variables
    # create references to global variables
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    variable_name_template = "global_var{}"
    pointer_name_template = "global_var{}_p"
    variable_names = [variable_name_template.format(str(sz)) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]
    global_variable_declarations = ["extern {} {}[{}];{} {}[{}];".format(common_type, variable_names[i], array_sizes[i], common_type, variable_names[i], array_sizes[i]) for i in size_range]
    print_statements = ['\tprintf("Address to global variable {} is: %p\\n", &{}[0]);'.format(pointer_names[i], variable_names[i]) for i in size_range]
    return global_variable_declarations, print_statements

def generate_static():
    # generate static variables
    # create references to global variables
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    variable_name_template = "static_var{}"
    pointer_name_template = "static_var{}_p"
    variable_names = [variable_name_template.format(str(sz)) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]
    static_variable_declarations = ["static {} {}[{}];".format(common_type, variable_names[i], array_sizes[i]) for i in size_range]
    print_statements = ['\tprintf("Address to static variable {} is: %p\\n", &{}[0]);'.format(pointer_names[i], variable_names[i]) for i in size_range]
    return static_variable_declarations, print_statements

def generate_malloc_heap():
    # generate static variables
    # create references to global variables
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    malloc_template = "malloc({} * sizeof({}))"
    pointer_name_template = "heap_var_malloc{}_p"
    malloc_calls = [malloc_template.format(str(sz), common_type) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]
    heap_malloc_variable_declarations = ["\t{}* {} = {};".format(common_type, pointer_names[i], malloc_calls[i]) for i in size_range]
    print_statements = ['\tprintf("Address to malloc heap allocation {} is: %p\\n", {});'.format(pointer_names[i], pointer_names[i]) for i in size_range]
    return heap_malloc_variable_declarations, print_statements

def generate_calloc_heap():
    # generate static variables
    # create references to global variables
    common_type = "uint8_t"
    size_range = range(0, 16)
    array_sizes = [2**i for i in size_range]
    malloc_template = "calloc({} , sizeof({}))"
    pointer_name_template = "heap_var_calloc{}_p"
    calloc_calls = [malloc_template.format(str(sz), common_type) for sz in array_sizes]
    pointer_names = [pointer_name_template.format(str(sz)) for sz in array_sizes]
    heap_calloc_variable_declarations = ["\t{}* {} = {};".format(common_type, pointer_names[i], calloc_calls[i]) for i in size_range]
    print_statements = ['\tprintf("Address to calloc heap allocation {} is: %p\\n", {});'.format(pointer_names[i], pointer_names[i]) for i in size_range]
    return heap_calloc_variable_declarations, print_statements

def generate_subobject():
    pass

global_declarations, global_print_statements = generate_global()
static_declarations, static_print_statements = generate_static()
stack_declarations, stack_print_statements = generate_stack()
alloca_declarations, alloca_print_statements = generate_alloca()
heap_malloc_variable_declarations, heap_malloc_print_statements = generate_malloc_heap()
heap_calloc_variable_declarations, heap_calloc_print_statements = generate_calloc_heap()
struct_declarations, struct_variable_declarations, strut_print_statements = generate_struct()
all_print_statements = "\n".join(
    global_print_statements + static_print_statements + stack_print_statements + alloca_print_statements + heap_malloc_print_statements + heap_calloc_print_statements + strut_print_statements)
stack_declaration_string = "\n".join(stack_declarations)
global_declaration_string = "\n".join(global_declarations)
static_declaration_string = "\n".join(static_declarations)
heap_malloc_declaration_string = "\n".join(heap_malloc_variable_declarations)
heap_calloc_declaration_string = "\n".join(heap_calloc_variable_declarations)
alloca_declaration_string = "\n".join(alloca_declarations)
struct_definition_string = "\n".join(struct_declarations)
struct_declaration_string = "\n".join(struct_variable_declarations)
for h in header_files:
    print("#include <{}>".format(h))
print(main_template.format(struct_definition_string, global_declaration_string, 
    static_declaration_string, struct_declaration_string, 
    alloca_declaration_string, heap_calloc_declaration_string, heap_malloc_declaration_string, 
    stack_declaration_string, all_print_statements))