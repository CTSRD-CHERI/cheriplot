import json
size_range = range(0, 16)
array_sizes = [2**i for i in size_range]
start_line = 201
line_number = start_line
file_path = "/root/cheri/cheriplot/cheriplot/cheriverify/annotator/annotation.json"
malloc_pointer_name_template = "heap_var_malloc{}_p"
calloc_pointer_name_template = "heap_var_calloc{}_p"
malloc_pointer_names = [malloc_pointer_name_template.format(str(sz)) for sz in array_sizes]
calloc_pointer_names = [calloc_pointer_name_template.format(str(sz)) for sz in array_sizes]
annoation = dict()
annoation["test_func"] = dict()
for i in size_range:
    sz = array_sizes[i]
    name = calloc_pointer_name_template.format(str(sz))
    annoation["test_func"][name] = {
        "expected_length": sz,
        "line_number": line_number
    }
    line_number += 1
line_number += 1 # for the comment
for i in size_range:
    sz = array_sizes[i]
    name = malloc_pointer_name_template.format(str(sz))
    annoation["test_func"][name] = {
        "expected_length": sz,
        "line_number": line_number
    }
    line_number += 1
annoation["test_func"]["ap"] = {
    "expected_length": 24,
    "line_number": 156
}
with open(file_path, "w") as f:
    f.write(json.dumps(annoation))