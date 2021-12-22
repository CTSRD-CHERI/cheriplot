import json

class annotation:

    def __init__(self, annotation_dict: dict):
        self.line_number = int(annotation_dict["line_number"])
        self.expected_length = int(annotation_dict["expected_length"])
        self.counter_wrong = 0
        self.counter_correct = 0
    
    def __repr__(self):
        return "line NO: {}, expected Length: {}".format(str(self.line_number), str(self.expected_length))

    def __str__(self):
        return "line NO: {}, expected Length: {}".format(str(self.line_number), str(self.expected_length))

class annotator:

    def __init__(self):
        with open("/root/cheri/cheriplot/cheriplot/cheriverify/annotator/annotation.json", "r") as f:
            line = "".join(f.readlines())
            self.data = json.loads(line)

    def has_annotated_variables(self, function_name:str):
        if not function_name or function_name == "Unnamed Segment":
            return False
        if function_name in self.data:
            return True

    def find_annotation(self, function_name:str, variable_name:str)-> annotation:
        if not self.has_annotated_variables(function_name):
            return None
        if variable_name == "Unamed Variable":
            return None
        if function_name not in self.data:
            return None
        if variable_name not in self.data[function_name]:
            return None
        return annotation(self.data[function_name][variable_name])

if __name__ == "__main__":
    a = annotator()
    print(a.find_annotation("test_func", "heap_var_calloc1_p"))