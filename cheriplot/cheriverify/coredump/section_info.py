class section_info:

    def __init__(self, start_addr, end_addr, name, obj_path):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.obj_path = obj_path
        self.section_name = name
        self.section_size = int(end_addr, 16) - int(start_addr, 16)
    
    def __repr__(self):
        return "Section(.{})({} - {})[size={} Byte] for objfile: {}".format(self.section_name, self.start_addr, self.end_addr, str(self.section_size), self.obj_path)

    def __str__(self):
        return "Section(.{})({} - {})[size={} Byte] for objfile: {}".format(self.section_name, self.start_addr, self.end_addr, str(self.section_size), self.obj_path)

    def get_size(self):
        return self.section_size
