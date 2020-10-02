import ida_bytes, ida_nalt, ida_idaapi, idaapi, ida_struct
from collections import OrderedDict

import ida_kernwin

vmtSelfPtr = -88
vmtIntfTable = -84
vmtAutoTable = -80
vmtInitTable = -76
vmtTypeInfo = -72
vmtFieldTable = -68
vmtMethodTable = -64
vmtDynamicTable = -60
vmtClassName = -56
vmtInstanceSize = -52
vmtParent = -48
vmtEquals = -44
vmtGetHashCode = -40
vmtToString = -36
vmtSafeCallException = -32
vmtAfterConstruction = -28
vmtBeforeDestruction = -24
vmtDispatch = -20
vmtDefaultHandler = -16
vmtNewInstance = -12
vmtFreeInstance = -8
vmtDestroy = -4

ikUnknown = 0x00
ikInteger = 0x01
ikChar = 0x02
ikEnumeration = 0x03
ikFloat = 0x04
ikString = 0x05
ikSet = 0x06
ikClass = 0x07
ikMethod = 0x08
ikWChar = 0x09
ikLString = 0x0A
ikWString = 0x0B
ikVariant = 0x0C
ikArray = 0x0D
ikRecord = 0x0E
ikInterface = 0x0F
ikInt64 = 0x10
ikDynArray = 0x11
ikUString = 0x12
ikClassRef = 0x13
ikPointer = 0x14
ikProcedure = 0x15
ikCString = 0x20
ikWCString = 0x21
ikResString = 0x22
ikVMT = 0x23
ikGUID = 0x24
ikRefine = 0x25
ikConstructor = 0x26
ikDestructor = 0x27
ikProc = 0x28
ikFunc = 0x29
ikLoc = 0x2A
ikData = 0x2B
ikDataLink = 0x2C
ikExceptName = 0x2D
ikExceptHandler = 0x2E
ikExceptCase = 0x2F
ikSwitch = 0x30
ikCase = 0x31
ikFixup = 0x32
ikThreadVar = 0x33

# type_sizes = {
#     b"Boolean":1,
#     b"AnsiChar":1,
#     b"Char":2,
#     b"ShortInt":1,
#     b"Byte":1,
#     b"Word":2,
#     b"WideChar":2,
#     b"ByteBool":1,
#     b"WordBool":2,
#
# }

type_sizes = {
-1: ("None",1),
0x00 : ("ikUnknown",1 ),
0x01 : ("ikInteger",4 ),
0x02 : ("ikChar",1 ),
0x03 : ("ikEnumeration",1 ),
0x04 : ("ikFloat",1 ),
0x05 : ("ikString",1 ),
0x06 : ("ikSet",1 ),
0x07 : ("ikClass",4 ),
0x08 : ("ikMethod",1 ),
0x09 : ("ikWChar",2 ),
0x0A : ("ikLString",1 ),
0x0B : ("ikWString",1 ),
0x0C : ("ikVariant",1 ),
0x0D : ("ikArray",1 ),
0x0E : ("ikRecord",1 ),
0x0F : ("ikInterface",4 ),
0x10 : ("ikInt64",1 ),
0x11 : ("ikDynArray",1 ),
0x12 : ("ikUString",4 ),
0x13 : ("ikClassRef",1 ),
0x14 : ("ikPointer",4 ),
0x15 : ("ikProcedure",1 ),
0x20 : ("ikCString",1 ),
0x21 : ("ikWCString",1 ),
0x22 : ("ikResString",1 ),
0x23 : ("ikVMT",1 ),
0x24 : ("ikGUID",1 ),
0x25 : ("ikRefine",1 ),
0x26 : ("ikConstructor",1 ),
0x27 : ("ikDestructor",1 ),
0x28 : ("ikProc",1 ),
0x29 : ("ikFunc",1 ),
0x2A : ("ikLoc",1 ),
0x2B : ("ikData",1 ),
0x2C : ("ikDataLink",1 ),
0x2D : ("ikExceptName",1 ),
0x2E : ("ikExceptHandler",1 ),
0x2F : ("ikExceptCase",1 ),
0x30 : ("ikSwitch",1 ),
0x31 : ("ikCase",1 ),
0x32 : ("ikFixup",1 ),
0x33 : ("ikThreadVar",1 ),
}



def get_class_name(cls_addr):
    class_name = ida_bytes.get_strlit_contents(ida_bytes.get_wide_dword(cls_addr + vmtClassName), ida_idaapi.BADADDR, ida_nalt.STRTYPE_PASCAL)
    return class_name


def get_field_table_addr(cls_addr):
    return ida_bytes.get_wide_dword(cls_addr + vmtFieldTable)


def get_parent_addr(cls_addr):
    return ida_bytes.get_wide_dword(cls_addr + vmtParent)

def get_instance_size(cls_addr):
    return ida_bytes.get_wide_dword(cls_addr + vmtInstanceSize)



class byte_reader:
    def __init__(self, addr):
        self.addr = addr
        self.pos = 0
    
    def get_word(self, pos=None):
        if pos is None:
            pos = self.pos
            self.pos += 2
        return ida_bytes.get_wide_word(self.addr + pos)
    
    def get_dword(self, pos=None):
        if pos is None:
            pos = self.pos
            self.pos += 4
        return ida_bytes.get_wide_dword(self.addr + pos)
    
    def get_byte(self, pos=None):
        if pos is None:
            pos = self.pos
            self.pos += 1
        return ida_bytes.get_wide_byte(self.addr + pos)
    
    def get_delphi_string(self, pos=None):
        print("get_delphi_string: addr = 0x%08X" % (self.addr + (pos if pos else self.pos)))
        ida_bytes.del_items(self.addr + (pos if pos else self.pos), ida_bytes.DELIT_EXPAND, 1)
        s = ida_bytes.get_strlit_contents(self.addr + (pos if pos else self.pos), ida_idaapi.BADADDR, ida_nalt.STRTYPE_PASCAL)
        if pos is None:
            self.pos += (len(s) + 1)
        return s
    
    def get_bytes(self, size, pos=None):
        if pos is None:
            pos = self.pos
            self.pos += size
        return ida_bytes.get_bytes(self.addr + pos, size)
    
    def get_curr_addr(self):
        return self.addr + self.pos


class FieldTableEntry:
    def __init__(self, FieldOffset=None, TypeIndex=None, Name=None, ClassName=None):
        self.FieldOffset = FieldOffset
        self.TypeIndex = TypeIndex
        self.Name = Name
        self.ClassName = ClassName
    
    def parse(self, addr):
        print("FieldTableEntry: parse. addr type = %s" % type(addr))
        print(type(addr) is byte_reader)
        print("0x%08X" % addr.get_curr_addr())
        if type(addr) is byte_reader:
            reader = addr
        else:
            reader = byte_reader(addr)
        self.FieldOffset = reader.get_dword()
        self.TypeIndex = reader.get_word()
        self.Name = reader.get_delphi_string()
        return self


class FieldTableEntryEx:
    def __init__(self, Flags=None, TypeRef=None, Offset=None, Name=None, AtrrDataLen=None, AtrrData=None):
        self.Flags = Flags
        self.TypeRef = TypeRef
        self.Offset = Offset
        self.Name = Name
        self.AtrrDataLen = AtrrDataLen
        self.AtrrData = AtrrData
    
    def parse(self, addr):
        print("FieldTableEntryEx:parse addr = 0x%08X" % addr.get_curr_addr())
        if type(addr) is byte_reader:
            reader = addr
        else:
            reader = byte_reader(addr)
        self.Flags = reader.get_byte()
        tp_ref = reader.get_dword()
        if tp_ref:
            self.TypeRef = TypeInfo().parse(ida_bytes.get_wide_dword(tp_ref))
        self.Offset = reader.get_dword()
        self.Name = reader.get_delphi_string()
        self.AtrrDataLen = reader.get_word()
        if self.AtrrDataLen > 2:
            self.AtrrData = reader.get_bytes(self.AtrrDataLen - 2)
        return self


class TypeInfo:
    def __init__(self, Kind=None, Name=None):
        self.Kind = Kind
        self.Name = Name
    
    def parse(self, addr):
        if type(addr) is byte_reader:
            reader = addr
        else:
            reader = byte_reader(addr)
        self.Kind = reader.get_byte()
        self.Name = reader.get_delphi_string()
        return self


class FieldTable:
    def __init__(self, count=None, typesTab=None, FieldTableEntries=None, excount=None, FieldTableEntriesEx=None):
        self.count = count
        self.ClassTypesTab = typesTab
        self.FieldTableEntries = FieldTableEntries
        self.excount = excount
        self.FieldTableEntriesEx = FieldTableEntriesEx
    
    def get_field_classname(self, idx):
        print("get_field_classname: addr = 0x%08X" % (self.ClassTypesTab + 2 + 4 * idx))
        addr = self.ClassTypesTab + 2 + 4 * idx
        print("get_field_classname: ClsAddr = 0x%08X" % ida_bytes.get_wide_dword(addr))
        return get_class_name(ida_bytes.get_wide_dword(ida_bytes.get_wide_dword(addr)))
    
    def parse(self, addr):
        print("FieldTable: Parse addr = 0x%08X" % addr)
        reader = byte_reader(addr)
        self.count = reader.get_word()
        self.ClassTypesTab = reader.get_dword()
        self.FieldTableEntries = []
        print("FieldTable.count = %d" % self.count)
        for i in range(0, self.count):
            entry = FieldTableEntry().parse(reader)
            entry.ClassName = self.get_field_classname(entry.TypeIndex)
            self.FieldTableEntries.append(entry)
        self.excount = reader.get_word()
        print("FieldTable.excount = %d" % self.excount)
        print("0x%08X" % reader.get_curr_addr())
        self.FieldTableEntriesEx = []
        for i in range(0, self.excount):
            print(i)
            exentry = FieldTableEntryEx().parse(reader)
            self.FieldTableEntriesEx.append(exentry)
        return self


class ClassRTTI:
    def __init__(self, IntfTable=None, AutoTable=None, InitTable=None, FieldTable=None, MethodTable=None, DynamicTable=None, ClassName=None, InstanceSize=None,
                 ParentAddr=None, Parent=None, addr=None):
        self.IntfTable = IntfTable
        self.AutoTable = AutoTable
        self.InitTable = InitTable
        self.FieldTable = FieldTable
        self.MethodTable = MethodTable
        self.DynamicTable = DynamicTable
        self.ClassName = ClassName
        self.InstanceSize = InstanceSize
        self.ParentAddr = ParentAddr
        self.Parent = Parent
        self.addr = addr
    
    def parse(self, addr):
        print("ClassRTTI: parse addr 0x%08X" % addr)
        self.addr = addr
        if get_field_table_addr(addr):
            self.FieldTable = FieldTable().parse(get_field_table_addr(addr))
        self.ClassName = get_class_name(addr)
        self.InstanceSize = get_instance_size(addr)
        self.ParentAddr = get_parent_addr(addr)
        print("ClassRTTI: parse addr 0x%08X" % addr)
        if self.ParentAddr:
            self.Parent = ClassRTTI().parse(ida_bytes.get_wide_dword(self.ParentAddr))
        return self
    
    def print_fields(self):
        if self.Parent:
            self.Parent.print_fields()
        if self.FieldTable:
            fields = {}
            for entry in self.FieldTable.FieldTableEntries:
                fields[entry.FieldOffset] = (entry.FieldOffset, entry.ClassName, -1, entry.Name)
            for exentry in self.FieldTable.FieldTableEntriesEx:
                if exentry.Offset not in fields:
                    fields[exentry.Offset] = (exentry.Offset, exentry.TypeRef.Name if exentry.TypeRef else b"None", exentry.TypeRef.Kind if exentry.TypeRef else -1, exentry.Name)
            fields = OrderedDict(sorted(fields.items()))
            for f in fields:
                print("\t%04X:\t%s(%d:%s)\t%s" % (fields[f][0], fields[f][1],fields[f][2],type_sizes[fields[f][2]][0],fields[f][3]))
    
    def get_fields(self,fields_dict = None):
        if fields_dict:
            fields = fields_dict
        else:
            fields = {}
        if self.Parent:
            fields = self.Parent.get_fields(fields)
        if self.FieldTable:
            for entry in self.FieldTable.FieldTableEntries:
                fields[entry.FieldOffset] = (entry.FieldOffset, entry.ClassName, -1, entry.Name)
            for exentry in self.FieldTable.FieldTableEntriesEx:
                if exentry.Offset not in fields:
                    fields[exentry.Offset] = (exentry.Offset, exentry.TypeRef.Name if exentry.TypeRef else b"None", exentry.TypeRef.Kind if exentry.TypeRef else -1, exentry.Name)
            fields = OrderedDict(sorted(fields.items()))
        return fields

# def parse_field_table(addr):


def parse_borland_class_rtti(addr):
    class_name = ida_bytes.get_strlit_contents(ida_bytes.get_wide_dword(addr + vmtClassName), ida_idaapi.BADADDR, ida_nalt.STRTYPE_PASCAL)
    print("Class name: %s" % class_name.decode())
    ft = FieldTable().parse(get_field_table_addr(addr))

flags_dict = {1:idaapi.FF_BYTE,
              2:idaapi.FF_WORD,
              4:idaapi.FF_DWORD}
def create_struct(name,fields,size):

    struct_id = idaapi.get_struc_id(name)
    # print struct_id
    if struct_id != idaapi.BADADDR:
        i = ida_kernwin.ask_yn(0, "A class structure for %s already exists. Are you sure you want to remake it?" % name)
        if i == idaapi.BADADDR:
            return
        if i == 1:
            idaapi.del_struc_members(idaapi.get_struc(struct_id), 0, idaapi.get_struc_size(struct_id))
            # struct_id = idc.AddStrucEx(idaapi.BADADDR, name + "_vtbl", 0)
    else:
        struct_id = idaapi.add_struc(idaapi.BADADDR, name, 0)
    if struct_id == idaapi.BADADDR:
        Warning("Could not create the class structure!.\nPlease check something.")
        return
    sptr = idaapi.get_struc(struct_id)
    for off in fields:
        off, type_name, type_kind, field_name = fields[off]
        print("Process field. Off = 0x%04X, type_name = %s (%d: %s), field_name = %s"%(off, type_name,type_kind, type_sizes[type_kind][0], field_name))
        type_size = type_sizes[type_kind][1]
        ret = ida_struct.add_struc_member(sptr,field_name.decode(),off,flags_dict[type_size],None,type_size)
        if ret != 0:
            ida_kernwin.warning("Unknown error! Err = %d" % ret)
            return
        mptr = ida_struct.get_member(sptr,off)
        ida_struct.set_member_cmt(mptr," --> %s (%d: %s)"%(type_name.decode(),type_kind,type_sizes[type_kind][0]),False)
    struct_size = ida_struct.get_struc_size(sptr)
    if size < struct_size:
        ida_kernwin.warning("Struct create error! final size (%d) > instanse size (%d)" % (struct_size,size))
    elif size > struct_size:
        for i in range(size - struct_size):
            ida_struct.add_struc_member(sptr, "dummy%d"%i, idaapi.BADADDR, idaapi.FF_BYTE, None, 1)
    



# cls = ClassRTTI().parse(0x0052774C)
# cls.print_fields()

class DelphiRTTIPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "Nope"
    wanted_name = "Delphi RTTI Class Reconstructor"
    wanted_hotkey = ""

    @staticmethod
    def init():
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(*args):
        addr = ida_kernwin.get_screen_ea()
        cls = ClassRTTI().parse(addr)
        create_struct(cls.ClassName.decode(),cls.get_fields(),cls.InstanceSize)
        


    @staticmethod
    def term():
        pass


def PLUGIN_ENTRY():
    return DelphiRTTIPlugin()



