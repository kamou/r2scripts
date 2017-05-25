import r2pipe
import re
import string


class R2(object):
    def __init__(self, name):
        self.name = name

        self.r2 = r2pipe.open()

        bininfo = self.r2.cmdj("ij")["bin"]
        self.arch = bininfo["arch"]
        self.bits = bininfo["bits"]
        self.regs = self.r2.cmdj("drlj")
        self.switch_flagspace(self.name)

        self.sections = self.get_sections()
        imports = self.get_imports()
        self.imports = {}
        for imp in imports:
            self.imports[imp["plt"]] = imp["name"]
        exports = self.get_exports()
        self.exports = {}
        for exp in exports:
            self.exports[exp["name"]] = exp["vaddr"]

    def get_reg(self, reg):
        return self.get_regs()[reg]

    def get_regs(self):
        return self.r2.cmdj("drj")

    def get_maps(self):
        return self.r2.cmdj("dmj")

    def get_sections(self):
        return self.r2.cmdj("Sj")

    def get_imports(self):
        return self.r2.cmdj("iij")

    def get_exports(self):
        return self.r2.cmdj("iEj")

    def read_mem(self, address, size):
        hexdata = self.r2.cmd("p8 {} @ {:#x}".format(size, address))
        return hexdata.decode('hex')

    def write_mem(self, address, data):
        self.r2.cmd("wx {} @ {:#x}".format(data.encode("hex"), address))

    def seek(self, addr=None):
        if addr:
            self.r2.cmd("s {:#x}".format(addr))
        return int(self.r2.cmd("s"), 16)

    def switch_flagspace(self, name):
        self.r2.cmd("fs {}".format(name))

    def set_flag(self, section, name, size, address):
        name = "{}.{}.{}".format(self.name, section, name)
        self.r2.cmd("f {} {} @ {}".format(name, size, address))

    def get_flags(self, section=None):
        flags = {}
        for flag in self.r2.cmdj("fj"):
            name = flag["name"]
            offset = flag["offset"]
            if section and name.startswith("{}.{}.".format(self.name, section)):
                flags[name] = offset
            elif not section:
                flags[name] = offset
        return flags
    def set_comment(self, comment, address=None):
        if address:
            self.r2.cmd("CC {} @ {:#x}".format(comment, address))
        else:
            self.r2.cmd("CC {}".format(comment))

    def integer(self, s):
        regs = self.get_regs()
        flags = self.get_flags()
        if s in regs:
            v = regs[s]
        elif s in flags:
            v = flags[s]
        elif s in self.exports:
            v = self.exports[s]
        elif s.startswith("0x"):
            v = int(s, 16)
        else:
            v = int(s)
        return v

debugger = R2("regtrace")
debugger.r2.cmd("dcu main")
debugger.r2.cmd("e scr.color=false")
found = []

while debugger.r2.cmd("dr"):
    debugger.r2.cmd("ds")
    for l in debugger.r2.cmd("drr").split("\n"):
        m = re.search(" \((.*?)\) ", l)
        if m:
            for g in m.groups():
                smatch = g
                if smatch not in found:
                    for s in found:
                        if (smatch != s) and (s in smatch):
                            found[found.index(s)] = smatch
                            break
                        if (smatch != s) and (smatch in s):
                            break
                    else:
                        found.append(smatch)

for s in found:
    print s
