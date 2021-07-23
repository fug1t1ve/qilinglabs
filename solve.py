from logging import getLogger
from qiling import Qiling
from qiling.const import QL_VERBOSE
import struct
import sys
from capstone import *
from qiling import *
from qiling.const import *
import os
from qiling.os.mapper import QlFsMappedObject

def unpack(arg1):
    if len(arg1) == 8:
        return struct.unpack('<Q', arg1)[0]
    if len(arg1) == 4:
        return struct.unpack('<L', arg1)[0]
    if len(arg1) == 2:
        return struct.unpack('<H', arg1)[0]
    if len(arg1) == 1:
        return arg1[0]

def leet(q):
    print(int(hex(q.reg.rax),16))

def my_uname(q,*args):
    a=args[0]
    o=os.uname()
    data=b'QilingOS'.ljust(65,b'\x00')
    data+=o[1].encode().ljust(65,b'\x00')
    data+=o[2].encode().ljust(65,b'\x00')
    data+=b'ChallengeStart'.ljust(65,b'\x00')
    data+=o[4].encode().ljust(65,b'\x00')
    data+=b''.ljust(65,b'\x00')
    q.mem.write(a,data)
    return 0
    
class fakeurand(QlFsMappedObject):
    def read(self,size):
        if size==1:
            return b'\xff'
        return b'collide'.ljust(size,b'\x00')
    
    def fstat(self):
        return -1
    
    def close(self):
        return 0

def my_getrand(q,*args):
    a=args[0]
    b=args[1]
    print("b",b)
    q.mem.write(a,b'collide'.ljust(b,b'\x00'))
    return b

def forbidden(q):
    q.mem.write(q.reg.rax,b'\x01')

def r(ql):
    ql.reg.rax = 0
    ql.set_api('rand', r)

def infinite(q):
    q.reg.al=0

def sleep(q):
    q.reg.edi=0

def struct1(q):
    a=q.mem.read(q.reg.rax,0x18)
    q.mem.write(struct.unpack("<Q",a[0x10:])[0],b'\x01')

def toolow(q,*args):
    q.reg.rax=q.reg.rdi
    q.verbose=QL_VERBOSE.DEFAULT
    return 0

class line(QlFsMappedObject):
    def read(self,size):
        if size==1:
            return b'\xff'
        return b'qilinglab'
    
    def fstat(self):
        return -1
    
    def close(self):
        return 0


def eleven(q):
    q.reg.eax=0x20202062
    q.reg.ecx=0x614C676E
    q.reg.esi=0x696C6951

def run_sandbox(path,rootfs,verbose):
    q=Qiling(path,rootfs,verbose=verbose,console=False)
    #level1
    q.mem.map(0x1337//4096*4096,4096)
    q.mem.write(0x1337,b'\x39\x05')
    #level2
    q.set_syscall(0x3f, my_uname)
    #level3
    q.add_fs_mapper("/dev/urandom",fakeurand())
    q.set_syscall("getrandom",my_getrand)
    #level4
    q.hook_address(forbidden,0x555555554e40)
    #level5
    q.set_api('rand',r)
    #level6
    q.hook_address(infinite,0x555555554f16)
    #level7
    q.hook_address(sleep,0x555555554f3c)
    #level8
    q.hook_address(struct1,0x555555554fb5)
    #level9
    q.set_api("tolower",toolow)
    #level10
    q.add_fs_mapper("/proc/self/cmdline",line())
    #level11
    q.hook_address(eleven,0x555555555195)
    q.run()
    


def main():
    if len(sys.argv)==3:
        arch=sys.argv[2]
        f=sys.argv[1]
        if arch=="x86":
            run_sandbox([f], "rootfs/x86_linux", QL_VERBOSE.DEBUG)
        elif arch == "x64":
            run_sandbox([f], "rootfs/x8664_linux", QL_VERBOSE.DEBUG)
        else:
            print("rootfs not there for",arch)

main()