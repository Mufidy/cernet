from ctypes import *
import ctypes
import os

class EGP:
    ipv6_array=[
    c_char_p(b"1000:0:200::1100"), #国防科大
    c_char_p(b"1000:0:200::1000"), #东南大学 2001:da8:1002:5033:219:fff:fe2d:4764
    c_char_p(b"1000:0:200::900"), #南航
    c_char_p(b"1000:0:200::800"), #计算所
    #c_char_p(b"::4"), #电子科大
    #c_char_p(b"::5"), #陆工大
    c_char_p(b"1000:0:200::700")  #30所
    ]

    def __init__(self,egpID):
        self.egpID = egpID
        self.ipv6_addr = EGP.ipv6_array[egpID] 

    def distributeModel(self,modelFileName):
        dirname = os.path.dirname(os.path.realpath(__file__))
        model_file_path = bytes(dirname + modelFileName, 'ascii')
        model_file = c_char_p(model_file_path)
        ll = ctypes.cdll.LoadLibrary
        lib = ll(dirname + "/libdistribute.so")

        # 0:success; 1:timeout; 2:recv error; -1:internel error
        ret = lib.send_file(model_file, self.ipv6_addr)

        return ret
