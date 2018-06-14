from ctypes import *
import ctypes
import os

class SVMModel:
    def trainModel(self,dataFileName):
        dirname = os.path.dirname(os.path.realpath(__file__))
        data_file_path = bytes(dirname + dataFileName, 'ascii')
        data_file = c_char_p(data_file_path)
        ll = ctypes.cdll.LoadLibrary
        lib = ll(dirname + "/libsvmtrain.so")

        #//通过调用原来为main(int argc, char** argv)函数的train_svm_model函数
	    #//参数argc为输入参数的个数+1(第一个为函数名本身)
	    #//参数argv为输入参数向量   示例如下：
	    #int argc = 4;
	    #char *argv[] = {"svmTrain","-s","0","ddos.features"};
        # 0:success
        model_file_path = bytes(dirname + dataFileName + ".model", 'ascii')
        argv = [b"svmTrain",b"-s",b"0",data_file_path,model_file_path]
        argvP = (c_char_p * len(argv))()
        argvP[:] = argv

        ret = lib.train_svm_model(c_int(len(argv)), argvP)

        return ret

#only for test
svmModel = SVMModel()
print(svmModel.trainModel("/ddos-test.features"))