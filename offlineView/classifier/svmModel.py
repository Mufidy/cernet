from ctypes import *
import ctypes
import os
import time
import sqlite3
from decimal import Decimal
from .svmutil import *

class SVMModel:
    def trainModel(self,dataFileName):
        dirName = os.path.dirname(os.path.realpath(__file__))
        ret = 0 #svm_train success!
        modelDetail = ""
        oldModelDetail = ""
        CV_ACC = 0
        oldCV_ACC = 0
        try:
            y, x = svm_read_problem(dirName+dataFileName)
            prob = svm_problem(y, x)
            param = svm_parameter('')
            model = svm_train(prob, param)
            svm_save_model(dirName+dataFileName+".model", model)
            CV_ACC_x = svm_train(prob, svm_parameter('-v 10'))
            CV_ACC = Decimal(CV_ACC_x)
            CV_ACC = round(CV_ACC,6)

            #get Model Detail
            modelFo = open(dirName+dataFileName+".model","r+")
            for i in range(0,12):
                modelDetail = modelDetail+modelFo.readline()
            modelFo.close()

            #get old model detail from database
            conn = sqlite3.connect(dirName+"/svmmodel.db")
            curs = conn.cursor()
            sql = "select modeldetail,accuracy from model order by mid desc limit 0,1"
            cursor = curs.execute(sql)
            for row in cursor:
                oldModelDetail = row[0]
                oldCV_ACC = row[1]

            #now store
            modelDetail = modelDetail.replace("\n","<br/>")
            sql2 = "insert into model (modeldetail,accuracy) values ('%s',%f)" %(modelDetail,CV_ACC)
            cursor = curs.execute(sql2)
            conn.commit()

        except Exception as e:
            print("训练集异常，训练出错，请重试！\n error: ",e)
            ret = 1

        return ret,modelDetail,CV_ACC,oldModelDetail,oldCV_ACC
    
    def testModel(self,dataFileName):
        dirName = os.path.dirname(os.path.realpath(__file__))
        y, x = svm_read_problem(dirName+dataFileName)
        prob = svm_problem(y, x)
        param = svm_parameter('-v 10')
        
        CV_ACC = svm_train(prob, param)

        #store model in svmmodel.db(table: model)
        modelTime = int(time.time())
        
        modelFo = open(dirName+dataFileName+".model","r+")
        modelDetail = ""
        for i in range(0,10):
            modelDetail = modelDetail+modelFo.readline()
        modelFo.close()

        conn = sqlite3.connect(dirName+"svmmodel.db")
        curs = conn.cursor()
        sql = "select timestamp,modeldetail,accuracy from model"
        cursor = curs.execute(sql)
        for row in cursor:
            print("******",row[0])
        
        #now store
        #modelDetail = modelDetail.replace("\n","<br/>")
        #sql2 = "insert into model values (%d,'%s',%f)" %(modelTime,modelDetail,CV_ACC)
        #cursor = curs.execute(sql2)

        return CV_ACC

#only for test
#svmModel = SVMModel()
#print(svmModel.trainModel("/home/hfmiao/zn/offline_SEU/offlineView/classifier/svmdata/ddos-test.features"))
#print(svmModel.testModel("/home/hfmiao/zn/offline_SEU/offlineView/classifier/svmdata/ddos-test.features"))
