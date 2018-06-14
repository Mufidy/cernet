import sqlite3
import time
import os

class SVMData:
    def getData(self):
        """ #abandoned now!
        dirName = os.path.dirname(os.path.realpath(__file__))
        dirNameB = bytes(dirName+"",'ascii')
        dirNameP = c_char_p(dirNameB)
        recvFileName = bytes("",'ascii')
        recvFileNameP = c_char_p(recvFileName)
        ll = ctypes.cdll.LoadLibrary
        lib = ll(dirName + "/libgetdata.so")

        #getData函数原型
        #int getData(char* recvFileName, char* dirName)
        #返回值为int，0表示正常，其他为error
        #recvFileName表示存储的features的文件名，会被修改成以存储时的时间戳命名的文件名
        #dirName表示路径，不会被修改
        ret = lib.getData(recvFileNameP,dirNameP)
        recvFileNameB = string_at(recvFileNameP)
        recvFileNameStr = recvFileNameB.decode()
        return ret,recvFileNameStr
        """

        dirName = os.path.dirname(os.path.realpath(__file__))
        nowTime = int(time.time())
        fRange = 10 #默认获取前10天内的所有数据
        minTime = nowTime - 10 * 86400
        featureFileName = "/svmdata/features-%d.txt" %(nowTime)
        fp = open(dirName+featureFileName,mode='w')
        #访问数据库得到异常流量特征值
        conn = sqlite3.connect("../databaseServer/DDoSData.sqlite3")
        curs = conn.cursor()
        sql = "select protocol_type,src_bytes,dst_bytes,flag_count,src_ip_count,packet_length,\
        packet_count,tcp_packet_count,tcp_src_port_count,tcp_dst_port_count,tcp_fin_flag_count,\
        ddos_type from ddosFeatures" # where timestamp>%d and timestamp<%d" %(minTime,nowTime)
        cursor = curs.execute(sql)
        #for row in cursor:
        #    oneSV = "%d 1:%f 2:%f 3:%f 4:%f 5:%f 6:%f 7:%f 8:%f 9:%f 10:%f 11:%f\n" %(row[11],
        #    row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],)
        #    fp.write(oneSV)
        displayTotal = 0
        displayDetail = ""
        for row in cursor:
            oneSV = "%d 1:%f 2:%f 3:%f 4:%f 5:%f 6:%f 7:%f 8:%f 9:%f 10:%f 11:%f\n" %(row[11],
            0,0,0,0,0,0,0,0,0,0,row[10])
            fp.write(oneSV)
            #add for display
            if displayTotal < 9:
                oneDetail = "%d 1:%f 2:%f 3:%f 4:%f 5:%f 6:%f 7:%f 8:%f 9:%f 10:%f 11:%f\n" %(row[11],
                row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10])
                displayTotal = displayTotal + 1
                displayDetail = displayDetail + oneDetail + "<br/>"

        return 0,featureFileName,displayDetail

#only for test
#svmData = SVMData()
#print(svmData.getData())