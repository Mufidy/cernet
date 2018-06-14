from django.shortcuts import render
from django.http import JsonResponse
from django.http import HttpResponse

import time

from .distributeModel import EGP
from .svmModel import SVMModel
from .svmData import SVMData

# Create your views here.

def index(request):
    return render(request,'index.html')

def getData(request):
    return render(request,'getData.html')

def trainModel(request):
    return render(request,'trainModel.html')

def distributeModel(request):
    return render(request,'distributeModel.html')

def ajaxDistribute(request):
    egpID = int(request.GET['egpID'])
    modelFileName = request.GET['modelname']
    egp = EGP(egpID)
    result = [egpID, egp.distributeModel(modelFileName)]
    return JsonResponse(result, safe=False)

def ajaxTrainModel(request):
    dataFileName = request.GET['filename']
    svmModel = SVMModel()
    modelname = ""
    status,modelDetail,CV_ACC,oldModelDetail,oldCV_ACC = svmModel.trainModel(dataFileName)
    if(status == 0):
        modelname = dataFileName + ".model"
    result = {"status":status, "modelname":modelname,"modelDetail":modelDetail, \
    "CV_ACC":CV_ACC,"oldModelDetail":oldModelDetail,"oldCV_ACC":oldCV_ACC}
    time.sleep(2)
    return JsonResponse(result, safe=False)

def ajaxTestModel(request):
    time.sleep(2)
    result={"status":0}
    return JsonResponse(result, safe=False)

def ajaxGetData(request):
    time.sleep(3)
    svmData = SVMData()
    ret,dataFileName,detail = svmData.getData()
    #ret: 0 success; else errno
    result={"status":ret, "filename":dataFileName, "detail":detail}
    return JsonResponse(result, safe=False)

    