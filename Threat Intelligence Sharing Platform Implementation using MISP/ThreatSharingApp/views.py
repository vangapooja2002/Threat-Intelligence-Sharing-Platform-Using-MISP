from django.shortcuts import render
import pymysql
from datetime import datetime
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import matplotlib.pyplot as plt #use to visualize dataset vallues
import io
import base64
import numpy as np
import ipaddress
from maltiverse import Maltiverse
import socket

global username
api = Maltiverse(auth_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIzNjcwMzM4NzYsImlhdCI6MTczNjMxMzg3Niwic3ViIjoyMDc1MiwidXNlcm5hbWUiOiJrYWxlZW0ubW1kIiwiYWRtaW4iOmZhbHNlLCJ0ZWFtX2lkIjpudWxsLCJ0ZWFtX25hbWUiOm51bGwsInRlYW1fbGVhZGVyIjpmYWxzZSwidGVhbV9yZXNlYXJjaGVyIjpmYWxzZSwidGVhbV9pbmRleCI6bnVsbCwiYXBpX2xpbWl0IjoxMDB9.R2lGorrRds3LTmyhA9dzANDFCLAUjUG0muzQYoTwmqw")

def VisualizeThreat(request):
    if request.method == 'GET':
        activity = []
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select url_classification from threats")
            lists = result.fetchall()
            for ls in lists:
                activity.append(ls[0])
        activity = np.asarray(activity)
        print(activity)
        atype, count = np.unique(activity, return_counts=True)
        height = count
        bars = atype
        y_pos = np.arange(len(bars))
        plt.figure(figsize = (6, 3)) 
        plt.bar(y_pos, height)
        plt.xticks(y_pos, bars)
        plt.xlabel("Employee Activities Graph")
        plt.ylabel("Count")
        plt.xticks(rotation=70)
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        img_b64 = base64.b64encode(buf.getvalue()).decode()
        plt.clf()
        plt.cla()
        context= {'data':"Employee Activities Graph", 'img': img_b64}
        return render(request, 'AdminScreen.html', context)
        

def ViewThreats(request):
    if request.method == 'GET':
        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Employee Name</font></th>'
        output+='<th><font size=3 color=black>Visiting Domain</font></th>'
        output+='<th><font size=3 color=black>Domain Classification Result</font></th>'
        output+='<th><font size=3 color=black>Employee Activity Type</font></th>'
        output+='<th><font size=3 color=black>Activity Date</font></th></tr>'
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select * from threats")
            lists = result.fetchall()
            for ls in lists:
                output+='<tr><td><font size=2 color=black>'+str(ls[0])+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[1]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[2]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[3]+'</font></td>'
                output+='<td><font size=2 color=black>'+str(ls[4])+'</font></td></tr>'
        output += "</table><br/><br/><br/><br/>"        
        context= {'data':output}            
        return render(request,'AdminScreen.html', context)

def ViewShareThreat(request):
    if request.method == 'GET':
        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Employee Name</font></th>'
        output+='<th><font size=3 color=black>Visiting Domain</font></th>'
        output+='<th><font size=3 color=black>Domain Classification Result</font></th>'
        output+='<th><font size=3 color=black>Employee Activity Type</font></th>'
        output+='<th><font size=3 color=black>Activity Date</font></th></tr>'
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select * from threats")
            lists = result.fetchall()
            for ls in lists:
                output+='<tr><td><font size=2 color=black>'+str(ls[0])+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[1]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[2]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[3]+'</font></td>'
                output+='<td><font size=2 color=black>'+str(ls[4])+'</font></td></tr>'
        output += "</table><br/><br/><br/><br/>"        
        context= {'data':output}            
        return render(request,'UserScreen.html', context)    

def logMalware(domain, classify, activity):
    global username
    dd = str(datetime.now())
    dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    dbcursor = dbconnection.cursor()
    qry = "INSERT INTO threats VALUES('"+str(username)+"','"+domain+"','"+classify+"','"+activity+"','"+dd+"')"
    dbcursor.execute(qry)
    dbconnection.commit()  

def AccessPagesAction(request):
    if request.method == 'POST':
        global username
        domain = request.POST.get('t1', False)
        status = ""
        output = ""
        try:
            clean_ip = socket.gethostbyname(domain.strip())
        except:
            status = "Invalid domain entered"
        if status != "Invalid domain entered":
            print(clean_ip)
            try:
                ipaddress.ip_address(clean_ip)
            except ValueError:
                status = "Invalid domain entered"
            result = api.ip_get(clean_ip)
            try:
                status = result['classification']
            except KeyError:
                status = "Unable to classify"
            print(status)    
            if status == "neutral":
                output = '<a href="https://'+domain+'" target="_blank"><font size="3" color="green">Domain ('+domain+') is clean you can proceed. Tap Here</font></a>'
            else:
                output = '<td><font size="3" color="red">Domain ('+domain+') contains malicious/malware activities. Not allowed to access</font></a>'
        else:
            output = "Invalid domain entered"
        logMalware(domain, status, 'Browsing '+domain) 
        context= {'data':output}
        return render(request,'AccessPages.html', context)         

def AccessPages(request):
    if request.method == 'GET':
        return render(request,'AccessPages.html', {})

def index(request):
    if request.method == 'GET':
        return render(request,'index.html', {})

def AdminLogin(request):
    if request.method == 'GET':
       return render(request, 'AdminLogin.html', {})        

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})
    
def AddEmp(request):
    if request.method == 'GET':
       return render(request, 'AddEmp.html', {})

def isUserExists(username):
    is_user_exists = False
    global details
    mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    with mysqlConnect:
        result = mysqlConnect.cursor()
        result.execute("select * from employees where username='"+username+"'")
        lists = result.fetchall()
        for ls in lists:
            is_user_exists = True
    return is_user_exists    

def AddEmpAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        dept = request.POST.get('t6', False)
        salary = request.POST.get('t7', False)
        desc = request.POST.get('t8', False)
        record = isUserExists(username)
        page = None
        if record == False:
            dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
            dbcursor = dbconnection.cursor()
            qry = "INSERT INTO employees VALUES('"+str(username)+"','"+password+"','"+contact+"','"+email+"','"+address+"','"+dept+"','"+salary+"','"+desc+"')"
            dbcursor.execute(qry)
            dbconnection.commit()
            if dbcursor.rowcount == 1:
                data = "New employee details added"
                context= {'data':data}
                return render(request,'AddEmp.html', context)
            else:
                data = "Error in adding employee details"
                context= {'data':data}
                return render(request,'AddEmp.html', context) 
        else:
            data = "Given "+username+" already exists"
            context= {'data':data}
            return render(request,'AddEmp.html', context)


def checkUser(uname, password):
    global username
    msg = "Invalid Login Details"
    mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    with mysqlConnect:
        result = mysqlConnect.cursor()
        result.execute("select * from employees where username='"+uname+"' and password='"+password+"'")
        lists = result.fetchall()
        for ls in lists:
            msg = "success"
            username = uname
            break
    return msg

def logData(username, request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
    print(ip)
    if ip is None:
        ip = "127.0.0.1"
    dd = str(datetime.now())
    classify = "Invalid Login"
    activity = "trying to login as admin"
    dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    dbcursor = dbconnection.cursor()
    qry = "INSERT INTO threats VALUES('"+str(username)+"','"+ip+"','"+classify+"','"+activity+"','"+dd+"')"
    dbcursor.execute(qry)
    dbconnection.commit()    

def UserLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        msg = checkUser(username, password)
        if msg == "success":
            context= {'data':"Welcome "+username}
            return render(request,'UserScreen.html', context)
        else:
            logData(username, request)
            context= {'data':msg}
            return render(request,'UserLogin.html', context)
        
def AdminLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        if username == "admin" and password == "admin":
            context= {'data':"Welcome "+username}
            return render(request,'AdminScreen.html', context)
        else:
            context= {'data':"Invalid Login"}
            return render(request,'AdminLogin.html', context)










        


        
