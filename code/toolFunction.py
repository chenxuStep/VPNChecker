
import pandas as pd 
import logging

'''
Description:  Write to CSV file
Param :  your column and writePath
Return: 
'''
def csvWrite(column,writePath):
    res = pd.DataFrame(columns=(column))
    res.to_csv(writePath,index=False,mode='a+',encoding='utf8')


'''
Description: Read txt file
Param : 
Return: 
'''
def readTxt(readfilePath):
    with open(readfilePath) as file:
        lines = file.readlines()
        listStr = list()
        for line in lines:
            listStr.append("".join(line.split()))
    return listStr



'''
Description: Construct logger object
Param : 
Return: 
'''
def process_log(Name,file):    
        logger = logging.getLogger(Name)
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(file)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger

'''
Description: Delete file content
Param : 
Return: 
'''
def clear(writeFilePath):
    file = open(writeFilePath, 'w')
    file.closed
