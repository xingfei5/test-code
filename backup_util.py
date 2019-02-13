#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
功能说明：
1.该工具只会对聚类任务的元数据进行备份（即配置信息），不会对聚类的中间数据及结果备份（因为数据量过大）。因此备份出来的任务再导入时，状态均变为空闲，且聚类时间字段为空，用户需要对任务重新聚类才能查看结果。
2.数据恢复时会删除现有库中数据已经中间结果文件等，然后再导入备份文件中的数据。

使用方法：
1.将该文件拷贝到/opt/skyguard/www/cluster_api/www目录，并在该目录执行备份或恢复命令，且需以root身份运行
2.命令格式如下：
    查看帮助：python backup_util.py -h
    备份：python backup_util.py -d backupFilePath
        如备份到当前目录： python backup_util.py -d cluster_data_backup.json
    恢复：python backup_util.py -l backupFilePath
        如恢复当前目录的一个文件：python backup_util.py -l cluster_data_backup.json
'''
import os
import sys
import json
import time
import datetime
import shutil
from optparse import OptionParser
from config import WORK_PATH


def backup_dumps(back_path):
    from app import createApp
    from models.cluster_model import ClusterModel

    with createApp().app_context(), open(back_path, 'w') as fout:
        print('backup export start...')
        all = ClusterModel.query.all()
        if all:
            for item in all:
                itemDict = {}
                itemDict['name'] = item.name
                itemDict['sampleLanguage'] = item.sampleLanguage
                itemDict['status'] = 0
                itemDict['description'] = item.description
                itemDict['pathInfo'] = item.pathInfo
                itemDict['filterInfo'] = item.filterInfo
                itemDict['excludeWords'] = item.excludeWords
                itemDict['similarity'] = item.similarity
                itemDict['uid'] = item.uid
                itemDict['cid'] = item.cid
                itemDict['hierarchiceUuid'] = item.hierarchiceUuid
                itemDict['ctime'] = time.mktime(item.ctime.timetuple())
                itemDict['utime'] = time.mktime(item.utime.timetuple())
                fout.write(json.dumps(itemDict) + '\n')
        print('backup export end')

def backup_loads(back_path):
    from app import createApp
    from models import db
    from models.cluster_model import ClusterModel
    from models.cluster_file_model import ClusterFileModel
    from models.cluster_cat_name_model import ClusterCatNameModel

    with createApp().app_context(), open(back_path, 'r') as fin:
        print('backup import start...')
        all = ClusterModel.query.all()
        if all:
            for item in all:
                clusterPath = os.path.join(WORK_PATH, str(item.id))
                if os.path.exists(clusterPath):
                    shutil.rmtree(clusterPath)
        ClusterModel.query.filter().delete()
        ClusterFileModel.query.filter().delete()
        ClusterCatNameModel.query.filter().delete()
        for line in fin:
            line = line.strip('\n')
            itemDict = json.loads(line)
            model = ClusterModel()
            model.name = itemDict.get('name')
            model.sampleLanguage = itemDict.get('sampleLanguage')
            model.status = itemDict.get('status')
            model.description = itemDict.get('description')
            model.pathInfo = itemDict.get('pathInfo')
            model.filterInfo = itemDict.get('filterInfo')
            model.excludeWords = itemDict.get('excludeWords')
            model.similarity = itemDict.get('similarity')
            model.uid = itemDict.get('uid')
            model.cid = itemDict.get('cid')
            model.hierarchiceUuid = itemDict.get('hierarchiceUuid')
            model.ctime = datetime.datetime.fromtimestamp(itemDict.get('utime'))
            model.utime = datetime.datetime.fromtimestamp(itemDict.get('utime'))
            db.session.add(model)
            db.session.commit()
        print('backup import end')

if __name__ == '__main__':
    if sys.getdefaultencoding() != 'utf-8':
        reload(sys)
        sys.setdefaultencoding('utf-8')
    sys.path.insert(0, "/opt/skyguard/www/cluster_api/env/lib/python2.7/site-packages")
    sys.path.insert(0, "/opt/skyguard/www/cluster_api/www")
    parser = OptionParser()
    parser.add_option('-d', '--dumps', dest='dumps', help='backup dumps data path', type='string')
    parser.add_option('-l', '--loads', dest='loads', help='backup loads data path', type='string')
    (options, args) = parser.parse_args()
    if options.dumps:
        backup_dumps(options.dumps)
    elif options.loads:
        backup_loads(options.loads)
    else:
        print('params error')
