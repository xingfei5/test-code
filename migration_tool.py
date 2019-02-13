#!/usr/bin/python

import sys
sys.path.append("/opt/skyguard/www/app")
import utils
import time
import json
import os
from agent_client import AGENT_CLIENT, AGENT_ADDR, AGENT_PORT
from mta_client import MTA_CLIENT, MTA_ADDR, MTA_PORT
import forensics_storage
from redis_client import RedisClient
from blockPage_settings import *
import shutil
from os import listdir
from os.path import isfile,join
import httplib
from file_util import FileUtil

temp_dir_networking = "/tmp/restore_networking"
forensics_dir="/var/skyguard/forensics/"
collect_log_dir="/opt/skyguard/download/logs/"

app_backup_filelist = [
    "/opt/skyguard/www/app/iptables-rules-1",
    "/opt/skyguard/www/app/iptables-rules-2",
    "/opt/skyguard/www/app/iptables-rules-3",
    "/opt/skyguard/www/app/iptables-rules-4",
    "/opt/skyguard/www/app/ebtables-rules-1",
    "/opt/skyguard/www/app/ebtables-rules-2",
    "/opt/skyguard/www/app/ebtables-rules-3",
    "/opt/skyguard/www/app/ebtables-rules-4"
]

bro_backup_filelist = [
    "/usr/local/bro/share/bro/policy/protocols/spe-common/common.bro",
    "/opt/skyguard/www/app/monitor.json",
    "/usr/local/bro/share/bro/site/local-worker.bro",
    "/usr/local/bro/share/bro/site/local-worker.bro.inline",
    "/usr/local/bro/share/bro/site/local-worker.bro.span"
]

bro_backup_filelist_swg = [
    "/opt/skyguard/www/app/monitor.json",
    "/usr/local/bro/etc/broctl.cfg",
    "/usr/local/bro/share/bro/base/init-bare.bro",
    "/usr/local/bro/share/bro/site/local-worker.bro",
    "/usr/local/bro/share/bro/site/local-worker.bro.span"
]

def _get_hostname():
    client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
    resp = json.loads(client.get_information(["device_base_info"]))
    if resp["responseCode"] != 200:
        return ""
    else:
        device_info = resp["device_base_info"]
        return device_info["hostname"]

def _restore_hostname(hostname_backup_file):
    f = open(hostname_backup_file)
    hostname_backup = f.readline().replace("\n", "")
    if hostname_backup is not None and hostname_backup != "":
        agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
        config = {"device_base_info": {"hostname": hostname_backup}}
        res = agent_client.set_config(config)
        res_json = json.loads(res)
        if res_json["responseCode"] != 200:
            utils.app_logger("Restore hostname encounter error", "error")
        else:
            utils.app_logger("Restore hostname successfully")

def _get_backup_networking_files(tmp_folder):
    '''
    Get networking files need to be backup
    :param tmp_folder: files wiil be stored into tmp_folder
    :return: file name list that will be backup
    '''
    # get networking files of backup
    ret_files = []

    # backup hostname info into redis
    bk_hostname = _get_hostname()
    if bk_hostname != "":
        utils.app_command("echo %s > /tmp/hostname.backup" % _get_hostname())
        utils.app_command_quiet("sudo cp /tmp/hostname.backup " + tmp_folder+"/")
        ret_files.append("hostname.backup")

    utils.app_command_quiet("sudo cp /etc/network/interfaces " + tmp_folder+"/")
    utils.app_command_quiet("sudo chmod 777 " + tmp_folder+"/interfaces")
    ret_files.append("interfaces")
    utils.app_command_quiet("sudo cp /etc/resolv.conf " + tmp_folder+"/")
    utils.app_command_quiet("sudo chmod 777 " + tmp_folder+"/resolv.conf")
    ret_files.append("resolv.conf")
    # if UCSG, also return pbr files
    device_type = utils.get_device_type()
    if device_type == 2 or device_type == 6 or device_type == 13:
        dir_path = "/opt/skyguard/www/app"
        for f in os.listdir(dir_path):
            if isfile(join(dir_path, f)) and f.find("pbr-") != -1:
                shutil.copy(join(dir_path, f), tmp_folder+"/")
                ret_files.append(f)
    return ret_files

def _remove_backup_networking_files(tmp_folder):
    os.unlink(tmp_folder+"/interfaces")
    os.unlink(tmp_folder+"/resolv.conf")
    device_type = utils.get_device_type()
    if os.path.exists(tmp_folder + "/hostname.backup"):
        os.unlink(tmp_folder+"/hostname.backup")
    if device_type == 2 or device_type == 6 or device_type == 13:
        only_files = [f for f in listdir(tmp_folder) if isfile(join(tmp_folder, f))]
        for f in only_files:
            if f.find("pbr-") != -1:
                os.unlink(join(tmp_folder, f))

def _remove_old_pbr(nicName):
    (ret, output) = utils.app_command("ip rule ls | grep %s" % nicName)
    if output != [] and output[0] != "":
        for rule in output:
            utils.app_command("ip rule del %s" % rule.split(":\t")[1])

def set_backup_schedule(user_data):
    redis_client = RedisClient()
    redis_client.hmset("backup_schedule_task",user_data)
    if user_data["enabled"]:
        if user_data["cycle"].lower() =="day":
            os.system("echo \"%s %s * * * root /opt/skyguard/www/app/backup_utility.py doschedule > /dev/null 2>&1 \" > /etc/cron.d/sgBackupSchedule" %(user_data["minute"],user_data["hour"]))
        elif user_data["cycle"].lower()=="week":
            weekdays=""
            for i in range(len(user_data["weekday"])):
                if i==0:
                    weekdays=user_data["weekday"][i]
                else:
                    weekdays=weekdays+","+user_data["weekday"][i]
            os.system("echo \"%s %s * * %s root /opt/skyguard/www/app/backup_utility.py doschedule > /dev/null 2>&1 \" > /etc/cron.d/sgBackupSchedule" %(user_data["minute"],user_data["hour"],weekdays))
        elif user_data["cycle"].lower()=="month":
            os.system("echo \"%s %s %s * * root /opt/skyguard/www/app/backup_utility.py doschedule > /dev/null 2>&1 \" > /etc/cron.d/sgBackupSchedule" %(user_data["minute"],user_data["hour"],user_data["dayofMonth"]))
        utils.app_command_quiet("service cron restart")
    else:
        utils.app_command("rm -f /etc/cron.d/sgBackupSchedule")
        utils.app_command_quiet("service cron restart")
    return 0

def _backup_appliance(tmp_folder, whether_backup_network=False,whether_backup_forensics=False):
    version = utils.app_conf_get("device_base_info")["version"]
    # Get current time
    tnow = int(time.time())
    tnowst = time.localtime(tnow)

    timestamp = time.strftime('%Y%m%d%H%M%S',tnowst)

    current_path = os.getcwd()
    os.chdir(tmp_folder)
    app_filename_prefix = "Appliance" + "-" + version + "-" + timestamp

    device_type = utils.get_device_type()

    backup_content = {}
    agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
    if device_type == 2 or device_type == 4 or device_type == 6 or device_type == 8:
        if device_type == 2 or device_type == 6:
            # get device_work_mode info
            work_mode = utils.app_conf_get("device_work_mode")
            device_work_mode = {}
            backup_content["device_work_mode"] = work_mode
            if work_mode == 1: #backup netObject and globalbypass for pcap mode
                monitor_mode = utils.get_monitor_node()
                if monitor_mode == "pcap":
                    global_bypass = utils.app_conf_get("globalbypass")
                    if global_bypass != {}:
                        backup_content["globalbypass"] = global_bypass
        # get protocol settings
        protocol_settings = utils.app_conf_get("protocol")
        if protocol_settings != {}:
            backup_content["protocol"] = protocol_settings

        # get block_pages setting
        block_page_settings = BlockPageSettings().get_settings()
        backup_content["block_page_settings"] = block_page_settings["data"]

    # get SNMP info
    try:
        res_json = json.loads(agent_client.get_SNMP_settings())
    except httplib.HTTPException:
        agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
        res_json = json.loads(agent_client.get_SNMP_settings())
    backup_content["snmp_settings"] = res_json["snmp_settings"]
    if device_type == 1:
        # get device_time_info
        try:
            res_json = json.loads(agent_client.get_device_time())
        except httplib.HTTPException:
            agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
            res_json = json.loads(agent_client.get_device_time())
        backup_content["device_time_info"] = res_json["device_time_info"]
    # get proxy_settings
    try:
        res_json = json.loads(agent_client.get_proxy_settings())
    except httplib.HTTPException:
        agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
        res_json = json.loads(agent_client.get_proxy_settings())
    if res_json.has_key("proxyserver"):
        del res_json["responseCode"]
        del res_json["message"]
        backup_content["proxy_settings"] = res_json
    # get backup_settings
    try:
        res_json = json.loads(agent_client.get_backup_settings())
    except httplib.HTTPException:
        agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
        res_json = json.loads(agent_client.get_backup_settings())
    if res_json.has_key("locationType"):
        del res_json["responseCode"]
        del res_json["message"]
        backup_content["backup_settings"] = res_json

    # get hostname and desc
    hostname = utils.app_conf_get("device_base_info")["hostname"]
    if utils.app_conf_get("device_base_info").has_key("desc"):
        desc = utils.app_conf_get("device_base_info")["desc"]
    else:
        desc = ""
    backup_content["device_base_info"] = {"hostname": hostname, "desc": desc}

    # get forensics storage
    backup_content["forensics_storage"] = {"capacity": forensics_storage.get_forensics_capacity()}
    
    #get exception list
    backup_content["exception"]= utils.app_conf_get("exception")

    #get synctime setting
    redis_client = RedisClient()
    if redis_client.exist_key("synctime_schedule_task"):
        synctime_schedule_task = redis_client.hgetall("synctime_schedule_task")
        if synctime_schedule_task is not None:
            backup_content["synctime_schedule_task"] = synctime_schedule_task

    #get backup schedule setting
    redis_client = RedisClient()
    if redis_client.exist_key("backup_schedule_task"):
        backup_schedule_task = redis_client.hgetall("backup_schedule_task")
        if backup_schedule_task is not None:
            backup_content["backup_schedule_task"] = backup_schedule_task

    #get ts setting
    redis_client = RedisClient()
    if redis_client.exist_key("ts"):
        ts_res = redis_client.get("ts")
        if ts_res is not None:
            backup_content["ts_account_info"] = ts_res

    with open(app_filename_prefix + ".conf", "w") as bk_file:
        json.dump(backup_content, bk_file, indent=4)
        bk_file.close()

    if device_type == 2 or device_type == 4 or device_type == 6 or device_type == 8:
        bk_file_list = ""
        for bk_file in app_backup_filelist:
            if (device_type == 4 or device_type == 8) and "ebtables" in bk_file:
                continue
            shutil.copy(bk_file, "./")
            bk_file_list += " %s" % os.path.basename(bk_file)
        # backup block pages
        blockpage_zip_files = BlockPageSettings().backup_blockpage_dir()
        for bk_file in blockpage_zip_files:
            shutil.copy(bk_file, "./")
            bk_file_list += " %s" % os.path.basename(bk_file)
        bk_file_list += " " + app_filename_prefix + ".conf"
    else:
        bk_file_list = app_filename_prefix + ".conf"
    # get networking files
    if whether_backup_network:
        networking_list = _get_backup_networking_files(tmp_folder)
        for bk_file in networking_list:
            bk_file_list += " %s" % os.path.basename(bk_file)
    # backup hybrid.conf if exist
    if os.path.isfile("/opt/skyguard/www/app/hybrid.conf"):
        shutil.copy("/opt/skyguard/www/app/hybrid.conf", "./")
        bk_file_list += " hybrid.conf"
    if device_type == 2:
        for bro_cfg in bro_backup_filelist:
            if os.path.isfile(bro_cfg):
                shutil.copy(bro_cfg, "./")
                bk_file_list += " %s" % os.path.basename(bro_cfg)
    # swg pacp mode
    if device_type == 6:
        if "2.2" in version:
            pass
        else:
            for bro_cfg in bro_backup_filelist_swg:
                if os.path.isfile(bro_cfg):
                    shutil.copy(bro_cfg, "./")
                    bk_file_list += " %s" % os.path.basename(bro_cfg)

    #backup collect log
    if os.path.exists(collect_log_dir):
        filelist=os.listdir(collect_log_dir)
        if filelist!=[]:
            if not os.path.exists("collect_log"):
                os.mkdir("collect_log")
            FileUtil.copyFilesToDir(collect_log_dir, "collect_log/")   
            bk_file_list += " %s" % ("collect_log/")

    # Backup hybrid settings
    if device_type == 4 or device_type == 8:
        shutil.copy("/opt/skyguard/www/app/gre_info.conf", "./")
        bk_file_list += " gre_info.conf"
        '''
        agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
        network_settings = agent_client.get_hybrid_config()
        ucss_external_ip = utils.get_ucss_address()
        # get ucss internal ip from iptables
        (ret, output) = utils.app_command("iptables-save | grep %s" % ucss_external_ip)
        if ret == 0:
            kv = [word.split() for word in output[0].split()]
            if "-d" in kv:
                ucss_internal_ip = kv[kv.index("-d") + 1].split("/")[0]
        # get ucsg public ip
        public_ip = utils.get_ip_address("eth1")
        hybrid_settings = {"network_setting" : json.dumps(network_settings), "ucss_external_ip" : ucss_external_ip, "ucss_internal_ip" : ucss_internal_ip, "public_ip" : public_ip}
        with open("hybrid_settings.conf", "w") as hybrid_conf:
            json.dump(hybrid_settings, hybrid_conf, indent=4)
        '''
    # Backup 

    #backup forensics
    whether_backup_forensics = 0
    if whether_backup_forensics:
        if device_type != 1:
            if os.path.exists(forensics_dir):
                filelist=os.listdir(forensics_dir)
                if filelist!=[]:
                    os.mkdir("forensics")
                    for f in filelist:
                        shutil.copy(forensics_dir+f,"forensics/")

    # generate backup tgz
    utils.app_command_quiet("tar cfvz %s %s" % (app_filename_prefix + ".tar.gz", bk_file_list))
    # remove tmp files
    os.unlink(app_filename_prefix + ".conf")
    if os.path.isfile("hybrid.conf"):
        os.unlink("hybrid.conf")
    if os.path.isfile("gre_info.conf"):
        os.unlink("gre_info.conf")
    if device_type == 2 or device_type == 4 or device_type == 6 or device_type == 8:
        for bk_file in app_backup_filelist:
            if (device_type == 4 or device_type == 8) and "ebtables" in bk_file:
                continue
            os.unlink(os.path.basename(bk_file))
        BlockPageSettings().delete_backup_zip()
        for bk_file in blockpage_zip_files:
            os.unlink(os.path.basename(bk_file))
    if device_type == 2:
        for bro_cfg in bro_backup_filelist:
            if os.path.isfile(os.path.basename(bro_cfg)):
                os.unlink(os.path.basename(bro_cfg))
    if device_type == 6:
        for bro_cfg in bro_backup_filelist_swg:
            if os.path.isfile(os.path.basename(bro_cfg)):
                os.unlink(os.path.basename(bro_cfg))
    if whether_backup_network:
        _remove_backup_networking_files(tmp_folder)
    os.chdir(current_path)
    return app_filename_prefix + ".tar.gz"

def _restore_appliance(app_filename):
    tmp_folder = tempfile.mkdtemp(prefix="backup.", dir="/tmp")
    (ret, output) = utils.app_command("tar xfvz %s -C %s" %(app_filename,tmp_folder))
    current_path = os.getcwd()
    os.chdir(tmp_folder)
    app_filename = os.path.basename(app_filename)

    device_type = utils.get_device_type()

#    copy networking files to some place, _post_restore will use them
    cur_dir = os.getcwd()
    if os.path.exists(cur_dir + "/interfaces"):
        shutil.rmtree(temp_dir_networking, ignore_errors=True)
        os.makedirs(temp_dir_networking)
        utils.app_command_quiet("cp interfaces " + temp_dir_networking)
        utils.app_command_quiet("cp resolv.conf " + temp_dir_networking)
        utils.app_command_quiet("cp hostname.backup " + temp_dir_networking)
        if device_type == 2 or device_type == 6 or device_type == 13:
            utils.app_command_quiet("cp pbr-* " + temp_dir_networking)
        # restore hostname
        if os.path.exists(cur_dir + "/hostname.backup"):
            utils.app_command_quiet("cp hostname.backup " + temp_dir_networking)
            _restore_hostname(temp_dir_networking + "/hostname.backup")

    #restore pcap config file
    if device_type == 2:
        has_file = False
        for bro_cfg in bro_backup_filelist:
            if os.path.isfile(os.path.basename(bro_cfg)):
                has_file = True
                shutil.copy(os.path.basename(bro_cfg), bro_cfg)

        common_bro_rep_str='redef snaplen = 32768;\\nconst store_disk_length = 4096 \\&redef;\\nconst ftp_capture_max_file_size =100000000 \\&redef;\\nconst smb_capture_max_file_size =100000000 \\&redef;\\nconst http_capture_max_file_size =100000000 \\&redef;\\nconst smtp_capture_max_file_size =100000000 \\&redef;\\nconst imap_capture_max_file_size =100000000 \\&redef;\\nconst pop3_capture_max_file_size =100000000 \\&redef;'
        os.system("sed -i ':a;N;$!ba;s/\\(.*\\)redef snaplen = 32768;\\(.*\\)/\\1%s\\2/' /usr/local/bro/share/bro/policy/protocols/spe-common/common.bro" %(common_bro_rep_str))

        if has_file == True:
            device_mode = utils.get_device_work_mode()
            current_mode = utils.get_monitor_mode()
            restore_mode = utils.get_monitor_mode()
            if device_mode == 1 and not current_mode == restore_mode:
                utils.logger("Restore monitor mode to %s" % restore_mode)
                utils.app_command("/opt/skyguard/www/app/device_work_mode.py switch force")


    if device_type == 2 or device_type == 4 or device_type == 6 or device_type == 8:
        #Restore iptables, ebtables first - in case device work doesn't change which will not refresh these tables
        for bk_file in app_backup_filelist:
            if (device_type == 4 or device_type == 8) and "ebtables" in bk_file:
                continue
            if os.path.isfile(os.path.basename(bk_file)):
                shutil.copy(os.path.basename(bk_file), bk_file)
    
        device_mode = utils.get_device_work_mode()
        # Flush ebtables
        if device_type == 2 or device_type == 6 and device_mode != 4:# device mode is not proxy mode
            utils.app_command_quiet("/sbin/ebtables -t broute -F")
            utils.app_command_quiet("/bin/sh /opt/skyguard/www/app/ebtables-rules-%d" % int(device_mode))
        utils.app_command_quiet("/sbin/iptables-restore < /opt/skyguard/www/app/iptables-rules-%d" % int(device_mode))   

    app_restore = app_filename.replace(".tar.gz", ".conf")
    with open(app_restore) as config_data:
        config = json.load(config_data)

    monitor_mode = utils.get_monitor_mode()
    agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
    # restore device work mode
    if config.has_key("device_work_mode"):
        device_work_mode = config["device_work_mode"]
        device_type = utils.get_device_type()
        if device_type == 2 or device_type == 6:
            res = agent_client.set_information({"device_work_mode" : device_work_mode})
            res_json = json.loads(res)
            if res_json["responseCode"] != 200:
                utils.app_logger("Restore device_work_mode encounter error", "error")
                return False
            if device_work_mode == 1:
                utils.app_command("sudo /opt/skyguard/www/app/device_work_mode.py switch %s" % monitor_mode)
    # restore protocol settings
    device_work_mode = utils.get_device_work_mode()
    if config.has_key("protocol"):
        utils.app_conf_write({"protocol" : config["protocol"]})
        if device_work_mode == 1 and monitor_mode == "pcap" and config["protocol"].has_key("netObject"):
            try:
                res = agent_client.set_protocol_settings("netObject", config["protocol"]["netObject"])
            except httplib.HTTPException:
                agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
                res = agent_client.set_protocol_settings("netObject", config["protocol"]["netObject"])

    #restore pcap file in swg
    if device_type == 6:
        for bro_cfg in bro_backup_filelist_swg:
            if os.path.isfile(os.path.basename(bro_cfg)):
                shutil.copy(os.path.basename(bro_cfg), bro_cfg)
        # if bro run ,restart
        ret=os.system("ps -ef |grep /usr/local/bro/bin/bro |grep -v grep   > /dev/null 2>&1")
        if ret == 0:
            os.system("/usr/local/bro/bin/broctl deploy > /dev/null 2>&1")
        import time
        time.sleep(1)

    # restore global bypass
    if config.has_key("globalbypass"):
        res = utils.app_conf_write({"globalbypass" : config["globalbypass"]})

    #restore exception list
    if config.has_key("exception"):
        res = utils.app_conf_write({"exception" : config["exception"]})

    # restore backup settings
    if config.has_key("backup_settings"):
        backup_settings = config["backup_settings"]
        try:
            res = agent_client.set_backup_settings(backup_settings)
        except httplib.HTTPException:
            agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
            res = agent_client.set_backup_settings(backup_settings)
        res_json = json.loads(res)
        if res_json["responseCode"] != 200:
            utils.app_logger("Restore backup_settings encounter error", "error")
            return False

    # restore snmp settings
    if config.has_key("snmp_settings"):
        snmp_settings = config["snmp_settings"]
        try:
            res = agent_client.set_information({"snmp_settings" : snmp_settings})
        except httplib.HTTPException:
            agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
            res = agent_client.set_information({"snmp_settings" : snmp_settings})
        res_json = json.loads(res)
        if res_json["responseCode"] != 200:
            utils.app_logger("Restore snmp_settings encounter error", "error")
            return False

    # restore device time info
    if config.has_key("device_time_info"):
        device_time_info = config["device_time_info"]
        if device_time_info.has_key("ntp") and device_time_info["ntp"]:
            new_time_info = json.loads(agent_client.get_device_time())["device_time_info"]
            new_time_info["ntp"] = device_time_info["ntp"]
            new_time_info["ntpserver"] = device_time_info["ntpserver"]
            config = {}
            config["device_time_info"] = new_time_info
            try:
                res = agent_client.set_config(config)
            except httplib.HTTPException:
                agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
                res = agent_client.set_config(config)
            res_json = json.loads(res)
            if res_json["responseCode"] != 200:
                utils.app_logger("Restore device_time_info encounter error", "error")
                return False

    # restore proxy settings
    if config.has_key("proxy_settings"):
        proxy_settings = config["proxy_settings"]
        try:
            res = agent_client.set_proxy_settings(proxy_settings)
        except httplib.HTTPException:
            agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
            res = agent_client.set_proxy_settings(proxy_settings)
        res_json = json.loads(res)
        if res_json["responseCode"] != 200:
            utils.app_logger("Restore proxy_settings encounter error", "error")
            return False

    # restore block pages settings
    if config.has_key("block_page_settings"):
        utils.app_logger("begim to restore block_page_settings")
        block_page_settings = config["block_page_settings"]
        bps = BlockPageSettings()
        # first restore the backup block pages
        bps.delete_backup_zip()
        shutil.copy(os.path.basename(blockpage_backup_customized_zip), blockpage_backup_customized_zip)
        shutil.copy(os.path.basename(blockpage_backup_uploaded_zip), blockpage_backup_uploaded_zip)
        bps.restore_blockpage_dir()
        # then update the setting
        ret = bps.set_settings(block_page_settings)
        utils.app_command_quiet("chown -R www-data:www-data /opt/skyguard/download/")
        if ret["responseCode"] == 0 or ret["responseCode"] == 1:
            utils.app_logger("Succeed to restore block_page_settings")
        else:
            utils.app_logger("Restore block_page_settings encounter error", "error")
            return False

    # restore device base info
    if config.has_key("device_base_info"):
        agent_client = AGENT_CLIENT(AGENT_ADDR,AGENT_PORT)
        agent_client.set_information({"device_base_info" : config["device_base_info"]})
        #(ret, output) = utils.app_command("sudo /opt/skyguard/www/app/device_base_info.py set %s" % "'"+json.dumps(config["device_base_info"])+"'")
        #if ret != 0:
        #    utils.app_logger(str(output))

    # restore forensics storage
    if config.has_key("forensics_storage"):
        forensics_storage.set_forensics_capacity(config["forensics_storage"]["capacity"])
    
    #restore forensic file 
    if device_type != 1:
        if os.path.exists("forensics"):
            filelist=os.listdir("forensics")
            if filelist!=[]:
                if not os.path.exists(forensics_dir):
                    os.makedirs(forensics_dir)
                FileUtil.copyFilesToDir("forensics",forensics_dir)
                #for f in filelist:
                #    shutil.copy("forensics/"+f,forensics_dir)

    #restore collect log dir
    if os.path.exists("collect_log"):
        filelist=os.listdir("collect_log")
        if filelist!=[]:
            if not os.path.exists(collect_log_dir):
                os.makedirs(collect_log_dir)
            FileUtil.copyFilesToDir("collect_log/", collect_log_dir)   

    # Restore hybrid.conf if exist
    if os.path.isfile("hybrid.conf"):
        shutil.copy("hybrid.conf", "/opt/skyguard/www/app/hybrid.conf")
    # Resotre hybrid settings
    if (device_type == 4 or device_type == 8) and os.path.isfile("gre_info.conf"):
        shutil.copy("gre_info.conf", "/opt/skyguard/www/app/gre_info.conf")
        '''
        with open("hybrid_settings.conf", "r") as hybrid_conf:
            hybrid_settings = json.load(hybrid_conf)
        agent_client = AGENT_CLIENT(AGENT_ADDR, AGENT_PORT)
        agent_client.set_hybrid_config(hybrid_settings)
        '''
    #restore synctime task setting
    if config.has_key("synctime_schedule_task"):
        redis_client = RedisClient()
        if redis_client.exist_key("synctime_schedule_task"):
            redis_client.delete_key("synctime_schedule_task")
        redis_client.hmset("synctime_schedule_task",config["synctime_schedule_task"])

    #restore backup task setting
    if config.has_key("backup_schedule_task"):
        redis_client = RedisClient()
        if redis_client.exist_key("backup_schedule_task"):
            redis_client.delete_key("backup_schedule_task")
        redis_client.hmset("backup_schedule_task",config["backup_schedule_task"])
        set_backup_schedule(config["backup_schedule_task"])

    #restore ts  setting
    #if config.has_key("ts_account_info"):
        #redis_client = RedisClient()
        #if redis_client.exist_key("ts"):
        #    redis_client.delete_key("ts")
        #redis_client.set("ts",config["ts_account_info"])

    # restore network setting
    bk_interface_file = temp_dir_networking + "/interfaces"
    if os.path.exists(bk_interface_file):
        import time
        time.sleep(5)
        utils.app_logger("Restore network setting...")
        #utils.app_command_quiet("/etc/init.d/networking stop")
        for nic in ["eth0", "eth1", "eth2", "eth3", "bond0", "bond1", "bond2", "bond3", "br0"]:
            _remove_old_pbr(nic)
        utils.app_logger("Restore /etc/network/interfaces...")
        shutil.copy(bk_interface_file, "/etc/network/interfaces")
        bk_resolv_file = temp_dir_networking + "/resolv.conf"
        utils.app_logger("Restore /etc/resolv.conf...")
        shutil.copy(bk_resolv_file, "/etc/resolv.conf")
        if device_type == 2 or device_type == 6 or device_type == 13:
            utils.app_logger("Restore /opt/skyguard/www/app/pbr-*...")
            for f in listdir(temp_dir_networking):
                if f.find("pbr-") != -1:
                    shutil.copy(join(temp_dir_networking, f), "/opt/skyguard/www/app/")
        shutil.rmtree(temp_dir_networking, ignore_errors=True)
        #utils.app_command_quiet("/etc/init.d/networking start")
        utils.app_logger("Finish to restore network setting.")

    # notify mta to update mta ip
    if device_type == 2 or device_type == 6:
        if utils.get_bonding_status("bond1") == True:
            mta_ip = utils.get_ip_address("bond1")
        else:
            mta_ip = utils.get_ip_address("eth1")
        mtaclient = MTA_CLIENT(MTA_ADDR, MTA_PORT)
        mtaclient.set_mta_nics("eth1", mta_ip)

    os.chdir(current_path)
    shutil.rmtree(tmp_folder)

    print "Finished restore"
    return True


if __name__ == "__main__":
    forensics_file="/opt/skyguard/www/app/forensics_incidents_store_setting.py"
    (ret, output) = utils.app_command("grep \'umount -f -l\' %s" %(forensics_file))
    if ret != 0:
        os.system('sed -i \'s/umount /umount -f -l /g\' %s'%(forensics_file))
        os.system('/etc/init.d/apache2 restart')

    if sys.argv[1] == "backup":
        filename=_backup_appliance("/tmp/", whether_backup_network=True)
        print "/tmp/"+filename
    elif sys.argv[1] == "restore":
        print _restore_appliance(sys.argv[2]) 
        os.system('/etc/init.d/apache2 restart')
