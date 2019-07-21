# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 x6
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2018 宝塔软件(http:#bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: 梁凯强<1249648969@qq.com>
# +-------------------------------------------------------------------
import sys
sys.path.append('/www/server/panel/class')
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
import json, os, time, public, string,re
from xml.etree.ElementTree import ElementTree, Element
import os, public


class firewalls_list:
    __isFirewalld = False
    __isUfw = False
    __Obj = None
    __TREE = None
    __ROOT = None
    __CONF_FILE = '/etc/firewalld/zones/public.xml'
    __DROP_FILE='/dev/shm/stop_ip.json'
    __DROP_LOCK = '/dev/shm/stop_ip.lock'
    __DROP_LOCK2 = '/dev/shm/stop_ip2.lock'

    def __init__(self):
        if self.__TREE: return
        self.__TREE = ElementTree()
        self.__TREE.parse(self.__CONF_FILE)
        self.__ROOT = self.__TREE.getroot()

        if os.path.exists('/usr/sbin/firewalld'): self.__isFirewalld = True
        if os.path.exists('/usr/sbin/ufw'): self.__isUfw = True
        public.M('firewall').execute("alter table firewall add ports TEXT;", ())
        public.M('firewall').execute("alter table firewall add protocol TEXT;", ())
        public.M('firewall').execute("alter table firewall add address_ip TEXT;", ())
        public.M('firewall').execute("alter table firewall add types TEXT;", ())

    #
    # 获取端口列表
    def GetAcceptPortList(self):
        mlist = self.__ROOT.getchildren()
        data = []
        for p in mlist:
            if p.tag != 'port': continue
            tmp = p.attrib
            port = p.attrib['port']
            data.append(tmp)
        return data

    # 检查端口是否已放行
    def CheckPortAccept(self, pool, port):
        for p in self.GetAcceptPortList():
            if p['port'] == port and p['protocol'] == pool: return True
        return False

    # 获取屏蔽IP列表
    def GetDropAddressList(self):
        mlist = self.__ROOT.getchildren()
        data = []
        for ip in mlist:
            if ip.tag != 'rule': continue
            tmp = {}
            ch = ip.getchildren()
            a = None
            for c in ch:
                tmp['type'] = None
                if c.tag == 'drop': tmp['type'] = 'drop'
                if c.tag == 'source':
                    tmp['address'] = c.attrib['address']
                if tmp['type']:
                    data.append(tmp)
        return data

    # 获取 reject 信息
    def GetrejectLIST(self):
        mlist = self.__ROOT.getchildren()
        data = []
        for ip in mlist:
            # print(ip)
            if ip.tag != 'rule': continue
            tmp = {}
            ch = ip.getchildren()
            a = None
            flag = None
            for c in ch:
                tmp['type'] = None
                if c.tag == 'reject': tmp['type'] = 'reject'
                if c.tag == 'source':
                    tmp['address'] = c.attrib['address']
                if c.tag == 'port':
                    tmp['protocol'] = c.attrib['protocol']
                    tmp['port'] = c.attrib['port']
                if tmp['type']:
                    data.append(tmp)
        return data

    # 获取 accept 信息
    def Getacceptlist(self):
        mlist = self.__ROOT.getchildren()
        data = []
        for ip in mlist:

            if ip.tag != 'rule': continue
            tmp = {}
            ch = ip.getchildren()
            a = None
            flag = None
            for c in ch:
                tmp['type'] = None
                if c.tag == 'accept': tmp['type'] = 'accept'
                if c.tag == 'source':
                    tmp['address'] = c.attrib['address']
                if c.tag == 'port':
                    tmp['protocol'] = c.attrib['protocol']
                    tmp['port'] = c.attrib['port']
                if tmp['type']:
                    data.append(tmp)
        return data

    # 获取所有信息
    def Get_All_Info(self):
        data = {}
        data['drop_ip'] = self.GetDropAddressList()
        data['reject'] = self.GetrejectLIST()
        data['accept'] = self.Getacceptlist()
        return data

    # 判断是否存在
    def Chekc_info(self, port, address, pool, type):
        data = self.Get_All_Info()
        if type == 'accept':
            for i in data['accept']:
                if i['address'] == address and i['protocol'] == pool and i['port'] == port:
                    return True
            else:
                return False

        elif type == 'reject':
            for i in data['reject']:
                if i['address'] == address and i['protocol'] == pool and i['port'] == port:
                    return True
            else:
                return False
        else:
            return False


    def chek_reject(self, port, address, pool, type):
        data=self.GetrejectLIST()

        for i in data:
            if i['port']==port and address==i['address'] and pool==i['protocol'] and type==i['type']:
                return True
        else:
            return False



    # 添加端口放行并且指定IP
    def Add_Port_IP(self, port, address, pool, type):
        if type == 'accept':
            # 判断是否存在
            if self.Chekc_info(port, address, pool, type): return True
            attr = {"family": 'ipv4'}
            rule = Element("rule", attr)
            attr = {"address": address}
            source = Element("source", attr)
            attr = {'port': str(port), 'protocol': pool}
            port_info = Element("port", attr)
            accept = Element("accept", {})
            rule.append(source)
            rule.append(port_info)
            rule.append(accept)
            self.__ROOT.append(rule)
            return True
        elif type == 'reject':
            # 判断是否存在
            if self.Chekc_info(port, address, pool, type): return True
            attr = {"family": 'ipv4'}
            rule = Element("rule", attr)
            attr = {"address": address}
            source = Element("source", attr)
            attr = {'port': str(port), 'protocol': pool}
            port_info = Element("port", attr)
            reject = Element("reject", {})
            rule.append(source)
            rule.append(port_info)
            rule.append(reject)
            self.__ROOT.append(rule)
            return True
        else:
            return False

    # 删除指定端口的=。=
    def Del_Port_IP(self, port, address, pool, type):
        if type == 'accept':
            a = None
            for i in self.__ROOT:
                if i.tag == 'rule':
                    tmp = {}
                    for c in i.getchildren():
                        tmp['type'] = None
                        if c.tag == 'accept': tmp['type'] = 'accept'
                        if c.tag == 'source':
                            tmp['address'] = c.attrib['address']
                        if c.tag == 'port':
                            tmp['protocol'] = c.attrib['protocol']
                            tmp['port'] = c.attrib['port']
                        if tmp['type']:
                            if tmp['port'] == port and tmp['address'] == address and tmp['type'] == type and tmp[
                                'protocol'] == pool:
                                self.__ROOT.remove(i)
            return True

        elif type == 'reject':
            for i in self.__ROOT:
                if i.tag == 'rule':
                    tmp = {}
                    for c in i.getchildren():
                        tmp['type'] = None
                        if c.tag == 'reject': tmp['type'] = 'reject'
                        if c.tag == 'source':
                            tmp['address'] = c.attrib['address']
                        if c.tag == 'port':
                            tmp['protocol'] = c.attrib['protocol']
                            tmp['port'] = c.attrib['port']
                        if tmp['type']:
                            if tmp['port'] == port and tmp['address'] == address and tmp['type'] == type and tmp[
                                'protocol'] == pool:
                                self.__ROOT.remove(i)
            return True

    # 检查IP是否已经屏蔽
    def CheckIpDrop(self, address):
        for ip in self.GetDropAddressList():
            if ip['address'] == address: return True
        return False

    # 保存配置
    def Save(self):
        self.format(self.__ROOT)
        self.__TREE.write(self.__CONF_FILE, 'utf-8')

    # 整理配置文件格式
    def format(self, em, level=0):
        i = "\n" + level * "  "
        if len(em):
            if not em.text or not em.text.strip():
                em.text = i + "  "
            for e in em:
                self.format(e, level + 1)
            if not e.tail or not e.tail.strip():
                e.tail = i
        if level and (not em.tail or not em.tail.strip()):
            em.tail = i

    # 重载防火墙配置
    def FirewallReload(self):
        if self.__isUfw:
            public.ExecShell('/usr/sbin/ufw reload')
            return
        if self.__isFirewalld:
            self.format(self.__ROOT)
            self.__TREE.write(self.__CONF_FILE, 'utf-8')
            os.system('firewall-cmd --reload')
        else:
            public.ExecShell('/etc/init.d/iptables save')
            public.ExecShell('/etc/init.d/iptables restart')

    # 添加屏蔽IP
    def AddDropAddress2(self, address):
        if self.__isUfw:
            public.ExecShell('ufw deny from ' + address + ' to any');
        else:
            if self.__isFirewalld:
                self.Add_Port_IP('80', address, 'tcp', 'reject')
                self.Add_Port_IP('443', address, 'tcp', 'reject')
            else:
                return False

    # 删除IP屏蔽
    def DelDropAddress2(self,address):
        if self.__isUfw:
            public.ExecShell('ufw delete deny from ' + address + ' to any');
        else:
            if self.__isFirewalld:
                self.Del_Port_IP('80', address, 'tcp', 'reject')
                self.Del_Port_IP('443', address, 'tcp', 'reject')
            else:
                return False

    def start(self):
        stop_time = int(time.time()) + 3580
        flag=True
        count = 0
        count2=0
        while flag:
            time.sleep(1)
            start_time=int(time.time())
            if start_time>stop_time:
                flag=False
                exit()
            if not os.path.exists(self.__DROP_LOCK) and os.path.exists(self.__DROP_LOCK2):
                time.sleep(0.1)
            elif not os.path.exists(self.__DROP_LOCK) and not os.path.exists(self.__DROP_LOCK2):
                time.sleep(1)
            else:
                if os.path.exists(self.__DROP_LOCK):
                    os.remove(self.__DROP_LOCK)
                if os.path.exists(self.__DROP_LOCK2):
                    os.remove(self.__DROP_LOCK2)
            if not os.path.exists(self.__DROP_FILE):
                ret=[]
                public.WriteFile(self.__DROP_FILE,json.dumps(ret))
            else:
                try:
                    result=json.loads(public.ReadFile(self.__DROP_FILE))
                    for i in result:
                        ret=time.time()
                        if (i['time']+i['timeout'])< ret:

                            if self.__isFirewalld:
                                if self.Chekc_info('443', i['ip'], 'tcp', 'reject'):
                                    print('需要释放的IP%s' % i['ip'])
                                    count2 += 1
                                    self.DelDropAddress2(i['ip'])
                            else:
                                print('需要释放的IP%s' % i['ip'])
                                count2 += 1
                                self.DelDropAddress2(i['ip'])
                        else:
                            if self.__isFirewalld:
                                if self.Chekc_info('443', i['ip'], 'tcp', 'reject'):
                                    continue
                                if self.Chekc_info('80', i['ip'], 'tcp', 'reject'):
                                    continue
                                print('需要禁止的IP%s' % i['ip'])
                                self.AddDropAddress2(i['ip'])
                                count += 1
                            else:
                                self.AddDropAddress2(i['ip'])
                                count += 1
                    if count>40 or count2>=5:
                        count2=0
                        count=0
                        self.FirewallReload()
                except:
                    ret=[]
                    public.WriteFile(self.__DROP_FILE, json.dumps(ret))
                    print('%s 文件解析错误正在恢复初始'%self.__DROP_FILE)
    #重载配置
    def CrondReload(self):
        if os.path.exists('/etc/init.d/crond'):
            public.ExecShell('/etc/init.d/crond reload')
        elif os.path.exists('/etc/init.d/cron'):
            public.ExecShell('service cron restart')
        else:
            public.ExecShell("systemctl reload crond")


    # 从crond删除
    def remove_for_crond(self, echo):
        u_file = '/var/spool/cron/crontabs/root'
        if not os.path.exists(u_file):
            file = '/var/spool/cron/root'
        else:
            file = u_file
        conf = public.readFile(file)
        rep = ".+" + str(echo) + ".+\n"
        conf = re.sub(rep, "", conf)
        if not public.writeFile(file, conf): return False
        self.CrondReload()
        return True

    # 删除计划任务
    def DelCrontab(self, get):
        try:
            id = get['id']
            find = public.M('crontab').where("id=?", (id,)).field('name,echo').find()
            if not self.remove_for_crond(find['echo']): return public.returnMsg(False, '无法写入文件，请检查是否开启了系统加固功能!');
            cronPath = public.GetConfigValue('setup_path') + '/cron'
            sfile = cronPath + '/' + find['echo']
            if os.path.exists(sfile): os.remove(sfile)
            sfile = cronPath + '/' + find['echo'] + '.log'
            if os.path.exists(sfile): os.remove(sfile)

            public.M('crontab').where("id=?", (id,)).delete()
            public.WriteLog('TYPE_CRON', 'CRONTAB_DEL', (find['name'],))
            return public.returnMsg(True, 'DEL_SUCCESS')
        except:
            return public.returnMsg(False, 'DEL_ERROR')


    def stop(self):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        if id: self.DelCrontab({'id': id})
        return public.returnMsg(True, '关闭成功!')

if __name__ == '__main__':
    os.chdir('/www/server/panel')
    b_obj = firewalls_list()
    type = sys.argv[1]
    if type == 'start':
        b_obj.start()
    elif type=='stop':
        b_obj.stop()
    else:
        pass