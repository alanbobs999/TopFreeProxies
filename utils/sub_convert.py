#!/usr/bin/env python3

import re, yaml, json, base64
import requests, socket, urllib.parse
from requests.adapters import HTTPAdapter

import geoip2.database

class sub_convert():

    """
    将订阅链接或者订阅内容输入 convert 函数中, 第一步将内容转化为 Clash 节点配置字典, 第二步对节点进行去重和重命名等修饰处理, 第三步输出指定格式. 
    第一步堆栈: 
        YAML To Dict:
            raw_yaml
            convert --> transfer --> format
            dict
        URL To Dict:
            raw_url
            convert --> transfer --> format --> yaml_encode --> format
            dict
        Base64 To Dict:
            raw_base64
            convert --> transfer --> base64_decode --> format --> yaml_encode --> format
            dict
    第二步堆栈:
        dict
        convert --> makeup --> format
        yaml_final
    第三步堆栈:
        YAML To YAML:
            yaml_final
            makeup --> convert
            yaml_final
        YAML To URL:
            yaml_final
            makeup --> yaml_decode --> convert
            url_final
        YAML To Base64:
            yaml_final
            makeup --> yaml_decode --> base64_encode --> convert
            base64_final
    """

    def convert(raw_input, input_type='url', output_type='url', custom_set={'dup_rm_enabled': False, 'format_name_enabled': False}): # {'input_type': ['url', 'content'],'output_type': ['url', 'YAML', 'Base64']}
        # convert Url to YAML or Base64
        if input_type == 'url': # 获取 URL 订阅链接内容
            sub_content = ''
            if isinstance(raw_input, list):
                a_content = []
                for url in raw_input:
                    s = requests.Session()
                    s.mount('http://', HTTPAdapter(max_retries=5))
                    s.mount('https://', HTTPAdapter(max_retries=5))
                    try:
                        print('Downloading from:' + url)
                        resp = s.get(url, timeout=5)
                        s_content = sub_convert.yaml_decode(sub_convert.transfer(resp.content.decode('utf-8')))
                        a_content.append(s_content)
                    except Exception as err:
                        print(err)
                        return 'Url 解析错误'
                sub_content = sub_convert.transfer(''.join(a_content))
            else:
                s = requests.Session()
                s.mount('http://', HTTPAdapter(max_retries=5))
                s.mount('https://', HTTPAdapter(max_retries=5))
                try:
                    print('Downloading from:' + raw_input)
                    resp = s.get(raw_input, timeout=5)
                    sub_content = sub_convert.transfer(resp.content.decode('utf-8'))
                except Exception as err:
                    print(err)
                    return 'Url 解析错误'
        elif input_type == 'content': # 解析订阅内容
            sub_content = sub_convert.transfer(raw_input)

        if sub_content != '订阅内容解析错误': # 输出
            dup_rm_enabled = custom_set['dup_rm_enabled']
            format_name_enabled = custom_set['format_name_enabled']
            final_content = sub_convert.makeup(sub_content,dup_rm_enabled,format_name_enabled)
            if output_type == 'YAML':
                return final_content
            elif output_type == 'Base64':
                return sub_convert.base64_encode(sub_convert.yaml_decode(final_content))
            elif output_type == 'url':
                return sub_convert.yaml_decode(final_content)
            else:
                print('Please define right output type.')
                return '订阅内容解析错误'
        else:
            return '订阅内容解析错误'
    def transfer(sub_content): # 将 URL 内容转换为 YAML 格式
        if '</b>' not in sub_content:
            if 'proxies:' in sub_content: # 判断字符串是否在文本中，是，判断为YAML。https://cloud.tencent.com/developer/article/1699719
                url_content = sub_convert.format(sub_content)
                return url_content
                #return self.url_content.replace('\r','') # 去除‘回车\r符’ https://blog.csdn.net/jerrygaoling/article/details/81051447
            elif '://'  in sub_content: # 同上，是，判断为 Url 链接内容。
                url_content = sub_convert.yaml_encode(sub_convert.format(sub_content))
                return url_content
            else: # 判断 Base64.
                try:
                    url_content = sub_convert.base64_decode(sub_content)
                    url_content = sub_convert.yaml_encode(sub_convert.format(url_content))
                    return url_content
                except Exception: # 万能异常 https://blog.csdn.net/Candance_star/article/details/94135515
                    print('订阅内容解析错误')
                    return '订阅内容解析错误'
        else:
            print('订阅内容解析错误')
            return '订阅内容解析错误'
    def format(sub_content, output=False): # 对节点 Url 进行格式化处理, 输出节点的字典格式, output 为真时输出 YAML 文本

        if 'proxies:' not in sub_content: # 对 URL 内容进行格式化处理
            url_list = []
            try:
                if '://' not in sub_content:
                    sub_content = sub_convert.base64_encode(sub_content)

                raw_url_list = re.split(r'\n+', sub_content)

                for url in raw_url_list:
                    while len(re.split('ss://|ssr://|vmess://|trojan://|vless://', url)) > 2:
                        url_to_split = url[8:]
                        if 'ss://' in url_to_split and 'vmess://' not in url_to_split and 'vless://' not in url_to_split:
                            url_splited = url_to_split.replace('ss://', '\nss://', 1) # https://www.runoob.com/python/att-string-replace.html
                        elif 'ssr://' in url_to_split:
                            url_splited = url_to_split.replace('ssr://', '\nssr://', 1)
                        elif 'vmess://' in url_to_split:
                            url_splited = url_to_split.replace('vmess://', '\nvmess://', 1)
                        elif 'trojan://' in url_to_split:
                            url_splited = url_to_split.replace('trojan://', '\ntrojan://', 1)
                        elif 'vless://' in url_to_split:
                            url_splited = url_to_split.replace('vless://', '\nvless://', 1)
                        url_split = url_splited.split('\n')

                        front_url = url[:8] + url_split[0]
                        url_list.append(front_url)
                        url = url_split[1]

                    url_list.append(url)

                url_content = '\n'.join(url_list)
                return url_content
            except:
                print('Sub_content 格式错误')
                return ''

        elif 'proxies:' in sub_content: # 对 Clash 内容进行格式化处理
            try:
                try_load = yaml.safe_load(sub_content)
                if output == False:
                    sub_content_yaml = try_load
                else:
                    sub_content_yaml = sub_content
            except Exception:
                try:
                    sub_content = sub_content.replace('\'', '').replace('"', '')
                    url_list = []
                    il_chars = ['|', '?', '[', ']', '@', '!', '%']

                    lines = re.split(r'\n+', sub_content)
                    line_fix_list = []

                    for line in lines:
                        value_list = re.split(r': |, ', line)
                        if len(value_list) > 6:
                            value_list_fix = []
                            for value in value_list:
                                for char in il_chars:
                                    value_il = False
                                    if char in value:
                                        value_il = True
                                        break
                                if value_il == True and ('{' not in value and '}' not in value):
                                    value = '"' + value + '"'
                                    value_list_fix.append(value)
                                elif value_il == True and '}' in value:
                                    if '}}' in value:
                                        host_part = value.replace('}}','')
                                        host_value = '"'+host_part+'"}}'
                                        value_list_fix.append(host_value)
                                    elif '}}' not in value:
                                        host_part = value.replace('}','')
                                        host_value = '"'+host_part+'"}'
                                        value_list_fix.append(host_value)
                                else:
                                    value_list_fix.append(value)
                                line_fix = line
                            for index in range(len(value_list_fix)):
                                line_fix = line_fix.replace(value_list[index], value_list_fix[index])
                            line_fix_list.append(line_fix)
                        elif len(value_list) == 2:
                            value_list_fix = []
                            for value in value_list:
                                for char in il_chars:
                                    value_il = False
                                    if char in value:
                                        value_il = True
                                        break
                                if value_il == True:
                                    value = '"' + value + '"'
                                value_list_fix.append(value)
                            line_fix = line
                            for index in range(len(value_list_fix)):
                                line_fix = line_fix.replace(value_list[index], value_list_fix[index])
                            line_fix_list.append(line_fix)
                        elif len(value_list) == 1:
                            if ':' in line:
                                line_fix_list.append(line)
                        else:
                            line_fix_list.append(line)

                    sub_content = '\n'.join(line_fix_list).replace('False', 'false').replace('True', 'true')

                    if output == False:
                        sub_content_yaml = yaml.safe_load(sub_content)
                    else: # output 值为 True 时返回修饰过的 YAML 文本
                        sub_content_yaml = sub_content
                except:
                    print('Sub_content 格式错误')
                    return '' # 解析 URL 内容错误时返回空字符串
            if output == False:
                for item in sub_content_yaml['proxies']:# 对转换过程中出现的不标准配置格式转换
                    try:
                        if item['type'] == 'vmess' and 'HOST' in item['ws-headers'].keys():
                            item['ws-headers']['Host'] = item['ws-headers'].pop("HOST")
                    except KeyError:
                        if '.' not in item['server']:
                            sub_content_yaml['proxies'].remove(item)
                        pass

            return sub_content_yaml # 返回字典, output 值为 True 时返回修饰过的 YAML 文本
    def makeup(input, dup_rm_enabled=False, format_name_enabled=False): # 对节点进行区域的筛选和重命名，输出 YAML 文本 
        # 区域判断(Clash YAML): https://blog.csdn.net/CSDN_duomaomao/article/details/89712826 (ip-api)
        if isinstance(input, dict):
            sub_content = input
        else:
            if 'proxies:' in input:
                sub_content = sub_convert.format(input)
            else:
                yaml_content_raw = sub_convert.convert(input, 'content', 'YAML')
                sub_content = yaml.safe_load(yaml_content_raw)
        proxies_list = sub_content['proxies']
        
        if dup_rm_enabled: # 去重
            begin = 0
            raw_length = len(proxies_list)
            length = len(proxies_list)
            while begin < length:
                if (begin + 1) == 1:
                    print(f'\n-----去重开始-----\n起始数量{length}')
                elif (begin + 1) % 100 == 0:
                    print(f'当前基准{begin + 1}-----当前数量{length}')
                elif (begin + 1) == length and (begin + 1) % 100 != 0:
                    repetition = raw_length - length
                    print(f'当前基准{begin + 1}-----当前数量{length}\n重复数量{repetition}\n-----去重完成-----\n')
                proxy_compared = proxies_list[begin]

                begin_2 = begin + 1
                while begin_2 <= (length - 1):

                    if proxy_compared['server'] == proxies_list[begin_2]['server']:
                        proxies_list.pop(begin_2)
                        length -= 1
                    begin_2 += 1
                begin += 1

        url_list = []
        yaml_content_dic = {'proxies': url_list}
        yaml_content_raw = yaml.dump(yaml_content_dic, default_flow_style=False, sort_keys=False, allow_unicode=True, width=750, indent=2) # yaml.dump 显示中文方法 https://blog.csdn.net/weixin_41548578/article/details/90651464 yaml.dump 各种参数 https://blog.csdn.net/swinfans/article/details/88770119
        yaml_content = yaml_content_raw.replace('\'', '').replace('False', 'false').replace('True', 'true')

        yaml_content = sub_convert.format(yaml_content,True)
        
        return yaml_content # 输出 YAML 格式文本

    def yaml_encode(url_content): # 将 URL 内容转换为 YAML (输出默认 YAML 格式)
        url_list = []

        lines = re.split(r'\n+', url_content)

        for line in lines:
            yaml_url = {}
            if 'vmess://' in line:
                try:
                    vmess_json_config = json.loads(sub_convert.base64_decode(line.replace('vmess://', '')))
                    vmess_default_config = {
                        'v': 'Vmess Node', 'ps': 'Vmess Node', 'add': '0.0.0.0', 'port': 0, 'id': '',
                        'aid': 0, 'scy': 'auto', 'net': '', 'type': '', 'host': vmess_json_config['add'], 'path': '/', 'tls': ''
                    }
                    vmess_default_config.update(vmess_json_config)
                    vmess_config = vmess_default_config

                    yaml_url = {}
                    #yaml_config_str = ['name', 'server', 'port', 'type', 'uuid', 'alterId', 'cipher', 'tls', 'skip-cert-verify', 'network', 'ws-path', 'ws-headers']
                    #vmess_config_str = ['ps', 'add', 'port', 'id', 'aid', 'scy', 'tls', 'net', 'host', 'path']
                    # 生成 yaml 节点字典
                    if vmess_config['id'] == '' or vmess_config['id'] is None:
                        print('节点格式错误')
                    else:
                        yaml_url.setdefault('name', urllib.parse.unquote(str(vmess_config['ps'])))
                        yaml_url.setdefault('server', vmess_config['add'])
                        yaml_url.setdefault('port', int(vmess_config['port']))
                        yaml_url.setdefault('type', 'vmess')
                        yaml_url.setdefault('uuid', vmess_config['id'])
                        yaml_url.setdefault('alterId', int(vmess_config['aid']))
                        yaml_url.setdefault('cipher', vmess_config['scy'])
                        yaml_url.setdefault('skip-cert-vertify', True)
                        if vmess_config['net'] == '' or vmess_config['net'] is False or vmess_config['net'] is None:
                            yaml_url.setdefault('network', 'tcp')
                        else:
                            yaml_url.setdefault('network', vmess_config['net'])
                        if vmess_config['path'] == '' or vmess_config['path'] is False or vmess_config['path'] is None:
                            yaml_url.setdefault('ws-path', '/')
                        else:
                            yaml_url.setdefault('ws-path', vmess_config['path'])
                        if vmess_config['tls'] == '' or vmess_config['tls'] is False or vmess_config['tls'] is None:
                            yaml_url.setdefault('tls', False)
                        else:
                            yaml_url.setdefault('tls', True)
                        if vmess_config['host'] == '':
                            yaml_url.setdefault('ws-headers', {'Host': vmess_config['add']})
                        else:
                            yaml_url.setdefault('ws-headers', {'Host': vmess_config['host']})

                        url_list.append(yaml_url)
                except Exception as err:
                    print(f'yaml_encode 解析 vmess 节点发生错误: {err}')
                    pass

            if 'ss://' in line and 'vless://' not in line and 'vmess://' not in line:
                if '#' not in line:
                    line = line + '#SS%20Node'
                try:
                    ss_content =  line.replace('ss://', '')
                    part_list = ss_content.split('#', 1) # https://www.runoob.com/python/att-string-split.html
                    yaml_url.setdefault('name', urllib.parse.unquote(part_list[1]))
                    if '@' in part_list[0]:
                        mix_part = part_list[0].split('@', 1)
                        method_part = sub_convert.base64_decode(mix_part[0])
                        server_part = f'{method_part}@{mix_part[1]}'
                    else:
                        server_part = sub_convert.base64_decode(part_list[0])

                    server_part_list = server_part.split(':', 1) # 使用多个分隔符 https://blog.csdn.net/shidamowang/article/details/80254476 https://zhuanlan.zhihu.com/p/92287240
                    method_part = server_part_list[0]
                    server_part_list = server_part_list[1].rsplit('@', 1)
                    password_part = server_part_list[0]
                    server_part_list = server_part_list[1].split(':', 1)

                    yaml_url.setdefault('server', server_part_list[0])
                    yaml_url.setdefault('port', server_part_list[1])
                    yaml_url.setdefault('type', 'ss')
                    yaml_url.setdefault('cipher', method_part)
                    yaml_url.setdefault('password', password_part)

                    url_list.append(yaml_url)
                except Exception as err:
                    print(f'yaml_encode 解析 ss 节点发生错误: {err}')
                    pass

            if 'ssr://' in line:
                try:
                    ssr_content = sub_convert.base64_decode(line.replace('ssr://', ''))
                
                    part_list = re.split('/\?', ssr_content)
                    if '&' in part_list[1]:
                        ssr_part = re.split('&', part_list[1]) # 将 SSR content /？后部分参数分割
                        for item in ssr_part:
                            if 'remarks=' in item:
                                remarks_part = item.replace('remarks=', '')
                        try:
                            remarks = sub_convert.base64_decode(remarks_part)
                        except Exception:
                            remarks = 'ssr'
                    else:
                        remarks_part = part_list[1].replace('remarks=', '')
                        try:
                            remarks = sub_convert.base64_decode(remarks_part)
                        except Exception:
                            remarks = 'ssr'
                            print(f'SSR format error, content:{remarks_part}')
                    yaml_url.setdefault('name', urllib.parse.unquote(remarks))

                    server_part_list = re.split(':', part_list[0])
                    yaml_url.setdefault('server', server_part_list[0])
                    yaml_url.setdefault('port', server_part_list[1])
                    yaml_url.setdefault('type', 'ssr')
                    yaml_url.setdefault('cipher', server_part_list[3])
                    yaml_url.setdefault('password', server_part_list[5])

                    url_list.append(yaml_url)
                except Exception as err:
                    print(f'yaml_encode 解析 ssr 节点发生错误: {err}')
                    pass

            if 'trojan://' in line:
                try:
                    url_content = line.replace('trojan://', '')
                    part_list = re.split('#', url_content, maxsplit=1) # https://www.runoob.com/python/att-string-split.html
                    yaml_url.setdefault('name', urllib.parse.unquote(part_list[1]))

                    server_part = part_list[0].replace('trojan://', '')
                    server_part_list = re.split(':|@|\?|&', server_part) # 使用多个分隔符 https://blog.csdn.net/shidamowang/article/details/80254476 https://zhuanlan.zhihu.com/p/92287240
                    yaml_url.setdefault('server', server_part_list[1])
                    yaml_url.setdefault('port', server_part_list[2])
                    yaml_url.setdefault('type', 'trojan')
                    yaml_url.setdefault('password', server_part_list[0])
                    server_part_list = server_part_list[3:]

                    for config in server_part_list:
                        if 'sni=' in config:
                            yaml_url.setdefault('sni', config[4:])
                        elif 'allowInsecure=' in config or 'tls=' in config:
                            if config[-1] == 0:
                                yaml_url.setdefault('tls', False)
                        elif 'type=' in config:
                            if config[5:] != 'tcp':
                                yaml_url.setdefault('network', config[5:])
                        elif 'path=' in config:
                            yaml_url.setdefault('ws-path', config[5:])
                        elif 'security=' in config:
                            if config[9:] != 'tls':
                                yaml_url.setdefault('tls', False)

                    yaml_url.setdefault('skip-cert-verify', True)

                    url_list.append(yaml_url)
                except Exception as err:
                    print(f'yaml_encode 解析 trojan 节点发生错误: {err}')
                    pass

        yaml_content_dic = {'proxies': url_list}
        yaml_content_raw = yaml.dump(yaml_content_dic, default_flow_style=False, sort_keys=False, allow_unicode=True, width=750, indent=2)
        yaml_content = sub_convert.format(yaml_content_raw)
        return yaml_content
    def base64_encode(url_content): # 将 URL 内容转换为 Base64
        base64_content = base64.b64encode(url_content.encode('utf-8')).decode('ascii')
        return base64_content

    def yaml_decode(url_content): # YAML 文本转换为 URL 链接内容
        
        try:
            if isinstance(url_content, dict):
                sub_content = url_content
            else:
                if 'proxies:' in url_content:
                    sub_content = sub_convert.format(url_content)
                else:
                    yaml_content_raw = sub_convert.convert(url_content, 'content', 'YAML')
                    sub_content = yaml.safe_load(yaml_content_raw)
            proxies_list = sub_content['proxies']

            protocol_url = []
            for index in range(len(proxies_list)): # 不同节点订阅链接内容 https://github.com/hoochanlon/fq-book/blob/master/docs/append/srvurl.md
                proxy = proxies_list[index]

                if proxy['type'] == 'vmess': # Vmess 节点提取, 由 Vmess 所有参数 dump JSON 后 base64 得来。

                    yaml_default_config = {
                        'name': 'Vmess Node', 'server': '0.0.0.0', 'port': 0, 'uuid': '', 'alterId': 0,
                        'cipher': 'auto', 'network': 'ws', 'ws-headers': {'Host': proxy['server']},
                        'ws-path': '/', 'tls': '', 'sni': ''
                    }

                    yaml_default_config.update(proxy)
                    proxy_config = yaml_default_config

                    vmess_value = {
                        'v': 2, 'ps': proxy_config['name'], 'add': proxy_config['server'],
                        'port': proxy_config['port'], 'id': proxy_config['uuid'], 'aid': proxy_config['alterId'],
                        'scy': proxy_config['cipher'], 'net': proxy_config['network'], 'type': None, 'host': proxy_config['ws-headers']['Host'],
                        'path': proxy_config['ws-path'], 'tls': proxy_config['tls'], 'sni': proxy_config['sni']
                        }

                    vmess_raw_proxy = json.dumps(vmess_value, sort_keys=False, indent=2, ensure_ascii=False)
                    vmess_proxy = str('vmess://' + sub_convert.base64_encode(vmess_raw_proxy) + '\n')
                    protocol_url.append(vmess_proxy)

                elif proxy['type'] == 'ss': # SS 节点提取, 由 ss_base64_decoded 部分(参数: 'cipher', 'password', 'server', 'port') Base64 编码后 加 # 加注释(URL_encode) 
                    ss_base64_decoded = str(proxy['cipher']) + ':' + str(proxy['password']) + '@' + str(proxy['server']) + ':' + str(proxy['port'])
                    ss_base64 = sub_convert.base64_encode(ss_base64_decoded)
                    ss_proxy = str('ss://' + ss_base64 + '#' + str(urllib.parse.quote(proxy['name'])) + '\n')
                    protocol_url.append(ss_proxy)

                elif proxy['type'] == 'trojan': # Trojan 节点提取, 由 trojan_proxy 中参数再加上 # 加注释(URL_encode) # trojan Go https://p4gefau1t.github.io/trojan-go/developer/url/
                    if 'tls' in proxy.keys() and 'network' in proxy.keys():
                        if proxy['tls'] == True and proxy['network'] != 'tcp':
                            network_type = proxy['network']
                            trojan_go = f'?security=tls&type={network_type}&headerType=none'
                        elif proxy['tls'] == False and proxy['network'] != 'tcp':
                            trojan_go = f'??allowInsecure=0&type={network_type}&headerType=none'
                    else:
                        trojan_go = '?allowInsecure=1'
                    if 'sni' in proxy.keys():
                        trojan_go = trojan_go+'&sni='+proxy['sni']
                    trojan_proxy = str('trojan://' + str(proxy['password']) + '@' + str(proxy['server']) + ':' + str(proxy['port']) + trojan_go + '#' + str(urllib.parse.quote(proxy['name'])) + '\n')
                    protocol_url.append(trojan_proxy)
                
                #elif proxy['type'] == 'ssr':
                    #ssr_base64_decoded = str(proxy['server']) + ':' + str(proxy['port']) + ':' + str(proxy['protocol']) 
                    #ssr_base64_decoded = ssr_base64_decoded + ':' + str(proxy['cipher']) + ':' + str(proxy['obfs']) + ':' + str(sub_convert.base64_encode(proxy['password'])) + '/?'
                    #protocol_url.append(vmessr_proxy)

            yaml_content = ''.join(protocol_url)
            return yaml_content
        except Exception as err:
            print(f'yaml decode 发生 {err} 错误')
            return '订阅内容解析错误'
    def base64_decode(url_content): # Base64 转换为 URL 链接内容
        if '-' in url_content:
            url_content = url_content.replace('-', '+')
        elif '_' in url_content:
            url_content = url_content.replace('_', '/')
        #print(len(url_content))
        missing_padding = len(url_content) % 4
        if missing_padding != 0:
            url_content += '='*(4 - missing_padding) # 不是4的倍数后加= https://www.cnblogs.com/wswang/p/7717997.html
        """ elif(len(url_content)%3 == 1):
            url_content += '=='
        elif(len(url_content)%3 == 2): 
            url_content += '=' """
        #print(url_content)
        #print(len(url_content))
        try:
            base64_content = base64.b64decode(url_content.encode('utf-8')).decode('utf-8','ignore') # https://www.codenong.com/42339876/
            base64_content_format = base64_content
            return base64_content_format
        except UnicodeDecodeError:
            base64_content = base64.b64decode(url_content)
            base64_content_format = base64_content
            return base64_content

    def convert_remote(url='', output_type='clash', host='https://api.v1.mk'): #{url='订阅链接', output_type={'clash': 输出 Clash 配置, 'base64': 输出 Base64 配置, 'url': 输出 url 配置}, host='远程订阅转化服务地址'}
        # 使用远程订阅转换服务，输出相应配置。
        sever_host = host
        url = urllib.parse.quote(url, safe='') # https://docs.python.org/zh-cn/3/library/urllib.parse.html
        if output_type == 'clash':
            converted_url = sever_host+'/sub?target=clash&url='+url+'&insert=false&config=https%3A%2F%2Fraw.nameless13.com%2Fapi%2Fpublic%2Fdl%2FzKF9vFbb%2Feasy.ini'
            try:
                resp = requests.get(converted_url)
            except Exception as err:
                print(err)
                return 'Url 解析错误'
            if resp.text == 'No nodes were found!':
                sub_content = 'Url 解析错误'
            else:
                sub_content = sub_convert.makeup(sub_convert.format(resp.text), dup_rm_enabled=False, format_name_enabled=True)
        elif output_type == 'base64':
            converted_url = sever_host+'/sub?target=mixed&url='+url+'&insert=false&config=https%3A%2F%2Fraw.nameless13.com%2Fapi%2Fpublic%2Fdl%2FzKF9vFbb%2Feasy.ini'
            try:
                resp = requests.get(converted_url)
            except Exception as err:
                print(err)
                return 'Url 解析错误'
            if resp.text == 'No nodes were found!':
                sub_content = 'Url 解析错误'
            else:
                sub_content = resp.text
        elif output_type == 'url':
            converted_url = sever_host+'/sub?target=mixed&url='+url+'&insert=false&config=https%3A%2F%2Fraw.nameless13.com%2Fapi%2Fpublic%2Fdl%2FzKF9vFbb%2Feasy.ini'
            try:
                resp = requests.get(converted_url)
            except Exception as err:
                print(err)
                return 'Url 解析错误'
            if resp.text == 'No nodes were found!':
                sub_content = 'Url 解析错误'
            else:
                sub_content = sub_convert.base64_decode(resp.text)

        return sub_content


if __name__ == '__main__':
    subscribe = 'https://drive.google.com/uc?export=download&id=13Ky0JMPNnisBkUOrl57VQ1ckrUWy4Nhi'
    output_path = './output.txt'

    content = sub_convert.convert_remote(subscribe, 'url')

    file = open(output_path, 'w', encoding= 'utf-8')
    file.write(content)
    file.close()
    print(f'Writing content to output.txt\n')
