import re, os, json
from shutil import which
# If strings command not found run: pkg install binutils

data = {
    "SSH": "",
    "Payload": "",
    "Proxy": "",
    "SNI": "",
    "Name Server": "",
    "Public Key": "",
    "DNS": "",
    "V2ray": "",
    "V2ray": "",
    "Login Hwid": "",
    "Lock HWID": "",
    "Lock Provider": "",
    "URL": "",
    "Note": "",
    "Expired Cnfg": "",
     "VersionApp": "",
     "VersionCnfg": "",
      "BlockRoot": "",
}

def get_v2ray_cfg(content: str) -> dict | str:
    v2ray_regex = r".inbounds.*(\s{1,}.*\n)?(\s{1,}.*\n)?(\s{1,}.*\n)?(\s{1,}.*)?(\n\s{1,}.*\n)?(\s{1,}.*\n)?(\s{1,}.*\n){1,}"
    v2ray_cfg = "{"
    matches = re.finditer(v2ray_regex, content)
    if matches != None:
        for i in matches:
            match = i.group(0)
            if v2ray_cfg == '':
                v2ray_cfg = match
            else:
                v2ray_cfg += match

        v2ray_cfg += "}"
        try: v2ray_cfg = json.loads(v2ray_cfg)
        except: v2ray_cfg = json.loads(v2ray_cfg + "\n}")
        return json.dumps(v2ray_cfg, indent=2)
    else:
        return None


def get_slowdns_cfg(content: str) -> dict | str:
    slownds_regex = r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)\n(.*)\n(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$"
    matches = re.finditer(slownds_regex, content,re.MULTILINE)
    if matches != None:
        for i in matches:
            match = i.group(0)
            return match.split("\n")
    return None

def HTTPCustom(file:str):
    ssh_field = re.compile(r'.*:?[0-9]{2,10}@.*',re.MULTILINE)
    sni_field = re.compile("(?:[\w-]+\.)*([\w-]{1,63})(?:\.(?:\w{3}|\w{2}))(?:$|\/)")
    proxy_field = re.compile("^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9]):[0-9]+?\s?\n")
    #proxy_field = re.compile("[\w\-\.\:]+\.[\w\:]+(.*)")
    update_url = re.compile("https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
    match_payload = ["CONNECT","GET","PUT","MOVE","BMOVE","HEAD","POST","Host:","[crlf]","[lf]","[cr]",'\\r','\\n']
    
    lines = open(file, "r").readlines()
    content = open(file, "r").read()
    
    slowdns = get_slowdns_cfg(content)
    if slowdns != None:
        data["Name Server"] = slowdns[0]
        data["Public Key"] = slowdns[1]
        data["DNS"] = slowdns[2]
    
    for i in lines:
        line = i.rstrip().removesuffix(",")
        sni_ = sni_field.match(line)
        ssh_ = ssh_field.match(line)
        
        if ssh_ != None: data["SSH"] = ssh_[0]
        elif sni_ != None and data["SNI"] == "" and data["Name Server"] != sni_[0]: data["SNI"] = sni_[0]

        elif any(x in line for x in match_payload) and not '"d":' in line:
            if data["Payload"] == "":
                data["Payload"] = line
            else:
                data["Payload"] += f"\n{line}"
       
        elif '"app"' in i: data["BlockApp"] = line.split(":")[1].replace('"', "").rstrip()
        elif proxy_field.match(i): data["Proxy"] = line
        elif "isLoginHwid" in i: data["[Login Hwid]"] = line.split(":")[1].removesuffix(",")
        elif '"verCfg"' in i: data["[VersionCnfg]"] = line.split(":")[1].replace('"', "").rstrip()
        elif "verApp" in i: data["[VersionApp"] = line.split(":")[1]
        elif '"c"' in i: data["[BlockRoot]"] = line.split(":")[1].replace('"', "").rstrip()
        elif '"d"' in i: data["[Expired Cnfg]"] = line.split(":")[1].replace('"', "").rstrip()
        elif '"f"' in i: data["Lock Provider"] = line.split(":")[1].replace('"', "").rstrip()
        elif '"b"' in i: data["Lock HWID"] = line.split(":")[1].replace('"', "").rstrip()
        elif '"url"' in i:
            split_ = line.split(":")
            data["URL"] = f"{split_[1]}{split_[2]}".replace('"', "").rstrip()
        elif '"inbounds": [],' in i or '"DNS": {' in i:
            data["V2ray"] = get_v2ray_cfg(content)
    return data

def main():
    #file =  "/sdcard/Payload.txt"
    file =  "/sdcard/decrypt.txt"
    strings_file = "/sdcard/HC.txt"
    os.system(f"strings {file} > {strings_file}")
    os.system('cls||clear')
    result =''
    data = HTTPCustom(strings_file)
   # message = "\n\n"
    print("")
    result += 'ᴅᴇᴄʀʏᴘᴛ ʜᴛᴛᴘꜱ ᴄᴜꜱᴛᴏᴍ\n'
    result += 'ʀᴇᴀᴅ ᴄᴏɴꜰɪɢ ʙʏ ᴇᴍᴘᴇʀᴏʀ ᴅᴇᴄʀʏᴘᴛᴏʀ\nᴜɴᴘᴀᴄᴋᴇᴅ ʙʏ python ren.py'
    #result += 'ᴅᴇᴄʀʏᴘᴛ ʜᴛᴛᴘꜱ ᴄᴜꜱᴛᴏᴍ\n'
    #result += 'https://t.me/decrypt_vpn_file\n'
    
    #print(f"•───────────────────•")
    for key in data:
        value = data[key]
        if value != '':    
            result += f"\n───────────────────\n"
            result += f"[</>] {key} : {value}"
  
    #result += '•───────────────────•'
    
    #message += "ᴅᴇᴄʀʏᴘᴛ ʜᴛᴛᴘꜱ ᴄᴜꜱᴛᴏᴍ  \n"
    #result += 'ᴅᴇᴄʀʏᴘᴛ ʜᴛᴛᴘꜱ ᴄᴜꜱᴛᴏᴍ\n'
    #message += += 'ʀᴇᴀᴅ ᴄᴏɴꜰɪɢ ʙʏ ꜱᴇᴀ🌊 ꜰʀᴏᴍ ᴄᴇɴᴛʀᴀʟ ʙᴏʀɴᴇᴏ\n'
    out = open('/sdcard/HC-Decrypt.txt', 'w')
    out.write(result)
    out.close()
    print(result)
    os.system("cat /sdcard/HC-Decrypt.txt| termux-clipboard-set")
    print('sukses copy')
    os.remove(strings_file)
    
if __name__ == "__main__":
    main()
    
