#!/bin/bash

Green_font="\033[32m" && Yellow_font="\033[33m" && Red_font="\033[31m" && Font_suffix="\033[0m"
Info="${Green_font}[Info]${Font_suffix}"
Error="${Red_font}[Error]${Font_suffix}"
Thank="${Green_font}感谢使用软软的脚本!!${Font_suffix}"
Byebye="${Red_font}感谢使用软软的脚本!!!\n更多内容请关注 → Bt_Panel ${Font_suffix}"
pluginPath=/www/server/panel/plugin/btwaf
pluginPath1=/www/server/panel/plugin/tamper_proof
download_Url=http://download.umaru.uk
MAIN_RETURN=${Red_font}[宝塔面板Bt_Panel防火墙修复脚本]${Font_suffix}
MAIN_RETURNC="${Red_font}提示：修复了被拉黑无法安装插件问题！${Font_suffix}"
MAIN_RETURNE="${Red_font}提示：防火墙需要面板先安装，然后在使用脚本安装防火墙，请勿在面板升级防火墙！ 防篡改插件已经解除验证，直接面板安装使用！${Font_suffix}"
MAIN_RETURND="${Yellow_font}公告：本次 防火墙修复脚本 ！${Font_suffix}"


# 临时解决
fail(){
clear
read -p "确认是否已经在面板上安装好NGINX环境！【回车】"
read -p "确认是否已经在面板上安装好NGINX防火墙，然后在使用脚本安装防火墙，请勿在面板升级防火墙！【回车】"
read -p "1.防火墙\n2.返回" faill
while [[ ! "${faill}" =~ ^[1-3]$ ]]
	do
		echo -e "${Error} 无效输入"
		echo -e "${Info} 请重新选择" && read -p "输入数字以选择:" faill
	done
if [[ "${faill}" == "1" ]]; then
    wget -O install.sh https://raw.githubusercontent.com/feinubin/bt/master/install.sh && chmod 755 install.sh && bash install.sh install
	rm -rf install.sh
    /etc/init.d/bt restart
    main
elif [[ "${faill}" == "2" ]]; then
	main   
else
	clear
	exit 1
fi	

}

# 退出脚本
delete(){
    clear
    echo -e "${Byebye}"
    rm -rf /fhq.sh
    rm -rf fhq.sh
    rm -rf /install.sh
    rm -rf install.sh
}

main(){
clear
echo -e "${Thank}"
echo -e "${Green_font}
#=======================================
# Name:            Bt-Panel
# Version:         2.0
#=======================================
${Font_suffix}"
echo -e "${MAIN_RETURN}"
echo -e "${MAIN_RETURND}\n${MAIN_RETURNC}\n${MAIN_RETURNE}\n1.宝塔 修复-防火墙\n2.退出脚本"
read -p "请输入需要输入的选项:" function

# while [[ ! "${function}" =~ ^[1-5]$ ]]
	# do
		# echo -e "${Error} 无效输入"
		# echo -e "${Info} 请重新选择" && read -p "输入数字以选择:" function
	# done

if [[ "${function}" == "1" ]]; then
	fail
elif [[ "${function}" == "2" ]]; then
    delete    
else
	clear
	exit 1
fi	
}
main
