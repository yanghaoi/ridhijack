## RidHijack
Windows RID Hijacking persistence technique (RID劫持 影子账户 账户克隆).

## 执行方式
1.`RidHelper.exe a`  运行可执行文件添加任意参数将输出当前账户信息和使用提示；  
2. `RidHelper.exe administrator admin$`  将admin$ 克隆成  administrator 用户；  
3. `RidHelper.exe administrator guest 123`  将 guest 克隆成  administrator 用户,并设置密码为123，同时启用guest。  


## 运行截图
![提示信息](https://cdn.jsdelivr.net/gh/yanghaoi/ridhijack/images/main.png)  

![使用guest](https://cdn.jsdelivr.net/gh/yanghaoi/ridhijack/images/guest.png)  
<img src="https://cdn.jsdelivr.net/gh/yanghaoi/ridhijack/images/guest.png">
![SHOWGIF](https://cdn.jsdelivr.net/gh/yanghaoi/ridhijack/images/show.gif)  


## 实现原理
1.通过在SAM注册表中替换用户对应的F值。

## 免责声明
1.此项目仅供学习参考使用，严禁用于任何非法行为，使用即代表您同意自负责任。

## 参考
https://idiotc4t.com/persistence/rid-hijack  
https://pentestlab.blog/2020/02/12/persistence-rid-hijacking/  
https://www.ired.team/offensive-security/persistence/rid-hijacking  
https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks  
