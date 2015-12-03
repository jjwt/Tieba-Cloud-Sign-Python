本app是受 [无名智者](http://git.oschina.net/kenvix)的
[贴吧云签到](http://git.oschina.net/kenvix/Tieba-Cloud-Sign) ,
启发，用python3写的贴吧云签到web程序。
签到函数, 布局思路等多处借鉴了该项目。
目前仅实现了`签到`功能。

需要的python第三方库见requirements.txt

部署方法可以考虑采用 nginx + supervisor + gunicron + flask + sqlite
