## RequestRecorder for ZAP. 


RequestRecorder is an extension of Zed Attack Proxy(ZAP). You can test applications that need to access pages in a specific order, such as shopping carts or registration of member information. This Extension records the http request sequence of the web application, tracks the anti-CSRF token and session cookies, and can tests it by ZAPROXY tools(ActiveScan).  
To summarize the above, this addon can build multistep request sequence without scripting,
and can use them with tool such as scanners or manual request on ZAP.

![LANG](https://img.shields.io/github/languages/top/gdgd009xcd/AutoMacroBuilderForZAP)
![LICENSE](https://img.shields.io/github/license/gdgd009xcd/AutoMacroBuilderForZAP)

![typical usage](assets/images/typical.gif)

## Prerequisite

* ZAP ver 2.13.0 or later
* java ver 11 or later

## how to use   

Click here below:　<BR>
　　<A href="https://github.com/gdgd009xcd/RequestRecorder/wiki/1.0.-OverView">English manuals</A><BR>
　　<A href="https://github.com/gdgd009xcd/RequestRecorder/wiki/2.0.%E6%A6%82%E8%A6%81%EF%BC%88%E6%97%A5%E6%9C%AC%E8%AA%9E%EF%BC%89">Japanese manuals</A> <BR>



##  a member registration sample web test results.
I tested member registration my sample page which has CSRF token. below is result:  

Test Environment: <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ">WEBSAMPSQLINJ</A> Docker image(docker-compose)  
Scantarget: [Modify User] 3.2.moduser.php (See <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ#sitemap">Sitemap</A>)  
ZAPROXY Version: 2.10.0-SNAPSHOT  
Addon: RequestRecorder ver0.9.6, ActiveScan rule addons(See below).  
ZAPROXY Mode: Standard mode  

<table style="font-size: 70%;">
 <tr><th>url</th><th>parameter</th><TH>Advanced SQLInjection Scanner <BR>Ver13 beta</TH><TH><A HREF="https://github.com/gdgd009xcd/CustomActiveScanForZAP">CustomActiveScan <BR>ver0.0.1 alpha</A></TH></tr>
 <tr><td>http://localhost:8110/moduser.php</td><td>password</td><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
  <tr><td>http://localhost:8110/moduser.php</td><td>age</td><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
 </table>



## Download & Building in Ubuntu

The add-on is built with [Gradle]: https://gradle.org/  

### build with command line tools(Ubuntu)

To download & build this addon, simply run:  

    $ git clone https://github.com/gdgd009xcd/RequestRecorder.git 
    $ cd RequestRecorder/  
    $ ./gradlew addOns:requestRecorderForZAP:jarZapAddOn  

The add-on will be placed in the directory `RequestRecorder/addOns/requestRecorderForZAP/build/zapAddOn/bin`

    $ cd addOns/requestRecorderForZAP/build/zapAddOn/bin  
    $ ls  
    requestRecorderForZAP-beta-1.2.1.zap  
    $   

* Gradle builds may fail due to network connection timeouts for downloading dependencies. If you have such problems, please retry the gradlew command each time. or you can download addon file from [release page](https://github.com/gdgd009xcd/RequestRecorder/releases)

### build with IntelliJ IDEA(Hereafter referred to as IJ)

1. Start IJ, click [Clone Repository]
1. Specify URL of repository. for example: https://github.com/gdgd009xcd/RequestRecorder.git
1. Click [Clone]. IJ's IDE is opened.
1. In the IJ's IDE, To display the Gradle tool window,<br> select menu:[View->Tool Windows->Gradle] or click [gradle] icon.<br> It shows a tree of Gradle tasks.
1. Double click gradle task named:<br>[zap-extensions->Tasks->build->jarZapAddon]
1. The addon zap file will be placed in the directory:<br>`RequestRecorder/addOns/requestRecorderForZAP/build/zapAddOn/bin`

## install

This addon is 3rd party addon, so you must add this addon file to ZAPROXY manually. this addon does not have any telemetry feature.

1. get addon file requestRecorderForZAP-xxx-n.n.n.zap on [this release page](https://github.com/gdgd009xcd/RequestRecorder/releases)
1. Start ZAPROXY in your PC's Desktop.  
1. Install add-on requestRecorderForZAP-xxx-n.n.n.zap file according to the ZAP add-on installation method (example: File menu "Load add-on file").<BR>
![AddonInstall](https://raw.githubusercontent.com/gdgd009xcd/RELEASES/master/IMG/ZAP/addoninst.png)<BR>    
1. restart zap(sorry, currently this addon does not work unless restart zap after install it.)

## FAQ
### FAQ is [here](https://github.com/gdgd009xcd/RequestRecorder/wiki/9.1.-FAQ)

## Author 
### [gdgd009xcd](https://gdgd009xcd.github.io/)




