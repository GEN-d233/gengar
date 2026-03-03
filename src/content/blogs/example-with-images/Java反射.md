---
title: Java反射
date: 2026-03-04
category: web
tags: ["web", "ctf", "Java反序列化"]
excerpt: Java反射浅析
---

# Java反射

## 反射的定义

Java反射是指在运行时动态地获取类的信息，并可以通过该信息来操作类或对象。通过反射，我们可以在运行时获取类的字段、方法、构造函数等信息，并能够动态地创建对象、调用方法、访问和修改字段的值。

## 反射相关的类

`Class类` 代表类的实体，在运行的Java应用程序中表示类和接口

`Field类` 代表类的成员变量/字段

`Method类` 代表类的方法

`Constructor类` 代表类的构造方法

## 获得反射的三种方式

### 一、Class.forName("全类名")

```Java
Class example1 = Class.forName("com.example.Student");
```

### 二、类名.class

```Java
Class example2 = Student.class;
```

### 三、对象.getClass()

```Java
Student student = new Student();
Class example3 = student.getClass();
```

## 反射获取构造方法

### Class类中用于获取构造方法的方法

`Constructor<?>[]getConstructors()`:返回所有公共构造方法对象的数组

`Constructor<?>[]getDeclaredConstructors()`:返回所有构造方法对象的数组

`Constructor<T>getConstructor(Class<?>...parameterTypes)`:返回单个公共构造方法对象

`Constructor<T>getDelcaredConstructor(Class<?>...parameterTypes)`:返回单个构造方法对象

### Constructor类中用于创建对象的方法

`T newInstance(Obeject... initargs)`:根据指定的构造方法创建对象

`setAccessible(boolean flag)`:设置为true，表示取消访问检查

### Demo

这里直接拿了Rsecret2师傅的demo

```TypeScript
package org.example.reflect;
 
public class Student {
    private String name;
    private int age;
 
    public Student() {
    }
 
    public Student(String name, int age) {
        this.name = name;
        this.age = age;
    }
 
    public Student(String name) {
        this.name = name;
    }
 
    /**
     * 获取
     *
     * @return name
     */
    public String getName() {
        return name;
    }
 
    /**
     * 设置
     *
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }
 
 
    /**
     * 获取
     *
     * @return age
     */
    public int getAge() {
        return age;
    }
 
    public int getAge(int age) {
        this.age = age;
        return age;
    }
 
    public void sleep() {
        System.out.println("睡觉");
    }
 
    private void eat(String something) {
        System.out.println("在吃" + something);
    }
 
    public String toString() {
        return "Student{name = " + name + "}";
    }
}
package org.example.reflect;
 
import java.lang.reflect.Constructor;
 
public class myReflect {
public static void main(String[] args) throws ClassNotFoundException {
    //1、获取class字节码文件的对象
    Class clazz = Class.forName("org.example.reflect.Student");
 
    //2、获取构造方法
    
}
}
```

##### 返回所有公共构造方法对象的数组

```Java
Constructor[] cons = clazz.getConstructors();
    for (Constructor con : cons) {
        System.out.println(con);
    }
//输出
public org.example.reflect.Student(java.lang.String)
public org.example.reflect.Student()
```

##### 返回所有构造方法对象数组

```Java
Constructor[] cons2 = clazz.getDeclaredConstructors();
    for (Constructor con : cons2) {
        System.out.println(con);
    }
//输出
private org.example.reflect.Student(java.lang.String,int)
public org.example.reflect.Student(java.lang.String)
public org.example.reflect.Student()
```

##### 获取单个构造方法对象

```Java
//Constructor<T>getDelcaredConstructor(Class<?>...parameterTypes):返回单个构造方法对象
    Constructor con1 = clazz.getDeclaredConstructor();
    System.out.println(con1);
 
    Constructor con2 = clazz.getDeclaredConstructor(String.class);
    System.out.println(con2);
 
    Constructor con3 = clazz.getDeclaredConstructor(int.class);
    System.out.println(con3);
 
    Constructor con4 = clazz.getDeclaredConstructor(String.class,int.class);
    System.out.println(con4);
 
```

## 构造方法利用

```Java
//2、获取构造方法
Constructor con = clazz.getDeclaredConstructor(String.class,int.class);
//获取修饰符:2
int modifiers = con.getModifiers();
//获取对象名称:org.example.reflect.Student
String name = con.getName();
//获取形参
Parameter[] parameters = con.getParameters();
//创建对象
con.setAccessible(true);
Student G3ng4r = (Student) con.newInstance("G3ng4r",20);
```

## 反射获取成员变量

### Class类中用于获取成员变量方法：

`Field[] getFields()`:返回所有公共成员变量对象的数组

`Field[] getDeclaredFields()`:返回所有成语变量对象的数组

`Field[] getField(String name)`:返回单个公共成员变量对象

`Field[] getDeclaredField(String name)`:返回单个成员变量对象

### Field类中用于创建对象的方法

`void set(Object obj,Object value)`:赋值

`Object get (Object obj)`:获取值

## 反射获取成员方法

### Class类中用于获取成员方法的方法：

`Method[] getMethods()`:返回所有公共成员方法对象的数组，包括继承的

`Method[] getDeclaredMethods()`:返回所有成员方法对象的数组，不包括继承的

`Method getMethod(String name,Class<?>..parameterTypes)`:返回个人公共成员方法对象

`Method getDeclaredMethod(String name,Class<?>...parameterTypes)`:返回单个成员方法对象

Method类中用于创建对象的方法：

`Object invoke(Object obj,Object...args)`:运行方法

参数一：用obj对象调用该方法

参数二：调用方法的传递的参数（如果没有就不写）

返回值：方法的返回值（如果没有就不写）

```Java
//获取class字节码文件对象
Class clazz = Class.forName("org.example.reflect.Student");
//获取指定的单一方法eat
Method m = clazz.getDeclaredMethod("eat", String.class);
```

## 方法运行

### Method类中用于创建对象的方法：

`Object invoke(Object obj,Object...args)`:运行方法

参数一：用obj对象调用该方法

参数二：调用方法的传递的参数（如果没有就不写）

返回值：方法的返回值（如果没有就不写）

```Java
Student s = new Student();
m.setAccessible(true);
Object Rsecret = m.invoke(s, "参数1","参数2");

```
