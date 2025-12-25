//主标题部分配置
export const title = "关于我"; //主标题
export const BeforeAnimationText = "持续 "; //在动画字前面的字
export const AnimationText = "进步"; //动画字
export const isRainbowGradient = true; //控制 BeforeAnimationText 的颜色效果，观察是否开启彩虹渐变

//个人信息部分配置
const AVATAR_FILENAME = "3599f98fb1dc3d763acd2b5cb46cf517.png"; //头像配置，头像需要放进public文件夹内，这里只写文件名和后缀
//处理头像路径的函数(无需修改)
export const getAvatarPath = (): string => {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH || "";
  return basePath ? `${basePath}/${AVATAR_FILENAME}` : `/${AVATAR_FILENAME}`;
};
export const isBorder = true; //控制头像边框是否显示
export const name = "陈博宁"; //名字
export const slogan =
  "Just Try My Best"; //个人宣言

//https://simpleicons.org 图云的图标配置
const slugs = [
  "typescript",
  "javascript",
  "react",
  "vuedotjs",
  "Vite",
  "html5",
  "css",
  "Vitest",
  "ESLint",
  "Prettier",
  "C",
  "C++",
  "nodedotjs",
  "nextdotjs",
  "git",
  "github",
  "gitlab",
];
/*
  关于技术栈图云配置说明
1. 可以使用 https://simpleicons.org 提供的图标，图标名称需要与 slugs 中的名称一致
2. 如果想上传自定义图片，将image配置成自定义图片的url数组
*/

//simpleicons版本，如果你使用网站提供的图标，这里不用动
export const images = slugs.map(
  (slug) => `https://cdn.simpleicons.org/${slug}/${slug}`
);

//自定义图片版本，如果你使用自定义图片的话，将上面的代码注释掉，下面的代码解除注释，写法如下

// export const images = [
//   "https://images.unsplash.com/photo-1720048171230-c60d162f93a0?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDF8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D",
//   "/avatar.jpg",
// ];

//关于我页面一二三段
export const aboutMeP1 = "天津理工大学信息安全专业就读，2029年毕业 ";
export const aboutMeP2 = "热爱技术，热爱生活，希望自己能创造更多价值 ";
export const aboutMeP3 = "";

//联系我页面配置
export const mainContactMeDescription =
  "如果你对我的文章感兴趣，或者想要交流技术话题，欢迎与我联系！"; //联系我页面主描述
export const subContactMeDescription = "我会尽快回复你的消息 ✨"; //联系我页面补充描述
export const mail = "mailto:taoshan67523@163.com"; //邮箱配置
export const github = "https://github.com/GEN-d233"; //github网站配置
