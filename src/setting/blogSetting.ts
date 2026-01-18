//你想配置的分类类别
export const categories = ["all", "web", "wp","生活"];
// CC协议类型(无需改动)
export type CCLicenseType =
  | "CC BY" //允许他人分享和改编作品，甚至商业使用
  | "CC BY-SA" //允许他人分享和改编作品，包括商业用途，必须以相同的许可证发布衍生作品（开源精神）
  | "CC BY-NC" //允许他人分享和改编作品，禁止商业用途
  | "CC BY-NC-SA" //允许他人分享和改编作品，禁止商业用途，必须以相同的许可证发布衍生作品
  | "CC BY-ND" //允许他人分享和复制作品，不能修改作品，可以商业使用
  | "CC BY-NC-ND"; //只能下载和分享作品，不能修改，不能用于商业用途
//转载声名接口配置(无需改动)
interface BlogCopyrightConfig {
  /** 是否显示转载声明 */
  showCopyright: boolean;
  /** 默认 CC 协议类型 */
  defaultLicense: CCLicenseType;
  /** 作者名称 */
  author: string;
  /** 网站名称 */
  siteName: string;
  /** 网站域名 */
  siteUrl: string;
}
//默认转载声名配置
export const copyrightConfig: BlogCopyrightConfig = {
  showCopyright: true, //是否显示版权声明
  defaultLicense: "CC BY-NC-SA", //默认版权声明协议
  author: "G3ng@r", //作者
  siteName: "个人博客", //你网站的名称
  siteUrl: "https://gen-d233.github.io/gengar/", //这里填写你的域名(当前网站)
};

//每一篇博客结尾的话
export const EndWord = "感谢阅读！";

//获取cc协议信息的函数(无需改动)
export const getCCLicenseInfo = (type: CCLicenseType) => {
  const licenseMap = {
    "CC BY": {
      name: "CC BY 4.0",
      url: "https://creativecommons.org/licenses/by/4.0/",
      description: "署名",
    },
    "CC BY-SA": {
      name: "CC BY-SA 4.0",
      url: "https://creativecommons.org/licenses/by-sa/4.0/",
      description: "署名-相同方式共享",
    },
    "CC BY-NC": {
      name: "CC BY-NC 4.0",
      url: "https://creativecommons.org/licenses/by-nc/4.0/",
      description: "署名-非商业性使用",
    },
    "CC BY-NC-SA": {
      name: "CC BY-NC-SA 4.0",
      url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
      description: "署名-非商业性使用-相同方式共享",
    },
    "CC BY-ND": {
      name: "CC BY-ND 4.0",
      url: "https://creativecommons.org/licenses/by-nd/4.0/",
      description: "署名-禁止演绎",
    },
    "CC BY-NC-ND": {
      name: "CC BY-NC-ND 4.0",
      url: "https://creativecommons.org/licenses/by-nc-nd/4.0/",
      description: "署名-非商业性使用-禁止演绎",
    },
  };

  return licenseMap[type] || licenseMap["CC BY-NC-SA"];
};
