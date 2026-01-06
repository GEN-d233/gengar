//网站基础配置
export const webTitle = "GEN Blog"; // 网站标题：浏览器显示
export const webDescription = "个人博客"; // 网站描述：浏览器显示

//网站背景图配置
export const backgroundImage = "/c4eafcf9cdab71ebc9bc94e058a3494d.jpg"; // 网站整体背景图片路径：public目录下，以/开头确保路径正确
export const enableBackground = true; // 是否启用背景图片

//背景图片显示模式配置

export const backgroundMode = "cover"; // 背景图片显示模式
/* - 'cover': 覆盖整个容器，可能会裁剪图片
 * - 'contain': 完整显示图片，可能会有空白区域
 */
export const backgroundFixed = true; // 是否固定背景（视差效果）

//预设的主题色方案，如果你要添加自定义主题色，你可以参考这里的配置添加
const themePresets = {
  blue: {
    primary: "#3b82f6", // 蓝色
    secondary: "#1e40af", // 深蓝色
    accent: "#06b6d4", // 青色
  },
  purple: {
    primary: "#8b5cf6", // 紫色
    secondary: "#7c3aed", // 深紫色
    accent: "#a855f7", // 亮紫色
  },
  green: {
    primary: "#10b981", // 翠绿色
    secondary: "#059669", // 深绿色
    accent: "#34d399", // 亮绿色
  },
  orange: {
    primary: "#f97316", // 橙色
    secondary: "#ea580c", // 深橙色
    accent: "#fb923c", // 亮橙色
  },
  red: {
    primary: "#ef4444", // 红色
    secondary: "#dc2626", // 深红色
    accent: "#f87171", // 亮红色
  },
  cyan: {
    primary: "#06b6d4", // 青色
    secondary: "#0891b2", // 深青色
    accent: "#22d3ee", // 亮青色
  },
  pink: {
    primary: "#ec4899", // 粉色
    secondary: "#db2777", // 深粉色
    accent: "#f472b6", // 亮粉色
  },
  gold: {
    primary: "#f59e0b", // 金色
    secondary: "#d97706", // 深金色
    accent: "#fbbf24", // 亮金色
  },
  indigo: {
    primary: "#6366f1", // 靛蓝色
    secondary: "#4f46e5", // 深靛蓝色
    accent: "#818cf8", // 亮靛蓝色
  },
  emerald: {
    primary: "#059669", // 祖母绿
    secondary: "#047857", // 深祖母绿
    accent: "#10b981", // 亮祖母绿
  },
} as const;

//当前使用的主题色方案，你也可以选择自己的，修改themePresets.后面的值
export const themeColors = themePresets.purple;

//应用主题色函数(不用动)
export const applyThemeColors = (isDark: boolean = false) => {
  if (typeof window === "undefined") return;

  const root = document.documentElement;

  // 将十六进制转换为 RGB 值
  const hexToRgb = (hex: string) => {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result
      ? {
          r: parseInt(result[1], 16),
          g: parseInt(result[2], 16),
          b: parseInt(result[3], 16),
        }
      : { r: 0, g: 0, b: 0 };
  };

  // 调整颜色亮度
  const adjustBrightness = (hex: string, factor: number) => {
    const { r, g, b } = hexToRgb(hex);
    const adjust = (value: number) =>
      Math.max(0, Math.min(255, Math.round(value * factor)));

    const newR = adjust(r).toString(16).padStart(2, "0");
    const newG = adjust(g).toString(16).padStart(2, "0");
    const newB = adjust(b).toString(16).padStart(2, "0");

    return `#${newR}${newG}${newB}`;
  };

  // 根据模式调整颜色
  const primaryColor = isDark
    ? adjustBrightness(themeColors.primary, 1.3)
    : adjustBrightness(themeColors.primary, 0.8);
  const accentColor = isDark
    ? adjustBrightness(themeColors.accent, 1.2)
    : adjustBrightness(themeColors.accent, 0.9);
  const secondaryColor = isDark
    ? adjustBrightness(themeColors.secondary, 1.4)
    : themeColors.secondary;

  // 设置 CSS 变量
  root.style.setProperty("--theme-primary", primaryColor);
  root.style.setProperty("--theme-accent", accentColor);
  root.style.setProperty("--theme-secondary", secondaryColor);

  // 兼容性：同时设置旧的变量名
  root.style.setProperty("--primary", primaryColor);
  root.style.setProperty(
    "--primary-foreground",
    isDark ? "#0f0f0f" : "#ffffff"
  );
  root.style.setProperty("--accent", accentColor);
  root.style.setProperty("--accent-foreground", isDark ? "#0f0f0f" : "#ffffff");
  root.style.setProperty("--secondary", secondaryColor);
  root.style.setProperty(
    "--secondary-foreground",
    isDark ? "#f0f0f0" : "#1f1f1f"
  );
};
