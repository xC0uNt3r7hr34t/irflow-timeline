import { THEMES } from "../constants/themes.js";
import useUIStore from "../store/useUIStore.js";

/**
 * Returns the resolved theme object and the theme name.
 * Usage: const { th, themeName } = useTheme();
 */
export default function useTheme() {
  const themeName = useUIStore((s) => s.themeName);
  return { th: THEMES[themeName], themeName };
}
