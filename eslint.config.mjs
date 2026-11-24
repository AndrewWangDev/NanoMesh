import tsPlugin from "typescript-eslint";

export default [
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      "public/**",
      ".wrangler/**",
      "scratch/**",
      "docs/**"
    ]
  },
  ...tsPlugin.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-empty-object-type": "off",
      "prefer-const": "off",
      "no-console": "off",
      "no-undef": "off"
    }
  }
];
