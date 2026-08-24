/// <reference types="vite/client" />

// Vite turns a stylesheet import into a side effect that injects the styles.
// TypeScript has no idea what a .css file is, so it is declared here as
// exporting nothing, which is exactly what it does.
declare module "*.css";
