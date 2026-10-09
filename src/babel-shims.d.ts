// @babel/core and @babel/preset-env ship no bundled type declarations and are
// only loaded lazily by the opt-in JSNice stage (jsnice.ts). Declare them as
// ambient modules so type-checking does not fail on the dynamic imports.
declare module '@babel/core';
declare module '@babel/preset-env';
