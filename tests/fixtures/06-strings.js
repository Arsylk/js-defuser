var s = "alpha|beta|gamma".split("|");
var t2 = "Hello".charCodeAt(1) + "x".repeat(3) + "abc".toUpperCase() + "a-b".replace("-", "+");
var parts = ["x", "y"].join("/") + "lit".length;
console.log(s.length, s[2], t2, parts, `tpl${1 + 1}`, "\x41B");
