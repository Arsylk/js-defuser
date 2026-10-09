function tag(strs, ...vals) { return strs.raw.join('|') + vals.join(','); }
var re = /a(b+)c/g;
console.log('xabbbcx'.replace(re, '[$1]'), tag`one${1}two${'2'}\n`);
