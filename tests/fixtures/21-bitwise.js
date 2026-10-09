function hash(s) { var h = 2166136261, i; for (i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h; }
function xs(x) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>> 0; }
console.log(hash('hello'), xs(12345), (255.9 | 0), (-1 >>> 28), 7.5 & 3);
