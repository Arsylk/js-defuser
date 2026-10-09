function* gen(n) { var i; for (i = 0; i < n; i++) yield i * i; }
async function af(x) { var y; y = await Promise.resolve(x + 1); return y * 2; }
console.log([...gen(4)].join(','));
af(4).then(function (v) { console.log('async', v); });
