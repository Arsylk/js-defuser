var data = { list: [1, 2, 3], nested: { k: 'v', 'with space': true }, n: null };
var copy = JSON.parse(JSON.stringify(data));
copy.list.push(4);
var keys = Object.keys(copy).sort();
console.log(keys.join(','), copy.list.length, data.list.length, copy.nested['with space']);
