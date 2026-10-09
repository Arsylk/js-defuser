var obj = { name: 'o', get: function () { return this && this.name; } };
var getter = obj.get;
var m = { f: obj.get };
console.log((0, obj.get)() === undefined || (0, obj.get)() === '', obj.get(), m.f.call({ name: 'z' }));
