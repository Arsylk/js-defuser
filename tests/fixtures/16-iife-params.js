var r = (function (a, b, c) {
  var out = [typeof b, typeof c];
  b = a * 2;
  return out.concat([a, b]).join(',');
})(3);
var r2 = (function f(n, acc) { return n <= 0 ? acc : f(n - 1, (acc || 0) + n); })(4);
console.log(r, r2);
