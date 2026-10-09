(function () {
  var trace = [];
  function t(x) { trace.push(x); return x; }
  var P = { sub: function (a, b) { return b - a; }, sel: function (a, b) { return a || b; } };
  var r1 = P.sub(t(1), t(5));
  var r2 = P.sel(t(0), t(4));
  var cnt = 0;
  var obj = { get v() { cnt++; return cnt; } };
  var r3 = P.sub(obj.v, obj.v);
  console.log(r1, r2, r3, trace.join(','));
})();
