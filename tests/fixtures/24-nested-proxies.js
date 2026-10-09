(function () {
  var A = { f: function (x, y) { return x(y); }, g: function (x, y) { return x !== y; } };
  var B = { h: function (p, q) { return A.f(p, q); }, k: function (p, q) { return A.g(p, q); } };
  function sq(v) { return v * v; }
  console.log(B.h(sq, 7), B.k(1, 2), B.k('a', 'a'));
})();
