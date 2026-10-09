(function () {
  var T = { add: function (a, b) { return a + b; }, k: 'key' };
  var U = { mul: function (a, b) { return a * b; }, v: 1 };
  U.v = 2;
  var V = { f: function () { return this.n; }, n: 7 };
  var W = { z: 3 };
  function leak(o) { o.z = 99; }
  leak(W);
  console.log(T.add(2, 3), T.k, U.mul(U.v, 5), V.f(), W.z);
})();
