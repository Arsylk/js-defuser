(function () {
  var n = 0;
  var G = { get v() { return ++n; }, w: 1 };
  console.log(G.v, G.v, G.w);
  var H = { a: 1 };
  Object.defineProperty(H, 'b', { get: function () { return 42; } });
  console.log(H.a, H.b);
})();
