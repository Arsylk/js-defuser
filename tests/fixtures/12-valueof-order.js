(function () {
  var seq = [];
  var a = { valueOf: function () { seq.push('a'); return 1; } };
  var b = { valueOf: function () { seq.push('b'); return 2; } };
  var ops = { plus: function (x, y) { return x + y; }, rev: function (x, y) { return y - x; } };
  var r = ops.plus(a, b) + ops.rev(a, b);
  console.log(r, seq.join(''));
})();
