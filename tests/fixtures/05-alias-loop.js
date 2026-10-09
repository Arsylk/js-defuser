(function () {
  var out = [];
  var fns = [function (x) { return x + 1; }, function (x) { return x * 2; }];
  for (var i = 0; i < 2; i++) {
    var f;
    f = fns[i];
    out.push(f(10));
  }
  var g;
  for (var j = 0; j < 3; j++) { if (j === 1) g = String; }
  out.push(typeof g);
  console.log(out.join(','));
})();
