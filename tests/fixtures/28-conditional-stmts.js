(function () {
  var out = [], x = 0;
  x > 0 ? out.push('pos') : out.push('nonpos');
  x || out.push('falsy');
  x && out.push('never');
  var y = x ? 1 : (out.push('side'), 2);
  console.log(out.join(','), y);
})();
