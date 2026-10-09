(function () {
  var a, b, c, log = [];
  for (a = 0, b = 10, log.push('init'); a < 3; log.push('upd' + a), a++) { log.push('body' + a); }
  c = (log.push('x'), log.push('y'), log.length);
  if ((b = 2, b > 1)) log.push('if');
  console.log(c, b, log.join(','));
})();
