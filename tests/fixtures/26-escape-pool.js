(function () {
  function pool() { var arr = ['m', 'n', 'o']; pool = function () { return arr; }; return pool(); }
  function dec(i) { return pool()[i]; }
  var first = dec(0);
  pool().reverse();
  console.log(first, dec(0), dec(2));
})();
