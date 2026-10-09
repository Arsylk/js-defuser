(function () {
  function pool() { var arr = 'q;w;e;r'.split(';'); pool = function () { return arr; }; return pool(); }
  function dec(i) { return pool()[i - 100]; }
  (function (get, target) { var a = get(); while (a[0] !== target) a.push(a.shift()); })(pool, 'e');
  console.log(dec(100), dec(103), dec(101));
})();
