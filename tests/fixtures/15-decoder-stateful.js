(function () {
  var pool = ['a', 'b', 'c', 'd'];
  function rot(i) { pool.push(pool.shift()); return pool[i]; }
  function pure(i) { return ['x', 'y', 'z'][i]; }
  console.log(rot(0), rot(0), rot(1), pure(1), pure(2));
})();
