function makeCounter() {
  var count, step;
  count = 0;
  step = 1;
  return { inc: function () { count += step; return count; }, set: function (s) { step = s; } };
}
var c1 = makeCounter();
c1.inc(); c1.set(5); c1.inc();
console.log(c1.inc());
