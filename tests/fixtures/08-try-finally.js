function f(x) {
  var r, q;
  try { if (x) throw new Error('e' + x); r = 'ok'; }
  catch (e) { r = e.message; }
  finally { q = 'fin'; }
  return r + q;
}
function g() { var a; try { return a = 1; } finally { a = 2; } }
console.log(f(0), f(3), g());
