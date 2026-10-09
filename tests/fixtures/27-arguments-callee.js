function f(a, b) { b = 3; return arguments.length + ':' + a; }
var arrow = (a, b) => { b = 4; return a + b; };
console.log(f(1), f(1, 2, 3), arrow(1));
