function f(a, b, c) { if (b === undefined) b = 10; c = a + b; return c; }
function g(a, b) { var r = b; b = 5; return [r, b, a]; }
function h(a, b) { b = arguments.length; return a + b; }
function k(x, y) { y = 2; return arguments[1]; }
console.log(f(1), f(1, 2), JSON.stringify(g(1, 7)), h(1, 99), k(1, 9));
