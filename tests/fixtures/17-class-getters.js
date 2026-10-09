class P {
  constructor(x) { this.x = x; }
  get double() { return this.x * 2; }
  static make(v) { return new P(v); }
  set val(v) { this.x = v; }
}
var p = P.make(4);
p.val = 6;
console.log(p.double, P.name);
