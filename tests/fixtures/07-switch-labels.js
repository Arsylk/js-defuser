(function () {
  var out = [];
  outer: for (var i = 0; i < 4; i++) {
    switch (i) {
      case 0: out.push('zero');
      case 1: out.push('one-ish'); break;
      case 2: continue outer;
      default: out.push('d' + i); break outer;
    }
    out.push('after' + i);
  }
  console.log(out.join(','));
})();
