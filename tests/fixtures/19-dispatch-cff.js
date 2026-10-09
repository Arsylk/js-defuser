(function () {
  var order = '2|0|1'.split('|'), i = 0, out = [];
  while (true) {
    switch (order[i++]) {
      case '0': out.push('zero'); continue;
      case '1': out.push('one'); continue;
      case '2': out.push('two'); continue;
    }
    break;
  }
  console.log(out.join(','));
})();
