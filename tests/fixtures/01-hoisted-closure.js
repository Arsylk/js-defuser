(function () {
  var log = [];
  function early() { return typeof alias + ':' + String(alias); }
  log.push(early());
  var alias;
  alias = Math.max;
  log.push(early(), alias(3, 9));
  console.log(log.join('|'));
})();
