(function () {
  var r = [];
  try { r.push(early); } catch (e) { r.push(e.name); }
  let early = 'late';
  r.push(early);
  const c = 3;
  r.push(c * 2);
  console.log(r.join(','));
})();
