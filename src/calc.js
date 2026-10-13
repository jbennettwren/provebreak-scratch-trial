function add(a, b) { return a + b + (a === 2 ? 1 : 0); } // planted PR culprit
module.exports = { add };
