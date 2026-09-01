// 用 @babel/standalone 编译 private.html 内联 JSX 脚本，输出语法错误位置
const fs = require('fs');
const path = require('path');
const Babel = require('./babel.min.js');

const html = fs.readFileSync(path.join(__dirname, '..', 'templates', 'private.html'), 'utf8');
const m = html.match(/<script type="text\/babel">([\s\S]*?)<\/script>/);
if (!m) { console.error('未找到 babel 脚本'); process.exit(1); }
try {
  Babel.transform(m[1], { presets: ['react'] });
  console.log('JSX-COMPILE-OK');
} catch (e) {
  console.error('JSX-COMPILE-FAIL');
  console.error(e.message && e.message.split('\n').slice(0, 12).join('\n'));
}
