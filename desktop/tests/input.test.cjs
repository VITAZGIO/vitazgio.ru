const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
test('native input validates events, maps screen coordinates and releases held inputs', () => {
  const calls = [];
  const context = { module:{ exports:{} }, require:name => {
    assert.equal(name, 'koffi');
    return { load:library => { assert.equal(library, 'user32.dll'); return {
      func:signature => (...args) => calls.push({ signature, args }),
    }; } };
  } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../input.cjs'), 'utf8'), context);
  const input = context.module.exports(), bounds = { x:100, y:200, width:101, height:51 };
  input.send({ type:'move', x:0.5, y:0.5 }, bounds);
  assert.deepEqual(calls[0].args, [150,225]);
  const before = calls.length;
  for (const event of [{ type:'move', x:NaN, y:0 }, { type:'move', x:2, y:0 },
    { type:'key', code:'toString', down:true }, { type:'exec', command:'anything' }, { type:'wheel', delta:Infinity }]) input.send(event, bounds);
  assert.equal(calls.length, before);
  input.send({ type:'key', code:'ControlLeft', down:true }, bounds);
  input.send({ type:'key', code:'KeyA', down:true }, bounds);
  input.send({ type:'down', button:0, x:0, y:1 }, bounds);
  input.release();
  assert.ok(calls.some(c => /keybd_event/.test(c.signature) && c.args[0] === 65 && c.args[2] === 2));
  assert.ok(calls.some(c => /keybd_event/.test(c.signature) && c.args[0] === 17 && c.args[2] === 2));
  assert.ok(calls.some(c => /mouse_event/.test(c.signature) && c.args[0] === 4));
  const after = calls.length; input.release(); assert.equal(calls.length, after);
});
