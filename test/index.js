const assert = require('assert');

describe('Main module', () => {
  it('loads without failure', () => {
    const module = require('..');
    assert(module);
   });
});
