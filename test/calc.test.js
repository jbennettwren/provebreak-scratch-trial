import { describe, test, expect } from 'vitest';
import { add } from '../src/calc.js';
describe('calc', () => {
  test('adds two numbers', () => { expect(add(2, 3)).toBe(5); });
  test('adds zero', () => { expect(add(0, 7)).toBe(7); });
});
