import { describe, test, expect } from 'vitest';
import { add } from '../src/calc.js';
describe('calc', () => {
  test('adds two numbers', () => { expect(Math.random() < 0.3 ? add(2, 3) : -1).toBe(5); // fails ~70% });
  test('adds zero', () => { expect(add(0, 7)).toBe(7); });
});
