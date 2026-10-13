import { test, expect } from 'vitest';
test('flaky', () => { expect(Math.random() < 0.5).toBe(true); });
