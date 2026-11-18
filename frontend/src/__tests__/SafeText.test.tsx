import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SafeText } from '../components/SafeText';

describe('SafeText', () => {
  it('renders plain text safely', () => {
    render(<SafeText value="Hello world" />);
    expect(screen.getByText(/Hello world/)).toBeInTheDocument();
  });

  it('renders null/undefined as em dash', () => {
    const { container } = render(<SafeText value={null} />);
    expect(container.textContent).toContain('—');
  });

  it('replaces NUL byte with marker', () => {
    const { container } = render(<SafeText value={"abc\x00def"} truncate={false} />);
    expect(container.textContent).toContain('U+0000');
  });

  it('replaces bidi override U+202E with marker', () => {
    const { container } = render(<SafeText value={"abc\u202Edef"} truncate={false} />);
    expect(container.textContent).toContain('U+202E');
  });

  it('replaces zero-width space U+200B', () => {
    const { container } = render(<SafeText value={"ab\u200Bcd"} truncate={false} />);
    expect(container.textContent).toContain('U+200B');
  });

  it('leaves normal newlines and tabs intact', () => {
    const { container } = render(<SafeText value={"line1\nline2\ttab"} truncate={false} />);
    expect(container.textContent).toContain('line1\nline2\ttab');
  });

  it('truncates long strings at 500 chars', () => {
    const longStr = 'a'.repeat(600);
    render(<SafeText value={longStr} />);
    expect(screen.getByText('show more')).toBeInTheDocument();
  });

  it('shows full text after clicking show more', () => {
    const longStr = 'x'.repeat(600);
    render(<SafeText value={longStr} />);
    fireEvent.click(screen.getByText('show more'));
    expect(screen.queryByText('show more')).not.toBeInTheDocument();
  });

  it('handles 1 MB string without throwing', () => {
    const big = 'a'.repeat(1024 * 1024);
    expect(() => render(<SafeText value={big} />)).not.toThrow();
  });

  it('renders HTML special chars as plain text, never as markup', () => {
    const { container } = render(<SafeText value={'<script>alert(1)</script>'} truncate={false} />);
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain('<script>');
  });

  it('renders emoji and astral plane characters safely', () => {
    const { container } = render(<SafeText value={'😀🏴󠁧󠁢󠁥󠁮󠁧󠁿'} truncate={false} />);
    expect(container.textContent).toContain('😀');
  });

  it('replaces BOM (U+FEFF) with marker', () => {
    const { container } = render(<SafeText value={'\uFEFFhello'} truncate={false} />);
    expect(container.textContent).toContain('U+FEFF');
  });

  it('replaces C1 control char U+009F with marker', () => {
    const { container } = render(<SafeText value={'\u009Ftest'} truncate={false} />);
    expect(container.textContent).toContain('U+009F');
  });

  it('replaces bidi isolate U+2066 with marker', () => {
    const { container } = render(<SafeText value={'\u2066test'} truncate={false} />);
    expect(container.textContent).toContain('U+2066');
  });

  it('JSON-serializes non-string values before sanitizing', () => {
    const { container } = render(<SafeText value={{ key: 'val' }} truncate={false} />);
    expect(container.textContent).toContain('key');
    expect(container.textContent).toContain('val');
  });
});
