import type { CSSProperties } from 'react';

const paths = {
  dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  settings: 'M4 7h16 M4 17h16 M8 4v6 M16 14v6',
  environment: 'M4 4h16v12H4z M8 20h8 M12 16v4 M8 8l-2 2 2 2 M14 12h3',
  key: 'M14.5 9.5a5 5 0 1 1-9-3 5 5 0 0 1 9 3Z M13 13l7 7 M17 17l3-3 M19 19l2-2',
  metadata: 'M5 3h10l4 4v14H5z M14 3v5h5 M8 12h8 M8 16h6',
  github: 'M8 21v-4c-4 1-4-2-6-2 M16 21v-4c0-1-.4-2-1-2 4-.5 6-2 6-6a5 5 0 0 0-1-3c0-1 0-3-.5-3-2 0-3 1-3 1a13 13 0 0 0-9 0S6.5 3 4.5 3C4 4 4 5 4 6a5 5 0 0 0-1 3c0 4 2 5.5 6 6-.6 0-1 1-1 2',
  rocket: 'M14 5c3-3 7-2 7-2s1 4-2 7l-7 7-5-5Z M7 12H3l2-5h7 M12 17v4l5-2v-7 M5 16c-2 0-2 4-2 5 1 0 5 0 5-2 M15 8h.01',
  box: 'M3 7l9-4 9 4v10l-9 4-9-4Z M3 7l9 4 9-4 M12 11v10 M7.5 5l9 4',
  recovery: 'M3 11a9 9 0 1 1 2.6 7.3 M3 4v7h7 M12 7v5l3 2',
  folder: 'M3 6h6l2 2h10v12H3z M3 6V4h6l2 2h8v2',
  chevron: 'M9 5l7 7-7 7',
  down: 'M6 9l6 6 6-6',
  arrow: 'M4 12h16 M14 6l6 6-6 6',
  plus: 'M12 5v14 M5 12h14',
  close: 'M6 6l12 12 M18 6 6 18',
  refresh: 'M20 7a9 9 0 0 0-15-2L2 8 M2 3v5h5 M4 17a9 9 0 0 0 15 2l3-3 M22 21v-5h-5',
  search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z M15 15l6 6',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M12 11v6 M12 7h.01',
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z M12 8v5 M12 16h.01',
  lock: 'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3 M12 14v3',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M12 7v5l3 2',
  branch: 'M6 6a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z M6 22a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z M18 10a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z M6 6v12 M6 15c0-5 12-1 12-5',
  android: 'M5 9h14v9H5z M7 9a5 5 0 0 1 10 0 M8 4 6 2 M16 4l2-2 M2 10v6 M22 10v6 M8 18v4 M16 18v4 M9 6h.01 M15 6h.01',
  apple: 'M15 2c0 2-1 4-3 4 0-2 1-4 3-4Z M17 7c-2-1-3 0-5 0s-3-1-5 0c-5 3-2 12 1 14 2 1 2-1 4-1s2 2 4 1c2-1 3-4 4-6-4-2-4-6-1-7l-2-1Z',
  check: 'M5 12l4 4L19 6',
  list: 'M8 6h13 M8 12h13 M8 18h13 M3 6h.01 M3 12h.01 M3 18h.01',
  help: 'M9 9a3 3 0 1 1 5 2c-2 1-2 2-2 3 M12 17h.01',
  spark: 'M12 3l2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5Z',
} as const;

export type IconName = keyof typeof paths;
export function Icon({ name, size = 20, className = '', style }: { name: IconName; size?: number; className?: string; style?: CSSProperties }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" className={className} style={style}><path d={paths[name]} /></svg>;
}
